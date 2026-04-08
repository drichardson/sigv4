# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Parametrized tests against the official AWS Signature Version 4 test suite.

Test vectors are vendored from botocore:
  https://github.com/boto/botocore/tree/develop/tests/unit/auth/aws4_testsuite

Each test case directory contains:
  <name>.req   — raw HTTP request (input)
  <name>.creq  — expected canonical request
  <name>.sts   — expected string to sign
  <name>.authz — expected Authorization header value

Test credentials (same across all cases):
  Access key:  AKIDEXAMPLE
  Secret key:  wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY
  Region:      us-east-1
  Service:     service
  Timestamp:   20150830T123600Z
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from sigv4.credentials import Credentials
from sigv4.signing import (
    _canonical_request,
    _string_to_sign,
    sign_headers,
)
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "data" / "aws4_testsuite"

_CREDS = Credentials(
    access_key="AKIDEXAMPLE",
    secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
)
_TIMESTAMP = datetime(2015, 8, 30, 12, 36, 0, tzinfo=UTC)
_REGION = "us-east-1"
_SERVICE = "service"


# The well-known session token used by get-vanilla-with-session-token.
# It does not appear in the .req file but is visible in the .sreq / .creq files.
# Other session-token test cases (post-sts-token/*) embed the token directly
# in their .req header lines, so we read it from there instead.
_SESSION_TOKEN_GET_VANILLA = (
    "6e86291e8372ff2a2260956d9b8aae1d763fbf315fa00fa31553b73ebf194267"
)


# ---------------------------------------------------------------------------
# Test case discovery
# ---------------------------------------------------------------------------


def _discover_test_cases() -> list[tuple[str, Path]]:
    """
    Walk FIXTURES_DIR and return (name, directory) pairs for every test case.

    Test cases are either:
      - Top-level directories (e.g. FIXTURES_DIR/get-vanilla/)
      - One level deep inside a grouping directory that has a readme
        (e.g. FIXTURES_DIR/normalize-path/get-relative/)
    """
    cases: list[tuple[str, Path]] = []

    for entry in sorted(FIXTURES_DIR.iterdir()):
        if not entry.is_dir():
            continue
        # Check if this is a grouping directory (contains sub-directories
        # that are the real test cases) vs a direct test case directory
        # (contains .req/.authz files directly).
        req_files = list(entry.glob("*.req"))
        if req_files:
            # Direct test case
            cases.append((entry.name, entry))
        else:
            # Grouping directory — descend one level
            for sub in sorted(entry.iterdir()):
                if sub.is_dir() and list(sub.glob("*.req")):
                    cases.append((f"{entry.name}/{sub.name}", sub))

    return cases


_ALL_CASES = _discover_test_cases()
_CASE_IDS = [name for name, _ in _ALL_CASES]
_CASE_DIRS = [d for _, d in _ALL_CASES]


# ---------------------------------------------------------------------------
# .req file parser
# ---------------------------------------------------------------------------


def _parse_req(req_path: Path) -> tuple[str, str, dict[str, str], bytes]:
    """
    Parse a raw HTTP request file.

    Returns:
        (method, url, headers, body)

    where url is the full URL (https://host/path?query) reconstructed from
    the request-line and Host header, and headers is a dict of lowercased
    header names to their values (with multiline values collapsed).
    """
    text = req_path.read_bytes().decode("utf-8")
    lines = text.splitlines()

    # Request line: METHOD /path?query HTTP/1.1
    # Split from the right to strip the HTTP version first, then split on the
    # first space to get the method.  This correctly handles paths that contain
    # literal spaces (e.g. get-space: "GET /example space/ HTTP/1.1").
    request_line = lines[0]
    path_and_version, _, _ = request_line.rpartition(" HTTP/")
    method, _, path_and_query = path_and_version.partition(" ")

    # Parse headers (multiline values continue with leading whitespace;
    # duplicate header names are comma-joined per the AWS spec).
    headers: dict[str, str] = {}
    i = 1
    while i < len(lines) and lines[i] != "":
        line = lines[i]
        if line and line[0] in (" ", "\t"):
            # Continuation of previous header value.
            last_key = list(headers.keys())[-1]
            headers[last_key] = headers[last_key] + " " + line.strip()
        else:
            colon_pos = line.index(":")
            key = line[:colon_pos].lower()
            value = line[colon_pos + 1 :]
            if key in headers:
                # Duplicate header — comma-join values (AWS canonical form).
                headers[key] = headers[key] + "," + value
            else:
                headers[key] = value
        i += 1

    # Body is everything after the blank line
    body_lines = lines[i + 1 :] if i < len(lines) else []
    body = "\n".join(body_lines).encode("utf-8") if body_lines else b""

    # Reconstruct URL
    host = headers.get("host", "")
    url = f"https://{host}{path_and_query}"

    return method, url, headers, body


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8").rstrip("\n")


def _creds_for(name: str, headers: dict[str, str]) -> Credentials:
    """Return credentials for a given test case, injecting session token as needed."""
    # First priority: token embedded directly in the .req headers.
    token: str | None = headers.get("x-amz-security-token")
    # Second priority: well-known token for get-vanilla-with-session-token,
    # which has no X-Amz-Security-Token header in its .req file.
    if token is None and name == "get-vanilla-with-session-token":
        token = _SESSION_TOKEN_GET_VANILLA
    return Credentials(
        access_key=_CREDS.access_key,
        secret_key=_CREDS.secret_key,
        token=token,
    )


def _working_headers(
    headers: dict[str, str], url: str, token: str | None
) -> dict[str, str]:
    """Build the working header set that sign_headers() uses internally."""
    parsed = urlsplit(url)
    working = dict(headers)
    if "host" not in working:
        working["host"] = parsed.netloc
    working["x-amz-date"] = _TIMESTAMP.strftime("%Y%m%dT%H%M%SZ")
    if token:
        working["x-amz-security-token"] = token
    return {k.lower(): v for k, v in working.items()}


# ---------------------------------------------------------------------------
# Parametrized tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name,case_dir", _ALL_CASES, ids=_CASE_IDS)
def test_authorization_header(name: str, case_dir: Path) -> None:
    """End-to-end: sign_headers() must produce the expected Authorization value."""

    stem = case_dir.name
    req_path = case_dir / f"{stem}.req"
    authz_path = case_dir / f"{stem}.authz"

    method, url, headers, body = _parse_req(req_path)
    expected_authz = _read(authz_path)

    creds = _creds_for(name, headers)

    result = sign_headers(
        method=method,
        url=url,
        headers=headers,
        body=body,
        region=_REGION,
        service=_SERVICE,
        credentials=creds,
        timestamp=_TIMESTAMP,
    )

    assert result["Authorization"] == expected_authz, (
        f"Test case: {name}\n"
        f"Expected:  {expected_authz}\n"
        f"Got:       {result['Authorization']}"
    )


@pytest.mark.parametrize("name,case_dir", _ALL_CASES, ids=_CASE_IDS)
def test_canonical_request(name: str, case_dir: Path) -> None:
    """The canonical request must match the .creq file exactly."""

    stem = case_dir.name
    req_path = case_dir / f"{stem}.req"
    creq_path = case_dir / f"{stem}.creq"

    method, url, headers, body = _parse_req(req_path)
    expected_creq = _read(creq_path)

    creds = _creds_for(name, headers)
    working = _working_headers(headers, url, creds.token)

    parsed = urlsplit(url)
    got_creq = _canonical_request(method, parsed, working, body)

    assert got_creq == expected_creq, (
        f"Test case: {name}\n"
        f"Expected canonical request:\n{expected_creq}\n"
        f"Got:\n{got_creq}"
    )


@pytest.mark.parametrize("name,case_dir", _ALL_CASES, ids=_CASE_IDS)
def test_string_to_sign(name: str, case_dir: Path) -> None:
    """The string to sign must match the .sts file exactly."""

    stem = case_dir.name
    req_path = case_dir / f"{stem}.req"
    sts_path = case_dir / f"{stem}.sts"

    method, url, headers, body = _parse_req(req_path)
    expected_sts = _read(sts_path)

    creds = _creds_for(name, headers)
    working = _working_headers(headers, url, creds.token)

    parsed = urlsplit(url)
    canonical_req = _canonical_request(method, parsed, working, body)

    amz_date = _TIMESTAMP.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = _TIMESTAMP.strftime("%Y%m%d")
    got_sts = _string_to_sign(amz_date, date_stamp, _REGION, _SERVICE, canonical_req)

    assert got_sts == expected_sts, (
        f"Test case: {name}\nExpected string to sign:\n{expected_sts}\nGot:\n{got_sts}"
    )
