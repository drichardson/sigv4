# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
AWS Signature Version 4 signing — pure computation, zero I/O.

Reference: https://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
"""

import hashlib
import hmac
import re
from datetime import UTC, datetime
from urllib.parse import quote, urlsplit, parse_qsl

from sigv4.credentials import Credentials

# Headers excluded from the signature.
#
# The AWS docs specify that hop-by-hop and volatile transport headers must not
# be signed because they are mutated by proxies, load balancers, and the nodes
# in a distributed system:
#   connection, x-amzn-trace-id, user-agent, keep-alive, transfer-encoding,
#   te, trailer, upgrade, proxy-authorization, proxy-authenticate
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv-create-signed-request.html
#
# "authorization" is also excluded — it contains the signature itself and
# cannot be an input to its own computation.
#
# "expect" is excluded because the Expect mechanism is hop-by-hop
# (RFC 9110 §10.1.1) — intermediaries may consume or modify it before the
# request reaches AWS, which would invalidate the signature.
_HEADERS_TO_IGNORE = frozenset(
    [
        "authorization",
        "connection",
        "expect",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
        "x-amzn-trace-id",
    ]
)

EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

_ALGORITHM = "AWS4-HMAC-SHA256"


def sign_headers(
    *,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    region: str,
    service: str,
    credentials: Credentials,
    timestamp: datetime | None = None,
) -> dict[str, str]:
    """
    Low-level SigV4 signing. Pure computation — no I/O, no credential refresh.

    Returns a dict of headers to merge into your request:
      - ``Authorization``
      - ``X-Amz-Date``
      - ``X-Amz-Security-Token`` (only if credentials.token is set)

    Args:
        method: HTTP method (GET, POST, PUT, …)
        url: Full URL including scheme, host, path, and query string.
        headers: Request headers you intend to send. ``host`` will be derived
            from *url* if not present. Do not include ``Authorization`` here.
        body: Raw request body bytes. Pass ``b""`` for requests with no body.
        region: AWS region name, e.g. ``"us-east-1"``.
        service: AWS service name, e.g. ``"s3"`` or ``"execute-api"``.
        credentials: Static credentials (access_key, secret_key, optional token).
            Use :func:`sigv4.resolve_credentials` to obtain these.
        timestamp: Override the signing timestamp. Defaults to UTC now. Useful
            for testing with known-good test vectors.

    Returns:
        Dict of headers to add to your request. Merge with your existing headers.
    """
    if timestamp is None:
        timestamp = datetime.now(UTC)

    amz_date = timestamp.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = timestamp.strftime("%Y%m%d")

    parsed = urlsplit(url)

    # Build the working header set: start with caller-supplied headers,
    # add host if missing, add X-Amz-Date and optionally X-Amz-Security-Token.
    working_headers: dict[str, str] = {k.lower(): v for k, v in headers.items()}
    if "host" not in working_headers:
        working_headers["host"] = parsed.netloc
    working_headers["x-amz-date"] = amz_date
    if credentials.token:
        working_headers["x-amz-security-token"] = credentials.token

    canonical_req = _canonical_request(method, parsed, working_headers, body)
    sts = _string_to_sign(amz_date, date_stamp, region, service, canonical_req)
    sig = _signature(credentials.secret_key, date_stamp, region, service, sts)
    signed_hdrs = _signed_headers(working_headers)

    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    authorization = (
        f"{_ALGORITHM} "
        f"Credential={credentials.access_key}/{credential_scope}, "
        f"SignedHeaders={signed_hdrs}, "
        f"Signature={sig}"
    )

    result: dict[str, str] = {
        "Authorization": authorization,
        "X-Amz-Date": amz_date,
    }
    if credentials.token:
        result["X-Amz-Security-Token"] = credentials.token

    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _canonical_request(
    method: str,
    parsed: object,  # SplitResult
    headers: dict[str, str],  # already lowercased
    body: bytes,
) -> str:
    from urllib.parse import SplitResult

    assert isinstance(parsed, SplitResult)
    canonical_uri = _canonical_uri(parsed.path)
    canonical_qs = _canonical_query_string(parsed.query)
    canonical_hdrs = _canonical_headers_str(headers)
    signed_hdrs = _signed_headers(headers)
    payload_hash = _payload_hash(body)

    return "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_qs,
            canonical_hdrs,
            "",  # canonical_hdrs already ends without newline; AWS spec wants blank line
            signed_hdrs,
            payload_hash,
        ]
    )


def _canonical_uri(path: str) -> str:
    if not path:
        return "/"
    # Normalize the path per RFC 3986: resolve '.' and '..' segments and
    # collapse consecutive slashes.  This matches botocore's behaviour and is
    # required by the AWS SigV4 test suite normalize-path test cases.
    path = _normalize_path(path)
    return quote(path, safe="/~")


def _normalize_path(path: str) -> str:
    """Resolve '.' and '..' segments and collapse consecutive slashes."""
    # Split on '/' keeping track of whether the path ends with a slash.
    parts = path.split("/")
    resolved: list[str] = []
    for part in parts:
        if part == "..":
            if resolved:
                resolved.pop()
        elif part == ".":
            pass  # skip
        else:
            resolved.append(part)
    normalized = "/".join(resolved)
    # Ensure it starts with '/' and never becomes empty.
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    # Collapse consecutive slashes (e.g. '//example//' → '/example/').
    import re as _re

    normalized = _re.sub(r"/+", "/", normalized)
    return normalized or "/"


def _canonical_query_string(query: str) -> str:
    if not query:
        return ""
    # parse_qsl preserves duplicate keys; sort by (key, value).
    pairs = parse_qsl(query, keep_blank_values=True)
    # URI-encode each key and value independently (safe chars per AWS spec).
    encoded = sorted((quote(k, safe="-_.~"), quote(v, safe="-_.~")) for k, v in pairs)
    return "&".join(f"{k}={v}" for k, v in encoded)


def _canonical_headers_str(headers: dict[str, str]) -> str:
    """Return the canonical headers block (no trailing newline)."""
    filtered = {k: v for k, v in headers.items() if k not in _HEADERS_TO_IGNORE}
    lines = []
    for key in sorted(filtered):
        # Collapse sequential whitespace to a single space and strip.
        value = re.sub(r"\s+", " ", filtered[key]).strip()
        lines.append(f"{key}:{value}")
    return "\n".join(lines)


def _signed_headers(headers: dict[str, str]) -> str:
    filtered = [k for k in headers if k not in _HEADERS_TO_IGNORE]
    return ";".join(sorted(filtered))


def _payload_hash(body: bytes) -> str:
    if not body:
        return EMPTY_SHA256
    return hashlib.sha256(body).hexdigest()


def _string_to_sign(
    amz_date: str,
    date_stamp: str,
    region: str,
    service: str,
    canonical_request: str,
) -> str:
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    hashed_cr = hashlib.sha256(canonical_request.encode()).hexdigest()
    return "\n".join([_ALGORITHM, amz_date, credential_scope, hashed_cr])


def _hmac_sha256(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def _signing_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = _hmac_sha256(f"AWS4{secret_key}".encode(), date_stamp)
    k_region = _hmac_sha256(k_date, region)
    k_service = _hmac_sha256(k_region, service)
    return _hmac_sha256(k_service, "aws4_request")


def _signature(
    secret_key: str, date_stamp: str, region: str, service: str, string_to_sign: str
) -> str:
    key = _signing_key(secret_key, date_stamp, region, service)
    return hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
