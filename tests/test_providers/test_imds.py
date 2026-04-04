# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the IMDS credential provider.

Two layers of tests:

1. Unit tests for ``_is_not_present`` — verify each errno is classified correctly.

2. Integration tests using ``pytest-httpserver`` (a real local HTTP server) —
   verify that ``try_load_from_imds`` behaves correctly end-to-end. The
   session-scoped server starts once for the entire test run; ``httpserver``
   clears expectations between tests automatically.

Connection-refused tests use a bare port with nothing listening — these cannot
use ``httpserver`` by design, since we need the connection to be rejected.
"""

import errno
import socket
import urllib.error

import pytest

from aws_sigv4.credentials import SigV4Error
from aws_sigv4.providers.imds import _is_not_present, try_load_from_imds

# ---------------------------------------------------------------------------
# Valid IMDS response bodies
# ---------------------------------------------------------------------------

_ROLE_NAME = "test-role"
_CREDS_JSON = {
    "Code": "Success",
    "AccessKeyId": "IMDS_AKID",
    "SecretAccessKey": "IMDS_SECRET",
    "Token": "IMDS_TOKEN",
    "Expiration": "2099-01-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# Unit tests: _is_not_present
# ---------------------------------------------------------------------------


def _url_error(err: int) -> urllib.error.URLError:
    """Build a URLError whose .reason has the given errno (as urllib does)."""
    inner = OSError(err, errno.errorcode.get(err, str(err)))
    inner.errno = err
    return urllib.error.URLError(inner)


def test_connection_refused_is_not_present():
    assert _is_not_present(_url_error(errno.ECONNREFUSED))


def test_network_unreachable_is_not_present():
    assert _is_not_present(_url_error(errno.ENETUNREACH))


def test_host_unreachable_is_not_present():
    assert _is_not_present(_url_error(errno.EHOSTUNREACH))


def test_timeout_is_not_not_present():
    """A timeout means something is there but not responding -- should raise."""
    assert not _is_not_present(_url_error(errno.ETIMEDOUT))


def test_generic_oserror_is_not_not_present():
    """A generic OSError (e.g. EIO) is not in the not-present set -- should raise."""
    assert not _is_not_present(_url_error(errno.EIO))


# ---------------------------------------------------------------------------
# Helpers for httpserver-based tests
# ---------------------------------------------------------------------------


def _register_imds(httpserver, role_name=_ROLE_NAME, creds=None):
    """Register the three IMDSv2 endpoints on httpserver."""
    if creds is None:
        creds = _CREDS_JSON
    httpserver.expect_ordered_request(
        "/latest/api/token", method="PUT"
    ).respond_with_data("test-imds-token")
    httpserver.expect_ordered_request(
        "/latest/meta-data/iam/security-credentials/"
    ).respond_with_data(role_name)
    httpserver.expect_ordered_request(
        f"/latest/meta-data/iam/security-credentials/{role_name}"
    ).respond_with_json(creds)


@pytest.fixture(autouse=True)
def _point_imds_at_httpserver(httpserver, monkeypatch):
    """Point the IMDS provider at the local httpserver for every test in this module."""
    monkeypatch.setattr(
        "aws_sigv4.providers.imds._IMDS_BASE",
        httpserver.url_for("/latest"),
    )
    monkeypatch.setattr("aws_sigv4.providers.imds._CONNECT_TIMEOUT", 2)


# ---------------------------------------------------------------------------
# Integration tests: try_load_from_imds with real httpserver
# ---------------------------------------------------------------------------


def test_returns_credentials_when_server_running(httpserver):
    """Server is up and returns valid credentials -- should return Credentials."""
    _register_imds(httpserver)
    creds = try_load_from_imds()
    assert creds is not None
    assert creds.access_key == "IMDS_AKID"
    assert creds.secret_key == "IMDS_SECRET"
    assert creds.token == "IMDS_TOKEN"
    assert creds.expires_at is not None


def test_returns_none_when_no_role_attached(httpserver):
    """Server is up but security-credentials endpoint returns 404 (no role)."""
    httpserver.expect_ordered_request(
        "/latest/api/token", method="PUT"
    ).respond_with_data("test-imds-token")
    httpserver.expect_ordered_request(
        "/latest/meta-data/iam/security-credentials/"
    ).respond_with_data("", status=404)
    assert try_load_from_imds() is None


def test_raises_when_credentials_response_missing_keys(httpserver):
    """Server returns a JSON response missing AccessKeyId -- should raise."""
    httpserver.expect_ordered_request(
        "/latest/api/token", method="PUT"
    ).respond_with_data("test-imds-token")
    httpserver.expect_ordered_request(
        "/latest/meta-data/iam/security-credentials/"
    ).respond_with_data(_ROLE_NAME)
    httpserver.expect_ordered_request(
        f"/latest/meta-data/iam/security-credentials/{_ROLE_NAME}"
    ).respond_with_json({"Code": "Success"})

    with pytest.raises(SigV4Error, match="missing required fields"):
        try_load_from_imds()


def test_raises_when_credentials_code_not_success(httpserver):
    """Server returns Code != Success -- should raise."""
    httpserver.expect_ordered_request(
        "/latest/api/token", method="PUT"
    ).respond_with_data("test-imds-token")
    httpserver.expect_ordered_request(
        "/latest/meta-data/iam/security-credentials/"
    ).respond_with_data(_ROLE_NAME)
    httpserver.expect_ordered_request(
        f"/latest/meta-data/iam/security-credentials/{_ROLE_NAME}"
    ).respond_with_json({"Code": "Failed"})

    with pytest.raises(SigV4Error, match="non-success"):
        try_load_from_imds()


def test_raises_when_token_request_times_out(httpserver):
    """URLError that is NOT a not-present error (e.g. timeout simulation) -- raise."""
    import urllib.error

    from unittest.mock import patch

    timeout_err = urllib.error.URLError(OSError(errno.ETIMEDOUT, "timed out"))
    timeout_err.reason = OSError(errno.ETIMEDOUT, "timed out")
    timeout_err.reason.errno = errno.ETIMEDOUT

    with patch("aws_sigv4.providers.imds._get_imds_token", side_effect=timeout_err):
        with pytest.raises(urllib.error.URLError):
            try_load_from_imds()


def test_returns_none_when_connection_refused(monkeypatch):
    """Nothing listening on the port -- connection refused -> return None.

    This test intentionally does NOT use httpserver -- we need a port with
    nothing listening to provoke ECONNREFUSED.
    """
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    # Socket released; nothing is listening on that port now.
    monkeypatch.setattr(
        "aws_sigv4.providers.imds._IMDS_BASE",
        f"http://127.0.0.1:{port}/latest",
    )
    assert try_load_from_imds() is None
