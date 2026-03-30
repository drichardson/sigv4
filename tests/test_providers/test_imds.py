# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the IMDS credential provider.

Two layers of tests:

1. Unit tests for ``_is_not_present`` — verify each errno is classified correctly.

2. Integration tests using a real local HTTP server (pytest fixtures) — verify
   that ``try_load_from_imds`` behaves correctly end-to-end when the server is:
   - not running (connection refused)      → return None
   - running but timing out               → raise
   - running and returning valid creds    → return Credentials
   - running but returning a bad response → raise
"""

import errno
import json
import socket
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from aws_sigv4.providers.imds import _is_not_present, try_load_from_imds


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _url_error(err: int) -> urllib.error.URLError:
    """Build a URLError whose .reason has the given errno (as urllib does)."""
    inner = OSError(err, errno.errorcode.get(err, str(err)))
    inner.errno = err
    return urllib.error.URLError(inner)


# ---------------------------------------------------------------------------
# Unit tests: _is_not_present
# ---------------------------------------------------------------------------


def test_connection_refused_is_not_present():
    assert _is_not_present(_url_error(errno.ECONNREFUSED))


def test_network_unreachable_is_not_present():
    assert _is_not_present(_url_error(errno.ENETUNREACH))


def test_host_unreachable_is_not_present():
    assert _is_not_present(_url_error(errno.EHOSTUNREACH))


def test_timeout_is_not_not_present():
    """A timeout means something is there but not responding — should raise."""
    assert not _is_not_present(_url_error(errno.ETIMEDOUT))


def test_generic_oserror_is_not_not_present():
    """A generic OSError (e.g. EIO) is not in the not-present set — should raise."""
    assert not _is_not_present(_url_error(errno.EIO))


# ---------------------------------------------------------------------------
# Local IMDS server fixtures
# ---------------------------------------------------------------------------

# Minimal IMDSv2 responses.
_ROLE_NAME = "test-role"
_CREDS_RESPONSE = {
    "Code": "Success",
    "AccessKeyId": "IMDS_AKID",
    "SecretAccessKey": "IMDS_SECRET",
    "Token": "IMDS_TOKEN",
    "Expiration": "2099-01-01T00:00:00Z",
}


class _IMDSHandler(BaseHTTPRequestHandler):
    """Minimal IMDSv2 handler serving the token and credentials endpoints."""

    def log_message(self, format, *args):  # noqa: A002
        pass  # suppress request logging in test output

    def do_PUT(self):
        # Token endpoint.
        if self.path == "/latest/api/token":
            ttl = self.headers.get("X-aws-ec2-metadata-token-ttl-seconds", "")
            if not ttl:
                self.send_response(400)
                self.end_headers()
                return
            token = "test-imds-token"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(token.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        token = self.headers.get("X-aws-ec2-metadata-token", "")
        if not token:
            self.send_response(401)
            self.end_headers()
            return

        if self.path == "/latest/meta-data/iam/security-credentials/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(_ROLE_NAME.encode())

        elif self.path == f"/latest/meta-data/iam/security-credentials/{_ROLE_NAME}":
            body = json.dumps(_CREDS_RESPONSE).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()


def _free_port() -> int:
    """Find a free TCP port on localhost."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def imds_server(monkeypatch):
    """
    Start a real local HTTP server simulating IMDS and point the provider at it.
    Yields the server address as ``(host, port)``.
    """
    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), _IMDSHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    monkeypatch.setattr(
        "aws_sigv4.providers.imds._IMDS_BASE",
        f"http://127.0.0.1:{port}/latest",
    )
    monkeypatch.setattr("aws_sigv4.providers.imds._CONNECT_TIMEOUT", 2)

    yield ("127.0.0.1", port)

    server.shutdown()
    thread.join(timeout=2)


@pytest.fixture()
def imds_server_port(monkeypatch):
    """
    Return a port with nothing listening on it (connection refused), and point
    the provider at it.
    """
    port = _free_port()
    # Do NOT start a server — the port is free but nothing is listening.
    monkeypatch.setattr(
        "aws_sigv4.providers.imds._IMDS_BASE",
        f"http://127.0.0.1:{port}/latest",
    )
    monkeypatch.setattr("aws_sigv4.providers.imds._CONNECT_TIMEOUT", 2)
    return port


# ---------------------------------------------------------------------------
# Integration tests: try_load_from_imds with real server
# ---------------------------------------------------------------------------


def test_returns_credentials_when_server_running(imds_server):
    """Server is up and returns valid credentials — should return Credentials."""
    creds = try_load_from_imds()
    assert creds is not None
    assert creds.access_key == "IMDS_AKID"
    assert creds.secret_key == "IMDS_SECRET"
    assert creds.token == "IMDS_TOKEN"
    assert creds.expires_at is not None


def test_returns_none_when_connection_refused(imds_server_port):
    """Nothing listening on the port — connection refused → return None."""
    result = try_load_from_imds()
    assert result is None


def test_raises_when_server_returns_bad_credentials(imds_server, monkeypatch):
    """Server is up but returns a malformed credentials response — should raise."""

    class _BadHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):  # noqa: A002
            pass

        def do_PUT(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"test-token")

        def do_GET(self):
            if self.path.endswith("/security-credentials/"):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"bad-role")
            else:
                # Return JSON missing the required fields.
                body = json.dumps({"Code": "Success"}).encode()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(body)

    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), _BadHandler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()

    monkeypatch.setattr(
        "aws_sigv4.providers.imds._IMDS_BASE",
        f"http://127.0.0.1:{port}/latest",
    )

    try:
        with pytest.raises(RuntimeError):
            try_load_from_imds()
    finally:
        server.shutdown()
        thread.join(timeout=2)
