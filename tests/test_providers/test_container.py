# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the container credential provider."""

import json

import pytest

from aws_sigv4.credentials import SigV4Error
from aws_sigv4.providers.container import try_load_from_container

_VALID_CREDS = {
    "AccessKeyId": "CONTAINER_AKID",
    "SecretAccessKey": "CONTAINER_SECRET",
    "Token": "CONTAINER_TOKEN",
    "Expiration": "2099-01-01T00:00:00Z",
}


# ---------------------------------------------------------------------------
# Provider not available (env vars not set) -> None
# ---------------------------------------------------------------------------


def test_returns_none_when_no_env_vars(monkeypatch):
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", raising=False)
    assert try_load_from_container() is None


# ---------------------------------------------------------------------------
# AWS_CONTAINER_CREDENTIALS_RELATIVE_URI
# ---------------------------------------------------------------------------


def test_relative_uri_returns_credentials(httpserver, monkeypatch):
    """AWS_CONTAINER_CREDENTIALS_RELATIVE_URI is appended to the ECS metadata
    host. We patch _ECS_METADATA_HOST to our local server to test end-to-end."""
    httpserver.expect_request("/creds").respond_with_json(_VALID_CREDS)

    monkeypatch.setattr(
        "aws_sigv4.providers.container._ECS_METADATA_HOST",
        httpserver.url_for("/").rstrip("/"),
    )
    monkeypatch.setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/creds")
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", raising=False)

    creds = try_load_from_container()
    assert creds is not None
    assert creds.access_key == "CONTAINER_AKID"
    assert creds.secret_key == "CONTAINER_SECRET"
    assert creds.token == "CONTAINER_TOKEN"
    assert creds.expires_at is not None


# ---------------------------------------------------------------------------
# AWS_CONTAINER_CREDENTIALS_FULL_URI
# ---------------------------------------------------------------------------


def test_full_uri_returns_credentials(httpserver, monkeypatch):
    httpserver.expect_request("/creds").respond_with_json(_VALID_CREDS)
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", httpserver.url_for("/creds")
    )
    creds = try_load_from_container()
    assert creds is not None
    assert creds.access_key == "CONTAINER_AKID"


def test_full_uri_disallowed_prefix_returns_none(monkeypatch):
    """A full URI with a non-allowed prefix is a security violation -- return None."""
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", "http://evil.example.com/steal-creds"
    )
    assert try_load_from_container() is None


def test_full_uri_https_allowed(httpserver, monkeypatch):
    """HTTPS URIs are allowed regardless of host."""
    # pytest-httpserver uses HTTP; we just test the prefix check logic here
    # by confirming an https:// URI passes the allowlist check (it will then
    # fail with a connection error since there's no HTTPS server, but the
    # important thing is it's not rejected by the prefix check).
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", "https://localhost:9999/creds"
    )
    # Should raise (connection error to non-existent server), not return None.
    with pytest.raises(SigV4Error):
        try_load_from_container()


# ---------------------------------------------------------------------------
# Auth token forwarding
# ---------------------------------------------------------------------------


def test_auth_token_forwarded(httpserver, monkeypatch):
    """AWS_CONTAINER_AUTHORIZATION_TOKEN must be sent as the Authorization header."""
    received_auth = []

    def handler(request):
        received_auth.append(request.headers.get("Authorization"))
        from werkzeug.wrappers import Response

        return Response(json.dumps(_VALID_CREDS), content_type="application/json")

    httpserver.expect_request("/creds").respond_with_handler(handler)
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", httpserver.url_for("/creds")
    )
    monkeypatch.setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "Bearer mytoken")

    try_load_from_container()
    assert received_auth == ["Bearer mytoken"]


# ---------------------------------------------------------------------------
# Error cases (provider available but broken)
# ---------------------------------------------------------------------------


def test_raises_when_server_returns_500(httpserver, monkeypatch):
    """Server returns 500 -- provider is available but broken -- should raise."""
    httpserver.expect_request("/creds").respond_with_data("error", status=500)
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", httpserver.url_for("/creds")
    )
    with pytest.raises(SigV4Error):
        try_load_from_container()


def test_raises_when_response_missing_keys(httpserver, monkeypatch):
    """Server returns JSON missing AccessKeyId -- should raise."""
    httpserver.expect_request("/creds").respond_with_json({"Token": "tok"})
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", httpserver.url_for("/creds")
    )
    with pytest.raises(SigV4Error, match="missing required fields"):
        try_load_from_container()


def test_raises_when_response_not_json(httpserver, monkeypatch):
    """Server returns non-JSON -- should raise."""
    httpserver.expect_request("/creds").respond_with_data(
        "not json", content_type="text/plain"
    )
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", httpserver.url_for("/creds")
    )
    with pytest.raises(SigV4Error):
        try_load_from_container()


def test_credentials_without_expiry(httpserver, monkeypatch):
    """Response without Expiration field -- expires_at should be None."""
    creds_no_expiry = {
        "AccessKeyId": "AKID",
        "SecretAccessKey": "secret",
    }
    httpserver.expect_request("/creds").respond_with_json(creds_no_expiry)
    monkeypatch.delenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", raising=False)
    monkeypatch.setenv(
        "AWS_CONTAINER_CREDENTIALS_FULL_URI", httpserver.url_for("/creds")
    )
    creds = try_load_from_container()
    assert creds is not None
    assert creds.expires_at is None
