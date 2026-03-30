# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the Web Identity / IRSA provider."""

from unittest.mock import patch

import pytest

from aws_sigv4.providers.web_identity import WebIdentityProvider, _parse_sts_response


_ROLE_ARN = "arn:aws:iam::123456789012:role/MyRole"

_STS_RESPONSE = b"""
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>STS_AKID</AccessKeyId>
      <SecretAccessKey>STS_SECRET</SecretAccessKey>
      <SessionToken>STS_TOKEN</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
"""

_STS_ERROR_RESPONSE = b"""
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>Not authorized to assume role</Message>
  </Error>
</ErrorResponse>
"""


def test_regional_sts_endpoint_used_when_configured(monkeypatch, tmp_path):
    """AWS_STS_REGIONAL_ENDPOINTS=regional + region -> regional STS endpoint."""
    from aws_sigv4.providers.web_identity import _resolve_sts_endpoint

    monkeypatch.setenv("AWS_STS_REGIONAL_ENDPOINTS", "regional")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "eu-west-1")
    monkeypatch.delenv("AWS_REGION", raising=False)

    endpoint = _resolve_sts_endpoint()
    assert endpoint == "https://sts.eu-west-1.amazonaws.com/"


def test_regional_sts_endpoint_falls_back_to_global_when_no_region(monkeypatch):
    """AWS_STS_REGIONAL_ENDPOINTS=regional but no region -> global endpoint."""
    from aws_sigv4.providers.web_identity import _resolve_sts_endpoint, _STS_ENDPOINT

    monkeypatch.setenv("AWS_STS_REGIONAL_ENDPOINTS", "regional")
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.delenv("AWS_REGION", raising=False)

    assert _resolve_sts_endpoint() == _STS_ENDPOINT


def test_sts_xml_without_namespace_parsed(tmp_path):
    """STS response without xmlns declaration still parses via fallback ns_map."""
    from aws_sigv4.providers.web_identity import _parse_sts_response

    # Same structure but without the xmlns attribute.
    xml = b"""
<AssumeRoleWithWebIdentityResponse>
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>NO_NS_AKID</AccessKeyId>
      <SecretAccessKey>NO_NS_SECRET</SecretAccessKey>
      <SessionToken>NO_NS_TOKEN</SessionToken>
      <Expiration>2099-01-01T00:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
"""
    creds = _parse_sts_response(xml)
    assert creds.access_key == "NO_NS_AKID"


def test_sts_xml_missing_field_raises(tmp_path):
    """STS response missing a required field -> RuntimeError from find()."""
    from aws_sigv4.providers.web_identity import _parse_sts_response

    xml = b"""
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKID</AccessKeyId>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
"""
    with pytest.raises(RuntimeError, match="could not find"):
        _parse_sts_response(xml)


def test_returns_none_when_env_vars_missing(monkeypatch):
    monkeypatch.delenv("AWS_WEB_IDENTITY_TOKEN_FILE", raising=False)
    monkeypatch.delenv("AWS_ROLE_ARN", raising=False)
    assert WebIdentityProvider().try_load() is None


def test_returns_none_when_only_token_file(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("myjwt")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("AWS_ROLE_ARN", raising=False)
    assert WebIdentityProvider().try_load() is None


def test_parse_sts_response():
    creds = _parse_sts_response(_STS_RESPONSE)
    assert creds.access_key == "STS_AKID"
    assert creds.secret_key == "STS_SECRET"
    assert creds.token == "STS_TOKEN"
    assert creds.expires_at is not None


def test_load_calls_sts(monkeypatch, tmp_path):
    token_file = tmp_path / "token"
    token_file.write_text("myjwt")
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/MyRole")
    monkeypatch.delenv("AWS_ROLE_SESSION_NAME", raising=False)
    monkeypatch.delenv("AWS_STS_REGIONAL_ENDPOINTS", raising=False)

    with patch(
        "aws_sigv4.providers.web_identity._assume_role_with_web_identity"
    ) as mock_sts:
        mock_sts.return_value = _parse_sts_response(_STS_RESPONSE)
        creds = WebIdentityProvider().try_load()

    assert creds is not None
    assert creds.access_key == "STS_AKID"
    mock_sts.assert_called_once()
    call_kwargs = mock_sts.call_args.kwargs
    assert call_kwargs["role_arn"] == "arn:aws:iam::123456789012:role/MyRole"
    assert call_kwargs["web_identity_token"] == "myjwt"


def test_token_file_not_found_raises(monkeypatch):
    monkeypatch.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", "/nonexistent/token")
    monkeypatch.setenv("AWS_ROLE_ARN", _ROLE_ARN)

    with pytest.raises(RuntimeError, match="Failed to read web identity token file"):
        WebIdentityProvider().try_load()


# ---------------------------------------------------------------------------
# Integration tests using a real local STS server (pytest-httpserver)
# ---------------------------------------------------------------------------


def _make_provider(httpserver, tmp_path, token="myjwt"):
    """Create a WebIdentityProvider pointed at the local httpserver."""
    token_file = tmp_path / "token"
    token_file.write_text(token)
    return WebIdentityProvider(
        token_file=str(token_file),
        role_arn=_ROLE_ARN,
        sts_endpoint=httpserver.url_for("/"),
    )


def test_sts_valid_response_returns_credentials(httpserver, tmp_path):
    """Valid STS XML response -> Credentials with correct fields."""
    httpserver.expect_request("/", method="POST").respond_with_data(
        _STS_RESPONSE, content_type="text/xml"
    )
    creds = _make_provider(httpserver, tmp_path).try_load()
    assert creds is not None
    assert creds.access_key == "STS_AKID"
    assert creds.secret_key == "STS_SECRET"
    assert creds.token == "STS_TOKEN"
    assert creds.expires_at is not None


def test_sts_403_raises(httpserver, tmp_path):
    """STS returns HTTP 403 -- provider available but broken -- should raise."""
    httpserver.expect_request("/", method="POST").respond_with_data(
        _STS_ERROR_RESPONSE, status=403, content_type="text/xml"
    )
    with pytest.raises(RuntimeError, match="403"):
        _make_provider(httpserver, tmp_path).try_load()


def test_sts_malformed_xml_raises(httpserver, tmp_path):
    """STS returns malformed XML -- should raise."""
    httpserver.expect_request("/", method="POST").respond_with_data(
        b"<not valid xml", content_type="text/xml"
    )
    with pytest.raises(Exception):
        _make_provider(httpserver, tmp_path).try_load()


def test_sts_receives_web_identity_token(httpserver, tmp_path):
    """The JWT from the token file must be sent to STS as WebIdentityToken."""
    received_bodies = []

    def handler(request):
        received_bodies.append(request.get_data(as_text=True))
        from werkzeug.wrappers import Response

        return Response(_STS_RESPONSE, content_type="text/xml")

    httpserver.expect_request("/", method="POST").respond_with_handler(handler)
    _make_provider(httpserver, tmp_path, token="my-k8s-jwt").try_load()

    assert len(received_bodies) == 1
    assert "WebIdentityToken=my-k8s-jwt" in received_bodies[0]


def test_token_file_reread_on_each_call(httpserver, tmp_path):
    """Token file must be re-read on every call (Kubernetes rotates it)."""
    received_bodies = []

    def handler(request):
        received_bodies.append(request.get_data(as_text=True))
        from werkzeug.wrappers import Response

        return Response(_STS_RESPONSE, content_type="text/xml")

    # Use expect_request (not ordered) so it matches multiple POST calls.
    httpserver.expect_request("/", method="POST").respond_with_handler(handler)

    token_file = tmp_path / "token"
    token_file.write_text("original-token")
    provider = WebIdentityProvider(
        token_file=str(token_file),
        role_arn=_ROLE_ARN,
        sts_endpoint=httpserver.url_for("/"),
    )

    provider.try_load()
    assert "WebIdentityToken=original-token" in received_bodies[0]

    # Simulate Kubernetes rotating the token.
    token_file.write_text("rotated-token")
    provider.try_load()

    assert len(received_bodies) == 2
    assert "WebIdentityToken=rotated-token" in received_bodies[1]
