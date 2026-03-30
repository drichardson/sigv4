# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the Web Identity / IRSA provider."""

from unittest.mock import patch

import pytest

from aws_sigv4.providers.web_identity import WebIdentityProvider, _parse_sts_response


_STS_RESPONSE = b"""
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>STS_AKID</AccessKeyId>
      <SecretAccessKey>STS_SECRET</SecretAccessKey>
      <SessionToken>STS_TOKEN</SessionToken>
      <Expiration>2026-03-29T12:00:00Z</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>
"""


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
    monkeypatch.setenv("AWS_ROLE_ARN", "arn:aws:iam::123456789012:role/MyRole")

    with pytest.raises(RuntimeError, match="Failed to read web identity token file"):
        WebIdentityProvider().try_load()
