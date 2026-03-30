# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT


from aws_sigv4.providers.env import try_load_from_env


def test_returns_none_when_no_env_vars(monkeypatch):
    monkeypatch.delenv("AWS_ACCESS_KEY_ID", raising=False)
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    assert try_load_from_env() is None


def test_returns_none_when_only_access_key(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.delenv("AWS_SECRET_ACCESS_KEY", raising=False)
    assert try_load_from_env() is None


def test_returns_credentials(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("AWS_SECURITY_TOKEN", raising=False)

    creds = try_load_from_env()
    assert creds is not None
    assert creds.access_key == "AKID"
    assert creds.secret_key == "secret"
    assert creds.token is None


def test_returns_session_token(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "mytoken")
    monkeypatch.delenv("AWS_SECURITY_TOKEN", raising=False)

    creds = try_load_from_env()
    assert creds is not None
    assert creds.token == "mytoken"


def test_legacy_security_token_var(monkeypatch):
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "legacytoken")

    creds = try_load_from_env()
    assert creds is not None
    assert creds.token == "legacytoken"
