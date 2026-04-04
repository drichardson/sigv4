# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the credential chain (_ChainProvider) error propagation behaviour.

Key invariants:
- Provider returns None → chain moves to the next provider
- Provider raises → exception propagates to the caller (chain does not swallow it)
- All providers return None → SigV4Error with a helpful message
"""

import pytest

from aws_sigv4.credentials import SigV4Error, Credentials
from aws_sigv4.resolve import resolve_credentials


_CREDS = Credentials(access_key="AKID", secret_key="secret")


def test_chain_returns_first_match():
    creds = resolve_credentials(providers=[lambda: None, lambda: _CREDS])
    assert creds.get().access_key == "AKID"


def test_chain_skips_none_providers():
    """Providers returning None are skipped; the first non-None result wins."""
    order = []

    def first():
        order.append("first")
        return None

    def second():
        order.append("second")
        return _CREDS

    def third():
        order.append("third")
        return None

    creds = resolve_credentials(providers=[first, second, third])
    creds.get()
    assert order == ["first", "second"]


def test_chain_raises_when_all_providers_return_none():
    """If every provider returns None a RuntimeError is raised."""
    rc = resolve_credentials(providers=[lambda: None, lambda: None])
    with pytest.raises(SigV4Error, match="No AWS credentials found"):
        rc.get()


def test_chain_propagates_provider_exception():
    """A provider that raises must not be silently swallowed by the chain."""

    def broken():
        raise ValueError("config file is malformed")

    rc = resolve_credentials(providers=[broken])
    with pytest.raises(ValueError, match="config file is malformed"):
        rc.get()


def test_chain_does_not_continue_after_exception():
    """Once a provider raises, subsequent providers must not be called."""
    called = []

    def broken():
        raise SigV4Error("broken provider")

    def should_not_be_called():
        called.append(True)
        return _CREDS

    rc = resolve_credentials(providers=[broken, should_not_be_called])
    with pytest.raises(SigV4Error):
        rc.get()

    assert called == [], "provider after a raising provider must not be called"


def test_resolve_credentials_with_no_args_uses_default_chain(monkeypatch):
    """Calling resolve_credentials() with no arguments uses the default provider chain."""
    # Set env vars so the first provider (EnvProvider) succeeds immediately.
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "DEFAULT_AKID")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "default_secret")
    monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

    rc = resolve_credentials()  # no providers= argument -> hits the None branch
    creds = rc.get()
    assert creds.access_key == "DEFAULT_AKID"
