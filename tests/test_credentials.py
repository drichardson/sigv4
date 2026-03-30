# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for RefreshableCredentials lifecycle."""

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from aws_sigv4.credentials import (
    Credentials,
    CredentialsExpiredError,
    RefreshableCredentials,
)


def _make_static_provider(creds: Credentials):
    return lambda: creds


def _make_expiring_creds(seconds_from_now: float) -> Credentials:
    return Credentials(
        access_key="AKI",
        secret_key="secret",
        token="token",
        expires_at=datetime.now(UTC) + timedelta(seconds=seconds_from_now),
    )


def _make_none_provider():
    return lambda: None


# ---------------------------------------------------------------------------
# Basic lifecycle
# ---------------------------------------------------------------------------


def test_not_ready_before_first_fetch():
    provider = _make_static_provider(Credentials(access_key="AKI", secret_key="secret"))
    rc = RefreshableCredentials(provider)
    assert not rc.is_ready


def test_ready_after_get():
    provider = _make_static_provider(Credentials(access_key="AKI", secret_key="secret"))
    rc = RefreshableCredentials(provider)
    rc.get()
    assert rc.is_ready


def test_get_returns_correct_credentials():
    creds = Credentials(access_key="AKID123", secret_key="mysecret")
    rc = RefreshableCredentials(_make_static_provider(creds))
    result = rc.get()
    assert result.access_key == "AKID123"
    assert result.secret_key == "mysecret"


def test_refresh_explicitly():
    creds = Credentials(access_key="AKI", secret_key="secret")
    rc = RefreshableCredentials(_make_static_provider(creds))
    rc.refresh()
    assert rc.is_ready


def test_expires_at_none_for_static_creds():
    creds = Credentials(access_key="AKI", secret_key="secret")
    rc = RefreshableCredentials(_make_static_provider(creds))
    rc.get()
    assert rc.expires_at is None


def test_expires_at_set_for_temporary_creds():
    creds = _make_expiring_creds(3600)
    rc = RefreshableCredentials(_make_static_provider(creds))
    rc.get()
    assert rc.expires_at is not None


def test_needs_refresh_true_before_first_fetch():
    rc = RefreshableCredentials(
        _make_static_provider(Credentials(access_key="A", secret_key="S"))
    )
    assert rc.needs_refresh


def test_needs_refresh_false_for_long_lived_creds():
    creds = Credentials(access_key="AKI", secret_key="secret")  # no expires_at
    rc = RefreshableCredentials(_make_static_provider(creds))
    rc.get()
    assert not rc.needs_refresh


def test_needs_refresh_true_in_advisory_window():
    creds = _make_expiring_creds(10 * 60 - 1)  # just inside mandatory window
    rc = RefreshableCredentials(_make_static_provider(creds))
    rc._credentials = creds  # bypass initial fetch
    assert rc.needs_refresh


def test_none_provider_raises_on_get():
    rc = RefreshableCredentials(_make_none_provider())
    with pytest.raises(CredentialsExpiredError):
        rc.get()


# ---------------------------------------------------------------------------
# Thread safety
# ---------------------------------------------------------------------------


def test_concurrent_gets_return_same_credentials():
    """Multiple threads calling get() concurrently should all succeed."""
    call_count = 0

    def counting_provider():
        nonlocal call_count
        call_count += 1
        time.sleep(0.01)  # simulate latency
        return Credentials(access_key="AKI", secret_key="secret")

    rc = RefreshableCredentials(counting_provider)
    results = []
    errors = []

    def worker():
        try:
            results.append(rc.get())
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(results) == 10
    # All threads should have gotten valid credentials.
    assert all(r.access_key == "AKI" for r in results)
