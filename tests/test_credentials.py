# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for RefreshableCredentials lifecycle."""

import threading
import time
from datetime import UTC, datetime, timedelta

import pytest

from aws_sigv4.credentials import (
    SigV4Error,
    Credentials,
    CredentialsExpiredError,
    RefreshableCredentials,
    parse_utc_datetime,
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


def test_is_ready_false_when_credentials_expired():
    """is_ready must return False when credentials exist but are past expiry."""
    expired = _make_expiring_creds(-1)  # expired 1 second ago
    rc = RefreshableCredentials(_make_static_provider(expired))
    rc._credentials = expired
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


# ---------------------------------------------------------------------------
# Refresh window behaviour
# ---------------------------------------------------------------------------


def test_advisory_window_triggers_refresh():
    """Credentials in advisory window (10-15 min) should trigger a refresh."""
    refresh_count = 0
    old_creds = _make_expiring_creds(12 * 60)  # 12 min — inside advisory window
    new_creds = Credentials(access_key="NEW", secret_key="newsecret")

    def provider():
        nonlocal refresh_count
        refresh_count += 1
        return new_creds

    rc = RefreshableCredentials(provider)
    rc._credentials = old_creds  # bypass initial fetch, put in advisory window

    result = rc.get()
    assert refresh_count == 1
    assert result.access_key == "NEW"


def test_advisory_window_uses_cached_when_refresh_fails():
    """In advisory window, if refresh fails the still-valid cached creds are returned."""
    old_creds = _make_expiring_creds(12 * 60)  # in advisory window

    def failing_provider():
        raise RuntimeError("STS unavailable")

    rc = RefreshableCredentials(failing_provider)
    rc._credentials = old_creds

    # Should NOT raise — advisory window allows fallback to cached.
    result = rc.get()
    assert result is old_creds


def test_mandatory_window_blocks_until_refreshed():
    """Credentials in mandatory window (< 10 min) must block and refresh."""
    refresh_count = 0
    old_creds = _make_expiring_creds(8 * 60)  # 8 min — inside mandatory window
    new_creds = Credentials(access_key="FRESH", secret_key="fresher")

    def provider():
        nonlocal refresh_count
        refresh_count += 1
        return new_creds

    rc = RefreshableCredentials(provider)
    rc._credentials = old_creds

    result = rc.get()
    assert refresh_count == 1
    assert result.access_key == "FRESH"


def test_mandatory_window_raises_when_refresh_fails():
    """In mandatory window, if refresh fails the error must propagate."""
    old_creds = _make_expiring_creds(8 * 60)  # in mandatory window

    def failing_provider():
        raise RuntimeError("cannot refresh")

    rc = RefreshableCredentials(failing_provider)
    rc._credentials = old_creds

    with pytest.raises(RuntimeError, match="cannot refresh"):
        rc.get()


def test_hard_expired_forces_refresh():
    """Credentials past expiry must be refreshed regardless."""
    expired_creds = _make_expiring_creds(-60)  # expired 60s ago
    new_creds = Credentials(access_key="RENEWED", secret_key="renewed")

    rc = RefreshableCredentials(lambda: new_creds)
    rc._credentials = expired_creds

    result = rc.get()
    assert result.access_key == "RENEWED"


def test_no_refresh_when_credentials_are_fresh():
    """Credentials with > 15 min remaining must be returned without refresh."""
    refresh_count = 0
    fresh_creds = _make_expiring_creds(30 * 60)  # 30 min remaining

    def provider():
        nonlocal refresh_count
        refresh_count += 1
        return fresh_creds

    rc = RefreshableCredentials(provider)
    rc._credentials = fresh_creds  # pre-load

    rc.get()
    assert refresh_count == 0  # no refresh should have occurred


def test_double_checked_locking_skips_redundant_refresh():
    """If a concurrent refresh already brought creds outside the advisory window,
    _do_refresh must return early without calling the provider again."""
    refresh_count = 0

    def provider():
        nonlocal refresh_count
        refresh_count += 1
        # Return creds well outside the advisory window so the lock-holder
        # skips further refreshes.
        return Credentials(
            access_key="FRESH",
            secret_key="secret",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

    rc = RefreshableCredentials(provider)
    rc.refresh()  # first refresh
    assert refresh_count == 1

    # Second refresh: double-checked locking should detect creds are fresh
    # and return early without calling the provider.
    rc.refresh()
    assert refresh_count == 1


# ---------------------------------------------------------------------------
# parse_utc_datetime
# ---------------------------------------------------------------------------


def test_parse_utc_datetime_with_z_suffix():
    dt = parse_utc_datetime("2099-01-01T00:00:00Z")
    assert dt.tzinfo is not None
    assert dt.year == 2099


def test_parse_utc_datetime_with_offset():
    dt = parse_utc_datetime("2099-01-01T00:00:00+00:00")
    assert dt.tzinfo is not None


def test_parse_utc_datetime_naive_gets_utc():
    """A datetime string without timezone info must have UTC attached."""
    dt = parse_utc_datetime("2099-01-01T00:00:00")
    assert dt.tzinfo is not None
    assert dt.tzinfo == UTC


# ---------------------------------------------------------------------------
# Credentials redaction
# ---------------------------------------------------------------------------


def test_credentials_repr_does_not_leak_secret_key():
    """repr(Credentials) must never contain the secret key value."""
    creds = Credentials(access_key="AKID", secret_key="supersecret", token="mytoken")
    assert "supersecret" not in repr(creds)
    assert "mytoken" not in repr(creds)


def test_credentials_str_does_not_leak_secret_key():
    """str(Credentials) must never contain the secret key value."""
    creds = Credentials(access_key="AKID", secret_key="supersecret", token="mytoken")
    assert "supersecret" not in str(creds)
    assert "mytoken" not in str(creds)


def test_credentials_repr_is_fully_redacted():
    """repr(Credentials) must show redacted placeholders, not real values."""
    creds = Credentials(access_key="AKID", secret_key="supersecret")
    r = repr(creds)
    assert "***" in r


# ---------------------------------------------------------------------------
# SigV4Error
# ---------------------------------------------------------------------------


def test_credentials_expired_error_is_awsv4sig_error():
    """CredentialsExpiredError must be a subclass of SigV4Error."""
    assert issubclass(CredentialsExpiredError, SigV4Error)


def test_awsv4sig_error_message_preserved():
    """SigV4Error must preserve the literal message."""
    e = SigV4Error("something went wrong")
    assert str(e) == "something went wrong"
