# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the IMDS credential provider.

These tests cover the "not available vs broken" distinction:
- Connection refused / unreachable → provider not present → return None
- Timeout / HTTP error → provider present but broken → raise
"""

import errno
from unittest.mock import patch

import pytest

from aws_sigv4.providers.imds import _is_not_present, try_load_from_imds


# ---------------------------------------------------------------------------
# _is_not_present helper
# ---------------------------------------------------------------------------


def _oserror(err: int) -> OSError:
    """Create an OSError with a specific errno."""
    e = OSError(err, f"errno {err}")
    e.errno = err
    return e


def _urlwrapped(err: int) -> OSError:
    """Create an OSError whose cause has the errno (simulates urllib wrapping)."""
    import urllib.error

    inner = OSError(err, f"errno {err}")
    inner.errno = err
    outer = urllib.error.URLError(inner)
    outer.__cause__ = inner
    return outer


def test_connection_refused_is_not_present():
    assert _is_not_present(_oserror(errno.ECONNREFUSED))


def test_network_unreachable_is_not_present():
    assert _is_not_present(_oserror(errno.ENETUNREACH))


def test_host_unreachable_is_not_present():
    assert _is_not_present(_oserror(errno.EHOSTUNREACH))


def test_timeout_is_not_not_present():
    """A timeout means something is there but slow — should raise, not skip."""
    assert not _is_not_present(_oserror(errno.ETIMEDOUT))


def test_urlwrapped_connection_refused_is_not_present():
    """urllib wraps socket errors in URLError — we unwrap to check errno."""
    assert _is_not_present(_urlwrapped(errno.ECONNREFUSED))


# ---------------------------------------------------------------------------
# try_load_from_imds behaviour
# ---------------------------------------------------------------------------


def test_returns_none_when_connection_refused():
    """Connection refused → IMDS not present → return None."""
    err = OSError(errno.ECONNREFUSED, "Connection refused")
    err.errno = errno.ECONNREFUSED
    with patch("aws_sigv4.providers.imds._get_imds_token", side_effect=err):
        assert try_load_from_imds() is None


def test_returns_none_when_host_unreachable():
    """Host unreachable → IMDS not present → return None."""
    err = OSError(errno.EHOSTUNREACH, "No route to host")
    err.errno = errno.EHOSTUNREACH
    with patch("aws_sigv4.providers.imds._get_imds_token", side_effect=err):
        assert try_load_from_imds() is None


def test_raises_when_timeout():
    """Timeout → IMDS present but not responding → raise."""
    err = OSError(errno.ETIMEDOUT, "Timed out")
    err.errno = errno.ETIMEDOUT
    with patch("aws_sigv4.providers.imds._get_imds_token", side_effect=err):
        with pytest.raises(OSError):
            try_load_from_imds()
