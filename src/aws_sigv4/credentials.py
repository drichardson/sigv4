# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential types and the refreshable credential wrapper.
"""

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime

logger = logging.getLogger(__name__)

# How far before expiry to attempt an advisory (non-blocking) refresh.
_ADVISORY_REFRESH_SECONDS = 15 * 60  # 15 minutes

# How far before expiry to force a mandatory (blocking) refresh.
_MANDATORY_REFRESH_SECONDS = 10 * 60  # 10 minutes


@dataclass(frozen=True)
class Credentials:
    """
    Static AWS credentials. Immutable — create a new instance on refresh.

    For temporary credentials (STS, IRSA, ECS, IMDS), ``token`` and
    ``expires_at`` will be set. For long-lived IAM user credentials they
    will be ``None``.
    """

    access_key: str
    secret_key: str
    token: str | None = None
    expires_at: datetime | None = None  # timezone-aware UTC


type CredentialProvider = Callable[[], Credentials | None]
"""
A callable that returns :class:`Credentials` or ``None`` if credentials are
not available in the current environment (e.g. env vars not set).
"""


class CredentialsExpiredError(Exception):
    """Raised by :class:`RefreshableCredentials` when credentials have expired
    and no auto-refresh is configured."""


class RefreshableCredentials:
    """
    Wraps a :class:`CredentialProvider` with thread-safe, automatic refresh.

    Credentials are fetched lazily on the first call to :meth:`get`. After
    that, :meth:`get` returns cached credentials instantly unless they are
    approaching expiry, in which case a refresh is triggered:

    - **Advisory window** (15 min before expiry): one thread refreshes in the
      background; others continue with the still-valid cached credentials.
    - **Mandatory window** (10 min before expiry): all threads block until a
      fresh set of credentials is available.

    Call :meth:`refresh` explicitly to pre-warm credentials before entering a
    latency-critical path.
    """

    def __init__(self, provider: CredentialProvider) -> None:
        self._provider: CredentialProvider = provider
        self._credentials: Credentials | None = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_ready(self) -> bool:
        """True if credentials have been fetched at least once and are not expired."""
        creds = self._credentials
        if creds is None:
            return False
        if creds.expires_at is None:
            return True
        return datetime.now(UTC) < creds.expires_at

    @property
    def needs_refresh(self) -> bool:
        """True if credentials are in the advisory or mandatory refresh window."""
        creds = self._credentials
        if creds is None:
            return True
        if creds.expires_at is None:
            return False
        remaining = (creds.expires_at - datetime.now(UTC)).total_seconds()
        return remaining < _ADVISORY_REFRESH_SECONDS

    @property
    def expires_at(self) -> datetime | None:
        """Expiry time of the current credentials, or ``None`` if non-expiring."""
        creds = self._credentials
        return creds.expires_at if creds is not None else None

    def refresh(self) -> None:
        """
        Explicitly fetch fresh credentials from the provider. Blocks until
        complete. Safe to call from any thread — only one refresh runs at a time.
        """
        self._do_refresh()

    def get(self) -> Credentials:
        """
        Return current credentials, refreshing if necessary.

        - If not yet fetched: blocks and fetches.
        - If in mandatory refresh window: blocks until refreshed.
        - If in advisory window: attempts refresh; if it fails, returns the
          still-valid cached credentials (warning is logged).
        - Otherwise: returns cached credentials instantly.

        Raises:
            CredentialsExpiredError: if credentials are past expiry and the
                provider fails to return new ones.
        """
        creds = self._credentials

        if creds is None:
            # First fetch — always block.
            self._do_refresh()
            return self._credentials  # type: ignore[return-value]

        if creds.expires_at is None:
            # Long-lived credentials — never expire.
            return creds

        remaining = (creds.expires_at - datetime.now(UTC)).total_seconds()

        if remaining <= 0:
            # Hard expired — must refresh and propagate any error.
            self._do_refresh()
            return self._credentials  # type: ignore[return-value]

        if remaining < _MANDATORY_REFRESH_SECONDS:
            # Mandatory window — block all callers.
            self._do_refresh()
            return self._credentials  # type: ignore[return-value]

        if remaining < _ADVISORY_REFRESH_SECONDS:
            # Advisory window — try to refresh; swallow errors and use cached.
            try:
                self._do_refresh()
            except Exception:
                logger.warning(
                    "Advisory credential refresh failed; using cached credentials "
                    "(expires in %.0f seconds).",
                    remaining,
                    exc_info=True,
                )

        return self._credentials or creds  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _do_refresh(self) -> None:
        with self._lock:
            # Double-checked locking: another thread may have refreshed while
            # we were waiting for the lock.
            creds = self._credentials
            if creds is not None and creds.expires_at is not None:
                remaining = (creds.expires_at - datetime.now(UTC)).total_seconds()
                if remaining > _MANDATORY_REFRESH_SECONDS:
                    return

            new_creds = self._provider()
            if new_creds is None:
                raise CredentialsExpiredError(
                    "Credential provider returned None during refresh. "
                    "Check your AWS credentials configuration."
                )
            self._credentials = new_creds
