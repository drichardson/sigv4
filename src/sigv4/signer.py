# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
High-level Signer — credential resolution + auto-refresh + signing.

Most callers should use :class:`Signer` rather than calling
:func:`sigv4.sign_headers` directly.
"""

from datetime import datetime

from sigv4.credentials import (
    RefreshableCredentials,
)
from sigv4.resolve import resolve_credentials
from sigv4.signing import sign_headers


class Signer:
    """
    High-level helper that combines credential resolution, auto-refresh,
    and SigV4 signing.

    Example::

        signer = Signer(region="us-east-1", service="s3")

        # Pre-warm credentials at startup (optional but recommended for
        # latency-critical paths).
        signer.credentials.refresh()

        # Later, in your request handler:
        extra_headers = signer.sign(
            method="GET",
            url="https://s3.us-east-1.amazonaws.com/my-bucket?list-type=2",
            headers={"host": "s3.us-east-1.amazonaws.com"},
            body=b"",
        )
        # Merge extra_headers into your actual HTTP request headers.

    Args:
        region: AWS region name (e.g. ``"us-east-1"``).
        service: AWS service name (e.g. ``"s3"``, ``"execute-api"``).
        credentials: A :class:`~sigv4.credentials.RefreshableCredentials`
            instance. If omitted, credentials are resolved from the standard
            chain (env vars → IRSA → config file → container → IMDS).
    """

    def __init__(
        self,
        *,
        region: str,
        service: str,
        credentials: RefreshableCredentials | None = None,
    ) -> None:
        self._region = region
        self._service = service
        self._credentials = credentials or resolve_credentials()

    @property
    def credentials(self) -> RefreshableCredentials:
        """The underlying refreshable credentials instance."""
        return self._credentials

    def sign(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes = b"",
        timestamp: datetime | None = None,
    ) -> dict[str, str]:
        """
        Return headers required to authenticate this request.

        Credentials are refreshed automatically if they are approaching expiry.
        This method may block on the first call (or in the mandatory refresh
        window) while credentials are fetched.

        Args:
            method: HTTP method (``"GET"``, ``"POST"``, …).
            url: Full URL including scheme, host, path, and query string.
            headers: Request headers you intend to send. ``host`` is derived
                from *url* if absent.
            body: Raw request body. Pass ``b""`` for bodyless requests.
            timestamp: Override the signing time (useful in tests).

        Returns:
            A dict of headers to merge into your request:
            ``Authorization``, ``X-Amz-Date``, and optionally
            ``X-Amz-Security-Token``.
        """
        creds = self._credentials.get()
        return sign_headers(
            method=method,
            url=url,
            headers=headers or {},
            body=body,
            region=self._region,
            service=self._service,
            credentials=creds,
            timestamp=timestamp,
        )
