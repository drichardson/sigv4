# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
sigv4 — AWS Signature Version 4 signing with zero Python package dependencies.

Public API::

    from sigv4 import Credentials, sign_headers, Signer, resolve_credentials

Low-level (pure computation, no I/O)::

    headers = sign_headers(
        method="GET",
        url="https://s3.us-east-1.amazonaws.com/my-bucket",
        headers={"host": "s3.us-east-1.amazonaws.com"},
        body=b"",
        region="us-east-1",
        service="s3",
        credentials=Credentials(access_key="...", secret_key="..."),
    )

High-level (credential resolution + auto-refresh + signing)::

    signer = Signer(region="us-east-1", service="s3")
    signer.credentials.refresh()  # optional pre-warm
    headers = signer.sign(method="GET", url="https://s3.us-east-1.amazonaws.com/my-bucket")
"""

from sigv4.credentials import (
    SigV4Error,
    CredentialProvider,
    Credentials,
    CredentialsExpiredError,
    RefreshableCredentials,
)
from sigv4.resolve import resolve_credentials
from sigv4.signing import sign_headers
from sigv4.signer import Signer

__all__ = [
    "SigV4Error",
    "CredentialProvider",
    "Credentials",
    "CredentialsExpiredError",
    "RefreshableCredentials",
    "Signer",
    "resolve_credentials",
    "sign_headers",
]
