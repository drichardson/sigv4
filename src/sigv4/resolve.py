# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential chain resolution.
"""

from sigv4.credentials import (
    SigV4Error,
    CredentialProvider,
    RefreshableCredentials,
)
from sigv4.providers.config_file import try_load_from_config_file
from sigv4.providers.container import try_load_from_container
from sigv4.providers.env import try_load_from_env
from sigv4.providers.imds import try_load_from_imds
from sigv4.providers.web_identity import WebIdentityProvider

# Default provider chain — constructed once at module load time.
# Each provider function re-reads env vars and files on every call, so
# caching the list is safe and avoids repeated allocations.
_DEFAULT_PROVIDERS: list[CredentialProvider] = [
    try_load_from_env,
    WebIdentityProvider().try_load,
    try_load_from_config_file,
    try_load_from_container,
    try_load_from_imds,
]


def resolve_credentials(
    providers: list[CredentialProvider] | None = None,
) -> RefreshableCredentials:
    """
    Resolve AWS credentials from the standard provider chain.

    The chain is tried in order; the first provider that returns credentials
    wins.     Returns a :class:`~sigv4.credentials.RefreshableCredentials`
    that will automatically refresh before expiry.

    Default provider order:

    1. **Environment variables** — ``AWS_ACCESS_KEY_ID`` /
       ``AWS_SECRET_ACCESS_KEY`` / ``AWS_SESSION_TOKEN``
    2. **Web Identity / IRSA** — ``AWS_WEB_IDENTITY_TOKEN_FILE`` +
       ``AWS_ROLE_ARN`` → STS ``AssumeRoleWithWebIdentity``
    3. **Config file** — ``~/.aws/credentials`` and ``~/.aws/config``
    4. **Container** — ECS task role via
       ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`` /
       ``AWS_CONTAINER_CREDENTIALS_FULL_URI``
    5. **IMDS** — EC2 instance metadata service (IMDSv2)

    Args:
        providers: Override the provider list. Useful for testing or custom
            credential chains.

    Returns:
        A :class:`~sigv4.credentials.RefreshableCredentials` instance
        wrapping the first matching provider.

    Raises:
        SigV4Error: If no provider in the chain can supply credentials.
    """
    chain = _ChainProvider(providers if providers is not None else _DEFAULT_PROVIDERS)
    return RefreshableCredentials(chain)


class _ChainProvider:
    """Tries each provider in order, returning the first non-None result."""

    def __init__(self, providers: list[CredentialProvider]) -> None:
        self._providers = providers

    def __call__(self):
        for provider in self._providers:
            creds = provider()
            if creds is not None:
                return creds
        raise SigV4Error("No AWS credentials found")
