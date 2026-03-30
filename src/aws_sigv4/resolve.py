# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential chain resolution.
"""

import logging

from aws_sigv4.credentials import CredentialProvider, RefreshableCredentials
from aws_sigv4.providers.env import load_from_env
from aws_sigv4.providers.web_identity import WebIdentityProvider
from aws_sigv4.providers.config_file import load_from_config_file
from aws_sigv4.providers.container import load_from_container
from aws_sigv4.providers.imds import load_from_imds

logger = logging.getLogger(__name__)


def resolve_credentials(
    providers: list[CredentialProvider] | None = None,
) -> RefreshableCredentials:
    """
    Resolve AWS credentials from the standard provider chain.

    The chain is tried in order; the first provider that returns credentials
    wins. Returns a :class:`~aws_sigv4.credentials.RefreshableCredentials`
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
        A :class:`~aws_sigv4.credentials.RefreshableCredentials` instance
        wrapping the first matching provider.

    Raises:
        RuntimeError: If no provider in the chain can supply credentials.
    """
    if providers is None:
        providers = [
            load_from_env,
            WebIdentityProvider().load,
            load_from_config_file,
            load_from_container,
            load_from_imds,
        ]

    chain = _ChainProvider(providers)
    return RefreshableCredentials(chain)


class _ChainProvider:
    """Tries each provider in order, returning the first non-None result."""

    def __init__(self, providers: list[CredentialProvider]) -> None:
        self._providers = providers

    def __call__(self):
        for provider in self._providers:
            try:
                creds = provider()
            except Exception:
                logger.debug(
                    "Credential provider %s raised an exception; skipping.",
                    provider.__name__,
                    exc_info=True,
                )
                continue
            if creds is not None:
                logger.debug("Credentials resolved via %s.", provider.__name__)
                return creds
        raise RuntimeError(
            "No AWS credentials found. Tried: "
            + ", ".join(p.__name__ for p in self._providers)
            + ". Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or configure "
            "an IAM role via IRSA, ECS task role, or EC2 instance profile."
        )
