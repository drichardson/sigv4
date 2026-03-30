# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential provider: container credential endpoint.

Fetches temporary credentials from a local HTTP endpoint whose URI is injected
via environment variable. This mechanism is used by:

- ECS tasks — the ECS agent sets ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI``
  pointing to ``http://169.254.170.2/...``
  (https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html)

- EKS Pod Identity — the EKS Pod Identity Agent sets
  ``AWS_CONTAINER_CREDENTIALS_FULL_URI`` pointing to
  ``http://169.254.170.23/...``
  (https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html)

- Any compatible runtime that implements the same container credential
  provider protocol
  (https://docs.aws.amazon.com/sdkref/latest/guide/setting-global-aws_container_credentials_full_uri.html)
"""

import json
import logging
import os
import urllib.error
import urllib.request
from datetime import UTC, datetime

from aws_sigv4.credentials import Credentials

logger = logging.getLogger(__name__)


def load_from_container() -> Credentials | None:
    """
    Load credentials from the container credential endpoint.

    Reads one of:

    - ``AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`` — path relative to
      ``http://169.254.170.2``
    - ``AWS_CONTAINER_CREDENTIALS_FULL_URI`` — full URL (must be HTTPS or
      the link-local address)
    """
    relative_uri = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
    full_uri = os.environ.get("AWS_CONTAINER_CREDENTIALS_FULL_URI")

    if relative_uri:
        url = f"http://169.254.170.2{relative_uri}"
    elif full_uri:
        if not any(
            full_uri.startswith(p) for p in ("http://169.254.170.2", "https://")
        ):
            logger.warning(
                "AWS_CONTAINER_CREDENTIALS_FULL_URI %r is not an allowed "
                "prefix; skipping container credential provider.",
                full_uri,
            )
            return None
        url = full_uri
    else:
        return None

    auth_token = os.environ.get("AWS_CONTAINER_AUTHORIZATION_TOKEN")
    headers: dict[str, str] = {}
    if auth_token:
        headers["Authorization"] = auth_token

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        raise RuntimeError(
            f"Failed to fetch container credentials from {url!r}: {e}"
        ) from e

    return _parse_container_response(data)


def _parse_container_response(data: dict) -> Credentials:
    access_key = data.get("AccessKeyId") or data.get("access_key_id")
    secret_key = data.get("SecretAccessKey") or data.get("secret_access_key")
    token = data.get("Token") or data.get("token")
    expiration = data.get("Expiration") or data.get("expiration")

    if not access_key or not secret_key:
        raise RuntimeError(
            f"Container credentials response missing AccessKeyId/SecretAccessKey: {data}"
        )

    expires_at: datetime | None = None
    if expiration:
        expires_at = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

    return Credentials(
        access_key=access_key,
        secret_key=secret_key,
        token=token or None,
        expires_at=expires_at,
    )
