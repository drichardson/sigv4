# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential provider: EC2 Instance Metadata Service (IMDSv2).

Uses the two-step IMDSv2 token-based protocol:
  1. PUT /latest/api/token → receive a session token (TTL 21600s = 6h)
  2. GET /latest/meta-data/iam/security-credentials/<role> with the token

Only active when running on an EC2 instance. On non-EC2 hosts the PUT will
time out quickly (1-second timeout).

Reference:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
"""

import json
import logging
import urllib.error
import urllib.request
from datetime import UTC, datetime

from aws_sigv4.credentials import Credentials

logger = logging.getLogger(__name__)

_IMDS_BASE = "http://169.254.169.254/latest"
_TOKEN_TTL_SECONDS = 21600  # 6 hours
_CONNECT_TIMEOUT = 1  # fail fast on non-EC2 hosts


def load_from_imds() -> Credentials | None:
    """
    Load credentials from the EC2 Instance Metadata Service (IMDSv2).

    Only succeeds when running on an EC2 instance. Times out quickly
    (1 second) on other hosts so it doesn't slow down the credential chain.
    """
    try:
        imds_token = _get_imds_token()
    except urllib.error.URLError, OSError:
        # Not on EC2, or IMDS disabled — skip silently.
        return None

    try:
        role_name = _get_role_name(imds_token)
    except (urllib.error.URLError, OSError) as e:
        logger.debug("IMDS: no IAM role attached to this instance: %s", e)
        return None

    return _get_role_credentials(imds_token, role_name)


def _get_imds_token() -> str:
    """Obtain an IMDSv2 session token."""
    req = urllib.request.Request(
        f"{_IMDS_BASE}/api/token",
        method="PUT",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": str(_TOKEN_TTL_SECONDS)},
    )
    with urllib.request.urlopen(req, timeout=_CONNECT_TIMEOUT) as resp:
        return resp.read().decode().strip()


def _get_role_name(imds_token: str) -> str:
    """Return the name of the IAM role attached to this instance."""
    req = urllib.request.Request(
        f"{_IMDS_BASE}/meta-data/iam/security-credentials/",
        headers={"X-aws-ec2-metadata-token": imds_token},
    )
    with urllib.request.urlopen(req, timeout=_CONNECT_TIMEOUT) as resp:
        # Response is a newline-separated list; the first entry is the role name.
        return resp.read().decode().strip().splitlines()[0]


def _get_role_credentials(imds_token: str, role_name: str) -> Credentials:
    """Fetch temporary credentials for *role_name* from IMDS."""
    url = f"{_IMDS_BASE}/meta-data/iam/security-credentials/{role_name}"
    req = urllib.request.Request(
        url,
        headers={"X-aws-ec2-metadata-token": imds_token},
    )
    with urllib.request.urlopen(req, timeout=_CONNECT_TIMEOUT) as resp:
        data = json.loads(resp.read())

    if data.get("Code") != "Success":
        raise RuntimeError(
            f"IMDS returned non-success code for role {role_name!r}: {data}"
        )

    expiration = data.get("Expiration", "")
    expires_at: datetime | None = None
    if expiration:
        expires_at = datetime.fromisoformat(expiration.replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

    return Credentials(
        access_key=data["AccessKeyId"],
        secret_key=data["SecretAccessKey"],
        token=data.get("Token"),
        expires_at=expires_at,
    )
