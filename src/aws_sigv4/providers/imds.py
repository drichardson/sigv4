# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential provider: EC2 Instance Metadata Service (IMDSv2).

Uses the two-step IMDSv2 token-based protocol:
  1. PUT /latest/api/token → receive a session token (TTL 21600s = 6h)
  2. GET /latest/meta-data/iam/security-credentials/<role> with the token

On non-EC2 hosts, ``169.254.169.254`` is not routable and the connection is
refused or the address is unreachable immediately — these indicate IMDS is not
present and the provider returns ``None``.

A timeout means something is at that address but not responding promptly —
this is treated as an error (IMDS present but broken) and propagates.

Reference:
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
"""

import errno
import json
import logging
import urllib.error
import urllib.request
from aws_sigv4.credentials import Credentials, parse_utc_datetime

logger = logging.getLogger(__name__)

_IMDS_BASE = "http://169.254.169.254/latest"
_TOKEN_TTL_SECONDS = 21600  # 6 hours
_CONNECT_TIMEOUT = 1  # fail fast on non-EC2 hosts


def try_load_from_imds() -> Credentials | None:
    """
    Load credentials from the EC2 Instance Metadata Service (IMDSv2).

    Returns ``None`` if IMDS is not present (connection refused or address
    unreachable — indicates a non-EC2 host). Raises if IMDS appears to be
    present but is not responding correctly (timeout, HTTP error, etc.).
    """
    try:
        imds_token = _get_imds_token()
    except OSError as e:
        if _is_not_present(e):
            return None
        raise

    try:
        role_name = _get_role_name(imds_token)
    except (urllib.error.URLError, OSError) as e:
        logger.debug("IMDS: no IAM role attached to this instance: %s", e)
        return None

    return _get_role_credentials(imds_token, role_name)


def _is_not_present(exc: OSError) -> bool:
    """
    Return True if the exception indicates IMDS is simply not present on
    this host (connection refused, network unreachable, host unreachable).
    These are expected on non-EC2 hosts and should be treated as
    "provider not available" rather than an error.
    """
    not_present_errnos = {
        errno.ECONNREFUSED,  # connection refused — nothing listening
        errno.ENETUNREACH,  # network unreachable
        errno.EHOSTUNREACH,  # host unreachable
        getattr(errno, "ENONET", None),  # no route to host (Linux only)
    }
    not_present_errnos.discard(None)
    # urllib wraps socket errors in URLError; unwrap to get the errno.
    cause = exc.__cause__ if exc.__cause__ is not None else exc
    return getattr(cause, "errno", None) in not_present_errnos


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

    return Credentials(
        access_key=data["AccessKeyId"],
        secret_key=data["SecretAccessKey"],
        token=data.get("Token"),
        expires_at=parse_utc_datetime(expiration) if expiration else None,
    )
