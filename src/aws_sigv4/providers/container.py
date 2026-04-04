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
import os
import urllib.error
import urllib.request

from aws_sigv4._log import warning
from aws_sigv4.credentials import SigV4Error, Credentials, parse_utc_datetime

# ECS link-local metadata host for relative URI credentials.
# https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html
_ECS_METADATA_HOST = "http://169.254.170.2"


def try_load_from_container() -> Credentials | None:
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
        url = f"{_ECS_METADATA_HOST}{relative_uri}"
    elif full_uri:
        if not any(
            full_uri.startswith(p)
            for p in (_ECS_METADATA_HOST, "http://127.0.0.1", "https://")
        ):
            warning(
                "AWS_CONTAINER_CREDENTIALS_FULL_URI must start with "
                "https:// or http://169.254.170.2"
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
            raw = resp.read()
    except urllib.error.URLError:
        raise SigV4Error("Failed to connect to container credentials endpoint")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise SigV4Error("Container credentials endpoint returned invalid JSON")

    return _parse_container_response(data)


def _parse_container_response(data: dict) -> Credentials:
    access_key = data.get("AccessKeyId") or data.get("access_key_id")
    secret_key = data.get("SecretAccessKey") or data.get("secret_access_key")
    token = data.get("Token") or data.get("token")
    expiration = data.get("Expiration") or data.get("expiration")

    match (access_key, secret_key):
        case (str(ak), str(sk)) if ak and sk:
            return Credentials(
                access_key=ak,
                secret_key=sk,
                token=token or None,
                expires_at=parse_utc_datetime(expiration) if expiration else None,
            )
        case (None | "", str()) | (str(), None | ""):
            if not access_key:
                raise SigV4Error("Container credentials response missing AccessKeyId")
            raise SigV4Error("Container credentials response missing SecretAccessKey")
        case _:
            raise SigV4Error(
                "Container credentials response missing AccessKeyId and SecretAccessKey"
            )
