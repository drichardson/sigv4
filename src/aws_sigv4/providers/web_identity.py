# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential provider: Web Identity / IRSA (IAM Roles for Service Accounts).

Reads a projected service-account JWT from ``AWS_WEB_IDENTITY_TOKEN_FILE``
and exchanges it for temporary STS credentials via AssumeRoleWithWebIdentity.

This is the standard mechanism for EKS pods using IRSA. No AWS credentials
are needed to bootstrap — the signed JWT from Kubernetes is the proof of
identity.

Reference:
  https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html
"""

import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from aws_sigv4.credentials import Credentials, parse_utc_datetime

logger = logging.getLogger(__name__)

_STS_ENDPOINT = "https://sts.amazonaws.com/"
_STS_NS = "https://sts.amazonaws.com/doc/2011-06-15/"


class WebIdentityProvider:
    """
    Load credentials by exchanging a Kubernetes service-account token with STS.

    Environment variables consumed:
    - ``AWS_WEB_IDENTITY_TOKEN_FILE`` — path to the projected JWT token file
    - ``AWS_ROLE_ARN`` — the IAM role ARN to assume
    - ``AWS_ROLE_SESSION_NAME`` — optional session name (default: ``aws-sigv4``)
    - ``AWS_STS_REGIONAL_ENDPOINTS`` — if set to ``regional``, uses the
      regional STS endpoint derived from ``AWS_DEFAULT_REGION`` or
      ``AWS_REGION``
    """

    def __init__(
        self,
        *,
        token_file: str | None = None,
        role_arn: str | None = None,
        role_session_name: str | None = None,
        sts_endpoint: str | None = None,
    ) -> None:
        """
        Args:
            token_file: Path to the web identity token file. Defaults to
                ``AWS_WEB_IDENTITY_TOKEN_FILE``.
            role_arn: IAM role ARN to assume. Defaults to ``AWS_ROLE_ARN``.
            role_session_name: STS session name. Defaults to
                ``AWS_ROLE_SESSION_NAME`` or ``"aws-sigv4"``.
            sts_endpoint: Override the STS endpoint URL. Defaults to the
                global endpoint or regional if configured.
        """
        self._token_file = token_file
        self._role_arn = role_arn
        self._role_session_name = role_session_name
        self._sts_endpoint = sts_endpoint

    def try_load(self) -> Credentials | None:
        token_file = self._token_file or os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
        role_arn = self._role_arn or os.environ.get("AWS_ROLE_ARN")

        if not token_file or not role_arn:
            return None

        # Re-read the token file on every refresh — Kubernetes rotates it.
        try:
            with open(token_file) as f:
                web_identity_token = f.read().strip()
        except OSError as e:
            raise RuntimeError(
                f"Failed to read web identity token file {token_file!r}: {e}"
            ) from e

        session_name = (
            self._role_session_name
            or os.environ.get("AWS_ROLE_SESSION_NAME")
            or f"aws-sigv4-{int(time.time())}"
        )

        endpoint = self._sts_endpoint or _resolve_sts_endpoint()

        return _assume_role_with_web_identity(
            endpoint=endpoint,
            role_arn=role_arn,
            web_identity_token=web_identity_token,
            role_session_name=session_name,
        )


def _resolve_sts_endpoint() -> str:
    """Return the STS endpoint to use, honouring regional endpoint config."""
    regional = os.environ.get("AWS_STS_REGIONAL_ENDPOINTS", "").lower()
    if regional == "regional":
        region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION")
        if region:
            return f"https://sts.{region}.amazonaws.com/"
    return _STS_ENDPOINT


def _assume_role_with_web_identity(
    *,
    endpoint: str,
    role_arn: str,
    web_identity_token: str,
    role_session_name: str,
) -> Credentials:
    """Call STS AssumeRoleWithWebIdentity and return parsed credentials."""
    params = {
        "Action": "AssumeRoleWithWebIdentity",
        "Version": "2011-06-15",
        "RoleArn": role_arn,
        "WebIdentityToken": web_identity_token,
        "RoleSessionName": role_session_name,
    }
    body = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            xml_bytes = resp.read()
    except urllib.error.HTTPError as e:
        error_body = e.read().decode(errors="replace")
        raise RuntimeError(
            f"STS AssumeRoleWithWebIdentity failed ({e.code}): {error_body}"
        ) from e

    return _parse_sts_response(xml_bytes)


def _parse_sts_response(xml_bytes: bytes) -> Credentials:
    """Parse the STS XML response and return a Credentials instance."""
    root = ET.fromstring(xml_bytes)  # noqa: S314 — parsing trusted AWS response

    ns = {"sts": _STS_NS}

    def find(path: str) -> str:
        # Try with namespace prefix first, then without (for responses that
        # omit the xmlns declaration).
        for ns_map in (ns, {}):
            node = root.find(path, ns_map)
            if node is not None and node.text is not None:
                return node.text
        raise RuntimeError(
            f"Unexpected STS response — could not find {path!r} in:\n"
            + ET.tostring(root, encoding="unicode")
        )

    # XPath relative to document root (AssumeRoleWithWebIdentityResponse).
    access_key = find(
        "./sts:AssumeRoleWithWebIdentityResult/sts:Credentials/sts:AccessKeyId"
    )
    secret_key = find(
        "./sts:AssumeRoleWithWebIdentityResult/sts:Credentials/sts:SecretAccessKey"
    )
    token = find(
        "./sts:AssumeRoleWithWebIdentityResult/sts:Credentials/sts:SessionToken"
    )
    expiration_str = find(
        "./sts:AssumeRoleWithWebIdentityResult/sts:Credentials/sts:Expiration"
    )

    return Credentials(
        access_key=access_key,
        secret_key=secret_key,
        token=token,
        expires_at=parse_utc_datetime(expiration_str),
    )
