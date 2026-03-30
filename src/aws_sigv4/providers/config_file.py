# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential provider: shared credentials and config files.

Reads ``~/.aws/credentials`` and ``~/.aws/config`` (or paths from
``AWS_SHARED_CREDENTIALS_FILE`` / ``AWS_CONFIG_FILE``). The profile is
taken from ``AWS_PROFILE`` (defaulting to ``"default"``).
"""

import configparser
import os
from pathlib import Path

from aws_sigv4.credentials import Credentials


def load_from_config_file() -> Credentials | None:
    """
    Load credentials from ``~/.aws/credentials`` and ``~/.aws/config``.

    Checks credentials file first (profile section), then config file
    (``[profile <name>]`` section for non-default profiles).
    """
    profile = os.environ.get("AWS_PROFILE", "default")

    creds_file = Path(
        os.environ.get("AWS_SHARED_CREDENTIALS_FILE", "~/.aws/credentials")
    ).expanduser()
    config_file = Path(os.environ.get("AWS_CONFIG_FILE", "~/.aws/config")).expanduser()

    # Try credentials file (sections are bare profile names).
    creds = _read_credentials_from_file(creds_file, profile)
    if creds:
        return creds

    # Try config file (sections are "profile <name>", except "default").
    config_section = "default" if profile == "default" else f"profile {profile}"
    return _read_credentials_from_file(config_file, config_section)


def _read_credentials_from_file(path: Path, section: str) -> Credentials | None:
    if not path.exists():
        return None

    parser = configparser.ConfigParser()
    try:
        parser.read(path)
    except configparser.Error:
        return None

    if not parser.has_section(section):
        return None

    access_key = parser.get(section, "aws_access_key_id", fallback=None)
    secret_key = parser.get(section, "aws_secret_access_key", fallback=None)

    if not access_key or not secret_key:
        return None

    token = parser.get(section, "aws_session_token", fallback=None)

    return Credentials(
        access_key=access_key.strip(),
        secret_key=secret_key.strip(),
        token=token.strip() if token else None,
    )
