# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Credential provider: environment variables.

Reads ``AWS_ACCESS_KEY_ID``, ``AWS_SECRET_ACCESS_KEY``, and optionally
``AWS_SESSION_TOKEN`` from the process environment.
"""

import os

from sigv4.credentials import Credentials


def try_load_from_env() -> Credentials | None:
    """Load credentials from environment variables."""
    access_key = os.environ.get("AWS_ACCESS_KEY_ID")
    secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")

    if not access_key or not secret_key:
        return None

    token = os.environ.get("AWS_SESSION_TOKEN") or os.environ.get("AWS_SECURITY_TOKEN")

    return Credentials(
        access_key=access_key,
        secret_key=secret_key,
        token=token or None,
    )
