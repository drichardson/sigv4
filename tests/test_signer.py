# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the high-level Signer class."""

from datetime import UTC, datetime


from sigv4 import Credentials, RefreshableCredentials, Signer


def _static_refreshable(creds: Credentials) -> RefreshableCredentials:
    return RefreshableCredentials(lambda: creds)


_CREDS = Credentials(
    access_key="AKIDEXAMPLE", secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
)
_TIMESTAMP = datetime(2015, 8, 30, 12, 36, 0, tzinfo=UTC)


def test_sign_returns_authorization_header():
    signer = Signer(
        region="us-east-1",
        service="s3",
        credentials=_static_refreshable(_CREDS),
    )
    headers = signer.sign(
        method="GET",
        url="https://s3.us-east-1.amazonaws.com/my-bucket",
        timestamp=_TIMESTAMP,
    )
    assert "Authorization" in headers
    assert "AWS4-HMAC-SHA256" in headers["Authorization"]
    assert "X-Amz-Date" in headers


def test_sign_no_security_token_for_static_creds():
    signer = Signer(
        region="us-east-1",
        service="s3",
        credentials=_static_refreshable(_CREDS),
    )
    headers = signer.sign(
        method="GET", url="https://s3.us-east-1.amazonaws.com/", timestamp=_TIMESTAMP
    )
    assert "X-Amz-Security-Token" not in headers


def test_sign_includes_security_token():
    creds = Credentials(access_key="AKID", secret_key="secret", token="mytoken")
    signer = Signer(
        region="us-east-1",
        service="s3",
        credentials=_static_refreshable(creds),
    )
    headers = signer.sign(
        method="GET", url="https://s3.us-east-1.amazonaws.com/", timestamp=_TIMESTAMP
    )
    assert headers.get("X-Amz-Security-Token") == "mytoken"


def test_credentials_property():
    rc = _static_refreshable(_CREDS)
    signer = Signer(region="us-east-1", service="s3", credentials=rc)
    assert signer.credentials is rc


def test_deterministic_output():
    signer = Signer(
        region="us-east-1",
        service="s3",
        credentials=_static_refreshable(_CREDS),
    )
    kwargs = dict(method="GET", url="https://s3.amazonaws.com/", timestamp=_TIMESTAMP)
    assert signer.sign(**kwargs) == signer.sign(**kwargs)
