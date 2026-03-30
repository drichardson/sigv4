# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

import textwrap
from pathlib import Path


from aws_sigv4.providers.config_file import load_from_config_file


def _write(tmp_path: Path, filename: str, content: str) -> Path:
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content))
    return p


def test_returns_none_when_no_files(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "creds"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    assert load_from_config_file() is None


def test_reads_default_profile_from_credentials_file(tmp_path, monkeypatch):
    creds_file = _write(
        tmp_path,
        "credentials",
        """
        [default]
        aws_access_key_id = AKID
        aws_secret_access_key = secret
        """,
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    creds = load_from_config_file()
    assert creds is not None
    assert creds.access_key == "AKID"
    assert creds.secret_key == "secret"
    assert creds.token is None


def test_reads_named_profile(tmp_path, monkeypatch):
    creds_file = _write(
        tmp_path,
        "credentials",
        """
        [default]
        aws_access_key_id = DEFAULT_AKID
        aws_secret_access_key = default_secret

        [myprofile]
        aws_access_key_id = PROFILE_AKID
        aws_secret_access_key = profile_secret
        """,
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_PROFILE", "myprofile")

    creds = load_from_config_file()
    assert creds is not None
    assert creds.access_key == "PROFILE_AKID"


def test_reads_session_token(tmp_path, monkeypatch):
    creds_file = _write(
        tmp_path,
        "credentials",
        """
        [default]
        aws_access_key_id = AKID
        aws_secret_access_key = secret
        aws_session_token = mytoken
        """,
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    creds = load_from_config_file()
    assert creds is not None
    assert creds.token == "mytoken"


def test_falls_back_to_config_file(tmp_path, monkeypatch):
    config_file = _write(
        tmp_path,
        "config",
        """
        [default]
        aws_access_key_id = CONFIG_AKID
        aws_secret_access_key = config_secret
        """,
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config_file))
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    creds = load_from_config_file()
    assert creds is not None
    assert creds.access_key == "CONFIG_AKID"
