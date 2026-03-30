# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

import textwrap
from pathlib import Path

import pytest

from aws_sigv4.providers.config_file import try_load_from_config_file


def _write(tmp_path: Path, filename: str, content: str) -> Path:
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content))
    return p


def test_returns_none_when_no_files(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "creds"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    assert try_load_from_config_file() is None


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

    creds = try_load_from_config_file()
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

    creds = try_load_from_config_file()
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

    creds = try_load_from_config_file()
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

    creds = try_load_from_config_file()
    assert creds is not None
    assert creds.access_key == "CONFIG_AKID"


def test_malformed_credentials_file_raises(tmp_path, monkeypatch):
    """A credentials file that exists but cannot be parsed must raise, not return None."""
    import configparser

    creds_file = tmp_path / "credentials"
    # A line without a section header is invalid INI — configparser raises
    # MissingSectionHeaderError (a subclass of configparser.Error).
    creds_file.write_text("aws_access_key_id = AKID\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    with pytest.raises(configparser.Error):
        try_load_from_config_file()


def test_malformed_config_file_raises(tmp_path, monkeypatch):
    """A config file that exists but cannot be parsed must raise, not return None."""
    import configparser

    config_file = tmp_path / "config"
    config_file.write_text("this is not valid ini = \n[broken\n")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config_file))
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    with pytest.raises(configparser.Error):
        try_load_from_config_file()


def test_missing_profile_returns_none(tmp_path, monkeypatch):
    """A valid file that doesn't contain the requested profile returns None."""
    creds_file = _write(
        tmp_path,
        "credentials",
        """
        [other-profile]
        aws_access_key_id = AKID
        aws_secret_access_key = secret
        """,
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_PROFILE", "nonexistent")

    assert try_load_from_config_file() is None


def test_section_missing_keys_returns_none(tmp_path, monkeypatch):
    """Section exists but is missing the key fields -- should return None."""
    creds_file = _write(
        tmp_path,
        "credentials",
        """
        [default]
        some_other_key = value
        """,
    )
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds_file))
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    assert try_load_from_config_file() is None
