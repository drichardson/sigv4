# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""Tests for the internal logging module."""

import logging

from sigv4._log import warning


def test_warning_emits_to_sigv4_logger(caplog):
    """warning() must emit to the sigv4 logger at WARNING level."""
    with caplog.at_level(logging.WARNING, logger="sigv4"):
        warning("test warning message")

    assert len(caplog.records) == 1
    assert caplog.records[0].levelname == "WARNING"
    assert caplog.records[0].message == "test warning message"
    assert caplog.records[0].name == "sigv4"
