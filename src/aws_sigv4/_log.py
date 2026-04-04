# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
Internal logging — the only module in ``aws_sigv4`` permitted to call the
stdlib ``logging`` API.

All log output from this library goes through :func:`warning`. The function
signature accepts only a ``LiteralString`` so that mypy enforces at
type-check time that no variable data (which could contain credentials) is
ever logged. The AST-based security check
(``scripts/check-no-credential-leaks.py``) additionally verifies that:

- No other module under ``src/aws_sigv4/`` imports ``logging``
- No other module calls ``logging.*`` or ``logger.*`` directly
- Every call to :func:`warning` passes a string literal
- No ``# type: ignore`` comment suppresses the ``LiteralString`` constraint

Only ``warning`` level is exposed. Errors are communicated via exceptions;
debug/info output is not provided because it risks logging values that could
contain credential material.
"""

import logging
from typing import LiteralString

_logger = logging.getLogger("aws_sigv4")


def warning(message: LiteralString) -> None:
    """Emit a warning-level log message.

    Only ``LiteralString`` arguments are accepted — variable data must never
    be passed here.
    """
    _logger.warning(message)
