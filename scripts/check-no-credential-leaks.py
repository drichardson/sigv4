#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2025-present Doug Richardson <git@rekt.email>
# SPDX-License-Identifier: MIT

"""
AST-based security check: enforce credential leak prevention rules across
all source files under src/aws_sigv4/.

Rules enforced:
  1. No print() calls anywhere in src/
  2. No `import logging` or `from logging import ...` except in _log.py
  3. No direct logging.*() or logger.*() calls except in _log.py
  4. raise statements must use SigV4Error or CredentialsExpiredError —
     RuntimeError and bare Exception are banned
  5. Exception constructor arguments must be string literals only —
     no f-strings, no .format(), no concatenation, no variable references
  6. No `raise ... from <expr>` except `raise ... from None`
  7. warning() calls (from _log) must have exactly one argument and it must
     be a string literal
  8. No `# type: ignore` anywhere in src/ (prevents suppressing the
     LiteralString constraint and other mypy checks)

This script is intentionally not suppressible via # noqa or # type: ignore.
"""

import ast
import sys
from pathlib import Path

SRC_DIR = Path(__file__).parent.parent / "src" / "aws_sigv4"
LOG_MODULE = "_log.py"

# Exception classes permitted in raise statements.
ALLOWED_EXCEPTION_CLASSES = {"SigV4Error", "CredentialsExpiredError"}

errors: list[str] = []


def err(path: Path, line: int, msg: str) -> None:
    errors.append(f"{path.relative_to(SRC_DIR.parent.parent)}:{line}: {msg}")


def is_string_literal(node: ast.expr) -> bool:
    """Return True if node is a plain string constant (not an f-string)."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def check_file(path: Path) -> None:
    source = path.read_text(encoding="utf-8")
    is_log_module = path.name == LOG_MODULE

    tree = ast.parse(source, filename=str(path))

    # Rule 8: no `# type: ignore` anywhere in src/
    # Collect line ranges covered by string literals (docstrings etc.) so we
    # don't flag mentions of "# type: ignore" inside documentation.
    string_lines: set[int] = set()
    for ast_node in ast.walk(tree):
        if isinstance(ast_node, ast.Constant) and isinstance(ast_node.value, str):
            end = getattr(ast_node, "end_lineno", ast_node.lineno)
            for ln in range(ast_node.lineno, end + 1):
                string_lines.add(ln)

    for lineno, line in enumerate(source.splitlines(), start=1):
        if "# type: ignore" in line and lineno not in string_lines:
            err(
                path,
                lineno,
                "# type: ignore is banned from src/ — fix the type error instead",
            )

    for node in ast.walk(tree):
        # Rule 1: no print() calls
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "print"
        ):
            err(
                path,
                node.lineno,
                "print() is banned — use _log.warning() for diagnostics",
            )

        # Rules 2 & 3: no logging imports or calls outside _log.py
        if not is_log_module:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "logging" or alias.name.startswith("logging."):
                        err(
                            path,
                            node.lineno,
                            "import logging is banned — use aws_sigv4._log.warning()",
                        )

            if isinstance(node, ast.ImportFrom):
                if node.module == "logging" or (
                    node.module and node.module.startswith("logging.")
                ):
                    err(
                        path,
                        node.lineno,
                        "from logging import ... is banned — use aws_sigv4._log.warning()",
                    )

            if isinstance(node, ast.Call):
                # Catch logger.warning(...), logging.warning(...), etc.
                if isinstance(node.func, ast.Attribute):
                    if isinstance(node.func.value, ast.Name) and node.func.value.id in (
                        "logging",
                        "logger",
                        "_logger",
                    ):
                        err(
                            path,
                            node.lineno,
                            f"{node.func.value.id}.{node.func.attr}() is banned — use aws_sigv4._log.warning()",
                        )

        # Rule 4 & 5: raise statements
        if isinstance(node, ast.Raise) and node.exc is not None:
            exc = node.exc

            # Determine the exception class name and its single argument.
            if isinstance(exc, ast.Call):
                func = exc.func
                class_name = func.id if isinstance(func, ast.Name) else None

                # Rule 4: only allowed exception classes
                if (
                    class_name is not None
                    and class_name not in ALLOWED_EXCEPTION_CLASSES
                ):
                    err(
                        path,
                        node.lineno,
                        f"raise {class_name}() is banned — use SigV4Error or CredentialsExpiredError",
                    )

                # Rule 5: exception message must be a string literal
                if exc.args:
                    msg_arg = exc.args[0]
                    if not is_string_literal(msg_arg):
                        err(
                            path,
                            node.lineno,
                            "Exception message must be a string literal — "
                            "no f-strings, format(), concatenation, or variable references",
                        )
                    if len(exc.args) > 1:
                        err(
                            path,
                            node.lineno,
                            "Exception constructor must have exactly one argument",
                        )

            elif isinstance(exc, ast.Name):
                # bare `raise SomeException` without calling it — allowed for re-raise
                pass

        # Rule 6: no `raise ... from <expr>` except `raise ... from None`
        if isinstance(node, ast.Raise) and node.cause is not None:
            cause = node.cause
            is_none = isinstance(cause, ast.Constant) and cause.value is None
            if not is_none:
                err(
                    path,
                    node.lineno,
                    "raise ... from <exception> is banned — chained exceptions may contain "
                    "credential data in their __str__. Use `raise ... from None` or omit the cause.",
                )

        # Rule 7: warning() calls must have exactly one string literal argument
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "warning"
        ):
            if len(node.args) != 1 or not is_string_literal(node.args[0]):
                err(
                    path,
                    node.lineno,
                    "warning() must be called with exactly one string literal argument",
                )
            if node.keywords:
                err(
                    path,
                    node.lineno,
                    "warning() must not be called with keyword arguments",
                )


def main() -> int:
    py_files = sorted(SRC_DIR.rglob("*.py"))
    if not py_files:
        print(f"ERROR: no .py files found under {SRC_DIR}", file=sys.stderr)
        return 1

    for path in py_files:
        check_file(path)

    if errors:
        print("Security check failed:", file=sys.stderr)
        for e in errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    print(f"OK: security check passed ({len(py_files)} files checked).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
