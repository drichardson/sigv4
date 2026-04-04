# Agents Guide

Read `DESIGN.md` first for the architecture, two-layer API, and credential chain.

## Development Commands

```sh
task test          # run tests with coverage (100% required)
task lint          # check formatting and lint
task format        # auto-format code
task typecheck     # run mypy type checker
task check-deps    # enforce zero Python package runtime dependencies
task check         # run all of the above
```

All tasks are defined in ``Taskfile.dist.yaml``. CI uses the same tasks.

Run ``task install-git-hooks`` once after cloning to install a pre-push hook
that runs ``task git-hook``. To change what the hook does, update the
``git-hook`` task — no need to reinstall.

## Conventions

- **Python 3.14+** — use modern syntax: `type` aliases, `match` statements.
- **Zero Python package dependencies** — stdlib only. Do not add any entries
  to the `[project] dependencies` list in `pyproject.toml`. This is a
  first-class design constraint (see `DESIGN.md`). CI enforces this via
  `scripts/check-no-runtime-deps.sh` and will fail if a dependency is added.
  Dev-only deps under `[dependency-groups]` (pytest, mypy, ruff) are fine.
- **Sync-only** — credential fetching uses `urllib.request`. The signing
  itself is pure computation with no I/O.
- **Structural typing** — prefer `Protocol` over inheritance for interfaces
  (see `CredentialProvider`).
- **Immutable credentials** — `Credentials` is a frozen dataclass. Create
  a new instance on each refresh; never mutate in place.
- **Thread safety** — `RefreshableCredentials` uses `threading.Lock`. All
  mutations to `_credentials` must be inside the lock.
- **SPDX headers** — all source files start with the SPDX copyright and
  license identifier comments.
- **No credential leakage** — see the Security section in ``DESIGN.md`` for
  the full rationale. The hard rules, all enforced by
  ``scripts/check-no-credential-leaks.py`` in CI (cannot be suppressed):

  - No ``print()`` anywhere in ``src/``
  - Raise only ``AWSv4SigError`` or its subclasses
  - Exception messages must be string literals only — no f-strings, no
    ``.format()``, no variable references, no concatenation
  - No ``raise ... from <exception>`` (use ``from None`` or omit the cause)
  - No ``import logging`` outside ``_log.py`` — use ``from aws_sigv4._log
    import warning`` and call ``warning("static message")`` only
  - ``warning()`` accepts only ``LiteralString`` — no variables, ever
  - No ``# type: ignore`` anywhere in ``src/``

- **No type suppressions** — ``# type: ignore`` is banned from all source
  files. If mypy reports an error, fix the code.
- **Docstrings** — use reStructuredText (RST) markup, which is the Python
  standard. Inline code uses double backticks: ````~/.aws/credentials````.
  Single backticks in RST mean a cross-reference, not inline code.

## When making changes always use Pull Requests

1. Create a branch
2. Push to a PR.

Don't push to main.
