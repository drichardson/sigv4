# Agents Guide

Read `DESIGN.md` first for the architecture, two-layer API, and credential chain.

## Development Commands

```sh
task test          # run tests with coverage (100% required)
task test:lowest   # run tests against lowest direct dependencies
task lint          # check formatting and lint
task format        # auto-format code
task typecheck     # run mypy type checker
task check-deps    # enforce zero Python package runtime dependencies
task check         # run all of the above
```

All tasks are defined in ``Taskfile.dist.yaml``. CI uses the same tasks.

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
- **No credential leakage** — never include sensitive values (tokens, secret
  keys, passwords, full HTTP response bodies from credential endpoints) in log
  messages, exception messages, or ``__repr__``/``__str__`` output. When an
  error message needs context, include only safe metadata (e.g. key names,
  URLs, HTTP status codes) — never values.
- **Docstrings** — use reStructuredText (RST) markup, which is the Python
  standard. Inline code uses double backticks: ````~/.aws/credentials````.
  Single backticks in RST mean a cross-reference, not inline code.

## When making changes always use Pull Requests

1. Create a branch
2. Push to a PR.

Don't push to main.
