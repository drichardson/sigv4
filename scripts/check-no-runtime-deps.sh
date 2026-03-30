#!/usr/bin/env bash
# Enforce the zero Python package dependencies design goal.
#
# Reads pyproject.toml and fails if any runtime dependencies are declared
# under [project] dependencies. Dev dependencies under [dependency-groups]
# are explicitly allowed.
#
# See DESIGN.md — "Zero Python package dependencies" is a first-class
# design constraint for this library.

set -euo pipefail

PYPROJECT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/pyproject.toml"

# Extract the [project] dependencies list using Python (already available
# since this runs inside a uv environment).
DEPS=$(python3 - <<EOF
import tomllib, sys
with open("${PYPROJECT}", "rb") as f:
    data = tomllib.load(f)
deps = data.get("project", {}).get("dependencies", [])
for d in deps:
    print(d)
EOF
)

if [ -n "${DEPS}" ]; then
    echo "ERROR: Runtime dependencies found in pyproject.toml."
    echo ""
    echo "aws-sigv4 must have zero Python package dependencies (stdlib only)."
    echo "See DESIGN.md for the rationale."
    echo ""
    echo "Offending entries:"
    echo "${DEPS}" | sed 's/^/  /'
    exit 1
fi

echo "OK: no runtime dependencies declared."
