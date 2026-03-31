#!/usr/bin/env bash
# Sync the vendored AWS SigV4 test suite from botocore.
#
# If changes are found, creates a branch, commits the update, pushes, and
# opens a draft PR using the GitHub CLI (gh).
#
# Requirements: git, gh (GitHub CLI), bash >=4

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURES_DIR="${REPO_ROOT}/tests/data/aws4_testsuite"
UPSTREAM_COMMIT_FILE="${FIXTURES_DIR}/.upstream-commit"
UPSTREAM_REPO="https://github.com/boto/botocore.git"
UPSTREAM_PATH="tests/unit/auth/aws4_testsuite"
BRANCH_DATE="$(date +%Y-%m-%d)"
BRANCH_NAME="sync/aws-test-suite-${BRANCH_DATE}"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "Cloning upstream botocore (sparse, shallow)..."
git clone --depth=1 --filter=blob:none --sparse "${UPSTREAM_REPO}" "${TMP_DIR}/botocore" 2>&1
git -C "${TMP_DIR}/botocore" sparse-checkout set "${UPSTREAM_PATH}" 2>&1
git -C "${TMP_DIR}/botocore" checkout 2>&1

UPSTREAM_SHA="$(git -C "${TMP_DIR}/botocore" rev-parse HEAD)"
UPSTREAM_SRC="${TMP_DIR}/botocore/${UPSTREAM_PATH}"

echo "Upstream HEAD: ${UPSTREAM_SHA}"

# Preserve .upstream-commit and LICENSE/NOTICE from within the fixture dir when
# doing the diff — we only care about test case content changes.
if diff -r \
    --exclude=".upstream-commit" \
    "${UPSTREAM_SRC}" "${FIXTURES_DIR}" > /dev/null 2>&1; then
    echo "No changes detected. Test suite is up to date."
    exit 0
fi

echo "Changes detected — updating fixtures..."

# Replace the fixture directory contents with the upstream version.
# Keep the .upstream-commit file (we'll update it ourselves).
rm -rf "${FIXTURES_DIR:?}"/*
cp -r "${UPSTREAM_SRC}/." "${FIXTURES_DIR}/"
echo "${UPSTREAM_SHA}" > "${UPSTREAM_COMMIT_FILE}"

# Check if there's actually anything to commit (handles the edge case where
# diff detected whitespace/metadata changes that don't affect file content).
cd "${REPO_ROOT}"
if git diff --quiet && git diff --staged --quiet; then
    # Nothing changed after copy
    echo "No git-level changes after sync. Exiting."
    exit 0
fi

CURRENT_BRANCH="$(git rev-parse --abbrev-ref HEAD)"

# If we're already on the sync branch (e.g. re-running after a partial run),
# just update it; otherwise create a fresh branch from main/master/current.
if [ "${CURRENT_BRANCH}" != "${BRANCH_NAME}" ]; then
    git checkout -b "${BRANCH_NAME}"
fi

git add tests/data/aws4_testsuite/
git commit -m "chore: sync AWS SigV4 test suite from botocore

Upstream commit: ${UPSTREAM_SHA}
Source: ${UPSTREAM_REPO} (${UPSTREAM_PATH})
Sync date: ${BRANCH_DATE}"

git push -u origin "${BRANCH_NAME}"

echo "Creating draft PR..."
gh pr create \
    --draft \
    --title "chore: sync AWS SigV4 test suite (${BRANCH_DATE})" \
    --body "## Summary

Monthly automated sync of the vendored AWS SigV4 test suite from [botocore](${UPSTREAM_REPO}).

- **Source:** \`${UPSTREAM_PATH}\`
- **Upstream commit:** \`${UPSTREAM_SHA}\`
- **Sync date:** ${BRANCH_DATE}

## Changes

$(git diff HEAD~1 --stat)

## Testing

CI will run the parametrized test suite against the updated fixtures automatically.

## Other Considerations

Review the diff to ensure no unexpected test cases were removed or modified upstream." \
    --base main

echo "Done. Draft PR created."
