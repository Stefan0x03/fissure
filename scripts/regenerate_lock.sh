#!/usr/bin/env bash
# Regenerate requirements-lock.txt with SHA256 hashes for all dependencies.
#
# SECURITY: This script creates a lock file that pins all direct and transitive
# Python dependencies to exact versions with integrity hashes. The lock file is
# used by GitHub Actions workflows with --require-hashes to prevent supply-chain
# attacks where a compromised package could exfiltrate credentials.
#
# Usage:
#   ./scripts/regenerate_lock.sh
#
# Prerequisites:
#   - Python 3.12+ (match the version used in workflows)
#   - pip-tools (installed automatically by this script in a temporary venv)
#
# After running:
#   1. Review the diff in requirements-lock.txt
#   2. Audit any new packages or major version changes
#   3. Commit both requirements.txt and requirements-lock.txt together

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$REPO_ROOT"

echo "==> Creating temporary virtual environment..."
VENV_DIR=$(mktemp -d)
trap "rm -rf $VENV_DIR" EXIT

python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

echo "==> Installing pip-tools..."
pip install --quiet --upgrade pip
pip install --quiet pip-tools

echo "==> Generating requirements-lock.txt with hashes..."
pip-compile \
  --generate-hashes \
  --allow-unsafe \
  --output-file requirements-lock.txt \
  requirements.txt

echo ""
echo "==> Lock file regenerated successfully!"
echo ""
echo "Next steps:"
echo "  1. Review the diff: git diff requirements-lock.txt"
echo "  2. Audit any new packages or major version changes"
echo "  3. Commit both files: git add requirements.txt requirements-lock.txt && git commit"
echo ""
echo "SECURITY: The lock file pins all transitive dependencies. If you see unexpected"
echo "packages or suspicious version changes, investigate before committing."
