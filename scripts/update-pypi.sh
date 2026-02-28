#!/bin/bash
set -euo pipefail

# MattStash PyPI publish script
# Usage: ./scripts/update-pypi.sh [--test]
#
# Options:
#   --test    Upload to TestPyPI instead of PyPI
#
# Prerequisites:
#   pip install build twine
#
# Authentication:
#   Set TWINE_USERNAME=__token__ and TWINE_PASSWORD=<your-pypi-api-token>
#   Or configure ~/.pypirc

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Parse args
REPO_FLAG=""
if [[ "${1:-}" == "--test" ]]; then
    REPO_FLAG="--repository testpypi"
    echo "==> Uploading to TestPyPI"
else
    echo "==> Uploading to PyPI"
fi

# Extract version from pyproject.toml
VERSION=$(python -c "
import re
with open('pyproject.toml') as f:
    m = re.search(r'version\s*=\s*\"([^\"]+)\"', f.read())
    print(m.group(1) if m else 'unknown')
")
echo "==> Version: $VERSION"

# Preflight checks
echo "==> Running tests..."
python -m pytest tests/ --ignore=tests/integration -q || {
    echo "ERROR: Tests failed. Aborting release."
    exit 1
}

echo "==> Running mypy..."
python -m mypy src/mattstash/ --strict || {
    echo "ERROR: Type checking failed. Aborting release."
    exit 1
}

# Clean previous builds
echo "==> Cleaning old artifacts..."
rm -rf dist/ build/ src/*.egg-info

# Build sdist + wheel
echo "==> Building..."
python -m build

# Verify the built artifacts
echo "==> Verifying..."
twine check dist/*

# Confirm
echo ""
echo "Ready to upload mattstash $VERSION"
read -r -p "Continue? [y/N] " confirm
if [[ "$confirm" != [yY] ]]; then
    echo "Aborted."
    exit 0
fi

# Upload
echo "==> Uploading..."
twine upload $REPO_FLAG dist/*

echo "==> Done! mattstash $VERSION published."
echo "    https://pypi.org/project/mattstash/$VERSION/"
