#!/bin/bash
# Run linting checks for MattStash
#
# Usage: ./scripts/lint.sh [OPTIONS]
#   --fix    Auto-fix fixable issues
#
# Examples:
#   ./scripts/lint.sh          # Check only (CI-safe)
#   ./scripts/lint.sh --fix    # Check and auto-fix

set -e

cd "$(dirname "$0")/.."

FIX_FLAG=""
if [ "$1" = "--fix" ]; then
    FIX_FLAG="--fix"
    echo "=== Ruff check (with auto-fix) ==="
else
    echo "=== Ruff check ==="
fi

ruff check $FIX_FLAG src/ tests/

echo ""
echo "=== Ruff format check ==="
if [ "$1" = "--fix" ]; then
    ruff format src/ tests/
else
    ruff format --check src/ tests/
fi

echo ""
echo "All lint checks passed."
