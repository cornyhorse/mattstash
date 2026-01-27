#!/bin/bash
# Server test runner script

set -e

# Change to server directory
cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Run tests with coverage
python -m pytest tests/ \
    --cov=app \
    --cov-report=term-missing \
    --cov-report=html:htmlcov \
    "$@"
