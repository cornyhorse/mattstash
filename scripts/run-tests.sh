#!/bin/bash
# Install the package in development mode and run tests with coverage

set -e  # Exit on any error

# Change to the project root directory (parent of scripts directory)
cd "$(dirname "$0")/.."

echo "Installing package in development mode..."
pip install -e .

echo "Clearing pytest cache..."
pytest --cache-clear

echo "Running tests..."
# Try with coverage first, fall back to basic tests if coverage not available
if pip list | grep -q pytest-cov; then
    echo "Running tests with coverage..."
    pytest -v --cov=src/mattstash --cov-report=term-missing --cov-report=html tests/
else
    echo "pytest-cov not found, installing it..."
    pip install pytest-cov
    if [ $? -eq 0 ]; then
        echo "Running tests with coverage..."
        pytest -v --cov=src/mattstash --cov-report=term-missing --cov-report=html tests/
    else
        echo "Could not install pytest-cov, running tests without coverage..."
        pytest -v tests/
    fi
fi

echo "Tests completed!"
