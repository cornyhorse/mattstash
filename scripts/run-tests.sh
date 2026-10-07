#!/bin/bash
# Run MattStash test suites
#
# Usage: ./scripts/run-tests.sh [OPTIONS]
#   --app           Run main application tests (default if no args)
#   --server        Run server unit tests
#   --integration   Run integration tests (real CLI against a real server subprocess; no Docker)
#   --all           Run all test suites
#
# Examples:
#   ./scripts/run-tests.sh                    # Run app tests only (default)
#   ./scripts/run-tests.sh --all              # Run everything
#   ./scripts/run-tests.sh --app --server     # Run app and server tests
#   ./scripts/run-tests.sh --integration      # Run integration tests only

set -e  # Exit on any error

# Change to project root
cd "$(dirname "$0")/.."

# Parse arguments
RUN_APP_TESTS=false
RUN_SERVER_TESTS=false
RUN_INTEGRATION_TESTS=false

# Default: just app tests if no arguments
if [ $# -eq 0 ]; then
    RUN_APP_TESTS=true
fi

while [[ $# -gt 0 ]]; do
    case $1 in
        --app)
            RUN_APP_TESTS=true
            shift
            ;;
        --server)
            RUN_SERVER_TESTS=true
            shift
            ;;
        --integration)
            RUN_INTEGRATION_TESTS=true
            shift
            ;;
        --all)
            RUN_APP_TESTS=true
            RUN_SERVER_TESTS=true
            RUN_INTEGRATION_TESTS=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --app           Run main application tests (default if no args)"
            echo "  --server        Run server unit tests"
            echo "  --integration   Run integration tests (real CLI against a real server subprocess; no Docker)"
            echo "  --all           Run all test suites"
            echo ""
            echo "Examples:"
            echo "  $0                    # Run app tests only"
            echo "  $0 --all              # Run everything"
            echo "  $0 --app --server     # Run app and server tests"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Install dependencies
echo "Installing package in development mode (with test tooling: pytest, pytest-cov, pytest-xdist)..."
pip install -e ".[all,dev]"

# Clear caches without triggering test discovery for suites whose optional
# dependencies may not be installed yet.
echo "Clearing pytest cache..."
rm -rf .pytest_cache server/.pytest_cache

# Run app tests
if [ "$RUN_APP_TESTS" = true ]; then
    echo ""
    echo "========================================"
    echo "Running Application Tests"
    echo "========================================"
    pytest -v -n auto \
        --cov=src/mattstash \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/app \
        tests/ \
        --ignore=tests/integration/
    
    echo ""
    echo "✓ Application test coverage report: htmlcov/app/index.html"
fi

# Run server tests
if [ "$RUN_SERVER_TESTS" = true ]; then
    echo ""
    echo "========================================"
    echo "Running Server Tests"
    echo "========================================"
    
    # Change to server directory
    cd server
    
    # Install server test dependencies
    if [ -f "requirements-dev.txt" ]; then
        pip install -r requirements-dev.txt
    fi
    
    # The server's own dependencies (fastapi, uvicorn, slowapi, ...) at their locked versions, plus the test tools
    pip install -r requirements.lock
    pip install pytest pytest-cov httpx
    
    # Run server tests
    pytest -v \
        --cov=app \
        --cov-report=term-missing \
        --cov-report=html:htmlcov \
        tests/
    
    echo ""
    echo "✓ Server test coverage report: server/htmlcov/index.html"
    
    # Return to project root
    cd ..
fi

# Run integration tests
if [ "$RUN_INTEGRATION_TESTS" = true ]; then
    echo ""
    echo "========================================"
    echo "Running Integration Tests"
    echo "========================================"
    
    # The tests start the server themselves (python -m app on a free port), so it needs its dependencies.
    pip install -r server/requirements.lock

    pytest -v -n auto \
        --cov=src/mattstash/cli \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/integration \
        tests/integration/

    echo ""
    echo "✓ Integration test coverage report: htmlcov/integration/index.html"
fi

echo ""
echo "========================================"
echo "Tests Completed!"
echo "========================================"
