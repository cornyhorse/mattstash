#!/bin/bash
# Run MattStash test suites
#
# Usage: ./scripts/run-tests.sh [OPTIONS]
#   --app           Run main application tests (default if no args)
#   --server        Run server unit tests
#   --integration   Run integration tests (CLI ↔ Server, requires Docker)
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
            echo "  --integration   Run integration tests (CLI ↔ Server, requires Docker)"
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
echo "Installing package in development mode..."
pip install -e .

# Ensure pytest-cov is available
if ! pip list | grep -q pytest-cov; then
    echo "Installing pytest-cov..."
    pip install pytest-cov
fi

# Clear cache
echo "Clearing pytest cache..."
pytest --cache-clear

# Run app tests
if [ "$RUN_APP_TESTS" = true ]; then
    echo ""
    echo "========================================"
    echo "Running Application Tests"
    echo "========================================"
    pytest -v \
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
    
    # Ensure pytest and coverage are available
    pip install pytest pytest-cov httpx fastapi slowapi
    
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
    
    # Check Docker is available
    if ! command -v docker &> /dev/null; then
        echo "ERROR: docker not found. Integration tests require Docker."
        echo "Skipping integration tests..."
    elif ! command -v docker-compose &> /dev/null; then
        echo "ERROR: docker-compose not found. Integration tests require docker-compose."
        echo "Skipping integration tests..."
    else
        # Ensure httpx is available for server health checks
        pip install httpx
        
        pytest -v \
            --cov=src/mattstash/cli \
            --cov-report=term-missing \
            --cov-report=html:htmlcov/integration \
            tests/integration/test_cli_server_*.py
        
        echo ""
        echo "✓ Integration test coverage report: htmlcov/integration/index.html"
    fi
fi

echo ""
echo "========================================"
echo "Tests Completed!"
echo "========================================"
