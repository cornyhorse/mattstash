# MattStash Test Suite

## Overview

MattStash has three types of tests:
1. **Application Tests** - Unit tests for the core library and CLI (local mode)
2. **Server Tests** - Unit tests for the FastAPI server
3. **Integration Tests** - End-to-end tests for CLI-to-server communication

## Running Tests

### Quick Start

```bash
# Run application tests only (default)
./scripts/run-tests.sh

# Run all tests
./scripts/run-tests.sh --all

# Run specific test suites
./scripts/run-tests.sh --app          # Application tests
./scripts/run-tests.sh --server       # Server tests
./scripts/run-tests.sh --integration  # Integration tests (real CLI against a real server subprocess; no Docker)

# Combine test suites
./scripts/run-tests.sh --app --server
```

### Individual Test Suites

#### Application Tests
Tests for the core MattStash library and CLI in local mode (direct KeePass access).

```bash
./scripts/run-tests.sh --app
```

- **Location**: `tests/`
- **Coverage Target**: 90%+
- **Dependencies**: pytest, pytest-cov, pykeepass
- **What's Tested**:
  - Core credential store operations
  - Version management
  - Database URL builders
  - S3 client builders
  - CLI handlers (local mode)
  - Module-level convenience functions

#### Server Tests
Tests for the FastAPI server component.

```bash
./scripts/run-tests.sh --server
```

- **Location**: `server/tests/`
- **Coverage Target**: 90%+
- **Dependencies**: pytest, pytest-cov, httpx, fastapi, slowapi
- **What's Tested**:
  - API endpoints (credentials, db-url, health)
  - Authentication and API key validation
  - Request/response models
  - Middleware (logging, rate limiting)
  - Configuration management
  - Dependency injection

#### Integration Tests
End-to-end tests that start the real API server (`python -m app` from `server/`) as a subprocess on a free
localhost port, backed by a throw-away database, and run the real `mattstash` CLI against it.

```bash
./scripts/run-tests.sh --integration
```

- **Location**: `tests/integration/test_cli_server_*.py`
- **Coverage Target**: 80%+
- **Dependencies**: the server's dependencies (`pip install -r server/requirements.lock`), pytest, httpx
- **What's Tested**:
  - CLI commands in server mode (--server-url)
  - CLI-to-server communication
  - Authentication with API keys
  - Complete workflows (put, get, list, delete, versions)
  - Error handling and edge cases

**Note**: No Docker is needed. The tests skip themselves only when the server's own dependencies (fastapi, uvicorn,
slowapi) are not installed.

## Test Structure

```
tests/
├── README.md                        # This file
├── integration/                     # Integration tests
│   ├── conftest.py                  # Server subprocess + CLI fixtures
│   ├── test_cli_server_get.py       # CLI get command tests
│   ├── test_cli_server_put.py       # CLI put command tests
│   ├── test_cli_server_list.py      # CLI list/keys tests
│   ├── test_cli_server_delete.py    # CLI delete/versions tests
│   ├── test_cli_workflows.py        # Existing workflow tests
│   └── test_end_to_end.py           # Existing E2E tests
├── test_*.py                        # Application unit tests
└── ...

server/tests/
├── conftest.py                      # Server test fixtures
├── test_config.py                   # Configuration tests
├── test_api_keys.py                 # API key validation tests
├── test_middleware_logging.py       # Logging middleware tests
├── test_models.py                   # Pydantic models tests
├── test_router_health.py            # Health endpoint tests
├── test_router_helpers.py           # Router helper function tests
└── ...
```

## Coverage Reports

After running tests, coverage reports are generated in HTML format:

- **Application**: `htmlcov/app/index.html`
- **Server**: `server/htmlcov/index.html`
- **Integration**: `htmlcov/integration/index.html`

Open these files in a browser to see detailed line-by-line coverage.

## Writing Tests

### Application Tests

Use the existing test structure in `tests/`. Mock external dependencies (KeePass database, AWS services).

```python
def test_my_feature(tmp_path):
    """Test description."""
    # Use tmp_path for temporary files
    db_path = tmp_path / "test.kdbx"
    # ... test logic
```

### Server Tests

Use FastAPI's `TestClient` to test endpoints without starting the server.

```python
def test_my_endpoint(test_client, auth_headers):
    """Test API endpoint."""
    response = test_client.get("/api/v1/endpoint", headers=auth_headers)
    assert response.status_code == 200
```

### Integration Tests

Use the `run_mattstash_cli` fixture to execute CLI commands against a running server.

```python
def test_my_workflow(run_mattstash_cli, cli_env):
    """Test complete workflow."""
    result = run_mattstash_cli(["get", "my-secret"], cli_env)
    assert result.returncode == 0
```

## Continuous Integration

When running in CI environments:

```bash
# Fast tests only (skip integration)
./scripts/run-tests.sh --app --server

# Full test suite
./scripts/run-tests.sh --all
```

## Troubleshooting

### Integration Tests Fail to Start Server
- Ensure the server dependencies are installed: `pip install -r server/requirements.lock`
- The server runs on a free localhost port; its output is shown in the failure report

### Import Errors in Server Tests
- Ensure you're in the correct virtual environment
- Install server dependencies: `cd server && pip install -r requirements-dev.txt`

### Coverage Below Target
- Check `htmlcov/index.html` for uncovered lines
- Add tests for edge cases and error conditions
- Mock external dependencies to test error paths

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [FastAPI testing guide](https://fastapi.tiangolo.com/tutorial/testing/)
