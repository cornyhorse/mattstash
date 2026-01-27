# Phase 5: CLI-to-Server Integration & Comprehensive Testing

## Status: 🚧 NOT STARTED

**Dependencies**: 
- Phase 2 (Server Implementation) - ✅ Complete
- Phase 3 (Not Yet Complete) - ⚠️ In Progress
- Phase 4 (Server Test Coverage) - ⚠️ Not Started

**Note**: Phases 3 and 4 are not yet complete at time of writing. This plan may require updates based on changes made during those phases.

---

## Objective

Transform MattStash CLI from a local-only KeePass client into a network-capable client that can target either local databases OR the FastAPI server, implement comprehensive integration testing between CLI and server, ensure server has complete test coverage, and update test infrastructure.

---

## Overview

This phase bridges the gap between the standalone CLI/library (which operates on local KeePass files) and the server component (which provides network-accessible credential storage). After completion:

1. **CLI will support dual modes**: 
   - Local mode (default): Direct KeePass file access (current behavior)
   - Server mode: HTTP requests to MattStash API server
   
2. **Integration tests** will verify end-to-end functionality by:
   - Starting the server in a test container
   - Running CLI commands against it
   - Validating responses and behavior
   
3. **Server testing** will be comprehensive with unit and integration coverage

4. **Test infrastructure** will support running different test suites independently

---

## Task Breakdown

### Task 1: Add Server Mode to CLI
**Priority**: Critical  
**Estimated Effort**: 4-6 hours  
**Dependencies**: Phase 2 complete

#### Scope
Add command-line options to allow the CLI to target the MattStash API server instead of local KeePass databases.

#### Implementation Details

##### 1.1 Add Global CLI Options
Add to `src/mattstash/cli/main.py`:
```python
@click.group()
@click.option('--db', type=click.Path(), help='Path to KeePass database')
@click.option('--password', help='Database password')
@click.option('--server-url', envvar='MATTSTASH_SERVER_URL', 
              help='MattStash server URL (enables server mode)')
@click.option('--api-key', envvar='MATTSTASH_API_KEY',
              help='API key for server authentication')
@click.option('--verbose', is_flag=True, help='Enable verbose output')
@click.pass_context
def cli(ctx, db, password, server_url, api_key, verbose):
    """MattStash credential management CLI."""
    ctx.ensure_object(dict)
    ctx.obj['mode'] = 'server' if server_url else 'local'
    ctx.obj['server_url'] = server_url
    ctx.obj['api_key'] = api_key
    ctx.obj['db'] = db
    ctx.obj['password'] = password
    ctx.obj['verbose'] = verbose
```

##### 1.2 Create HTTP Client Module
New file: `src/mattstash/cli/http_client.py`
```python
"""HTTP client for communicating with MattStash API server."""

import requests
from typing import Optional, Dict, Any, List
from ..models.credential import Credential

class MattStashServerClient:
    """Client for MattStash API server."""
    
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.headers = {'X-API-Key': api_key}
    
    def get(self, title: str, show_password: bool = False, 
            version: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Get credential from server."""
        # Implementation
    
    def put(self, title: str, **kwargs) -> Dict[str, Any]:
        """Store credential on server."""
        # Implementation
    
    def delete(self, title: str) -> bool:
        """Delete credential from server."""
        # Implementation
    
    def list(self, show_password: bool = False) -> List[Dict[str, Any]]:
        """List all credentials from server."""
        # Implementation
    
    def versions(self, title: str) -> List[str]:
        """Get version history from server."""
        # Implementation
    
    def health_check(self) -> Dict[str, Any]:
        """Check server health."""
        # Implementation
```

##### 1.3 Update CLI Handlers
Modify all handlers in `src/mattstash/cli/handlers/` to:
1. Check `ctx.obj['mode']` to determine local vs server mode
2. Route to appropriate backend (MattStash instance or ServerClient)
3. Format responses consistently

Example for `get.py`:
```python
@click.pass_context
def get(ctx, title, show_password, json_output, version):
    """Get a credential."""
    if ctx.obj['mode'] == 'server':
        client = MattStashServerClient(ctx.obj['server_url'], ctx.obj['api_key'])
        result = client.get(title, show_password, version)
    else:
        stash = MattStash(path=ctx.obj['db'], password=ctx.obj['password'])
        result = stash.get(title, show_password=show_password, version=version)
    
    # Format and output result
    ...
```

##### 1.4 Environment Variable Support
Add support for:
- `MATTSTASH_SERVER_URL` - Server base URL
- `MATTSTASH_API_KEY` - API key for authentication
- `MATTSTASH_MODE` - Force 'local' or 'server' mode

##### 1.5 Error Handling
- Network errors (connection refused, timeout)
- Authentication errors (invalid API key)
- HTTP errors (404, 500, etc.)
- Fallback behavior documentation

#### Testing Strategy
- Unit tests for `MattStashServerClient` with mocked requests
- Mock server responses for each CLI handler
- Error case coverage (network failures, auth failures)

#### Files Modified
- `src/mattstash/cli/main.py` - Add global options
- `src/mattstash/cli/handlers/*.py` - Update all handlers
- `src/mattstash/cli/http_client.py` - New file

---

### Task 2: Update Documentation for Server Mode
**Priority**: High  
**Estimated Effort**: 2-3 hours  
**Dependencies**: Task 1

#### Scope
Update existing documentation to reflect that the server exists and CLI can target it, without duplicating server-specific documentation that already exists in `/server/README.md` and `/server/QUICKSTART.md`.

#### Files to Update

##### 2.1 Main README.md
Add section after "Quick Start":
```markdown
## Server Mode (Optional)

MattStash can also run as a network service for containerized environments. The CLI can target either local KeePass databases (default) or a remote MattStash server.

### Using CLI with Server

# Set server URL and API key
export MATTSTASH_SERVER_URL="http://localhost:8000"
export MATTSTASH_API_KEY="your-api-key"

# Now all commands use the server
mattstash get "api-token"
mattstash list

# Or specify inline
mattstash --server-url http://localhost:8000 --api-key "key" get "api-token"

For server setup and deployment, see [Server Documentation](server/README.md).
```

##### 2.2 docs/cli-reference.md
Add global options section at top:
```markdown
## Global Options

Available for all commands:

--db PATH                    # Path to KeePass database (local mode)
--password PASSWORD          # Database password (local mode)
--server-url URL            # MattStash server URL (enables server mode)
--api-key KEY               # API key for server authentication
--verbose                   # Enable verbose output

## Environment Variables

- `MATTSTASH_SERVER_URL` - Server URL (enables server mode)
- `MATTSTASH_API_KEY` - Server API key
- `KDBX_PASSWORD` - Database password (local mode)
```

##### 2.3 docs/configuration.md
Add "Server Mode" section:
```markdown
## Server Mode Configuration

The CLI can connect to a MattStash API server instead of local databases.

### Enabling Server Mode

# Via environment variables (recommended)
export MATTSTASH_SERVER_URL="http://mattstash:8000"
export MATTSTASH_API_KEY="your-api-key-here"

# Via command-line flags
mattstash --server-url http://mattstash:8000 --api-key "key" list

### Mode Detection

Server mode is enabled when `--server-url` is provided or `MATTSTASH_SERVER_URL` 
environment variable is set. When in server mode:
- Local database options (--db, --password) are ignored
- All operations are HTTP requests to the server
- Authentication via API key is required

### Server Setup

For information about deploying the MattStash server, see:
- [Server README](../server/README.md)
- [Server Quick Start](../server/QUICKSTART.md)
```

##### 2.4 docs/python-api.md
Add note about server availability:
```markdown
## Note on Server Mode

The Python API (`MattStash` class) operates on local KeePass databases only. 
For network-accessible credential storage, use the MattStash API server.

The server provides a REST API - see [Server API Documentation](../server/README.md#api-documentation).
```

#### Files Modified
- `README.md` - Add server mode section
- `docs/cli-reference.md` - Add global options, environment variables
- `docs/configuration.md` - Add server mode configuration
- `docs/python-api.md` - Add note about server vs local

---

### Task 3: Server Unit Tests
**Priority**: Critical  
**Estimated Effort**: 8-10 hours  
**Dependencies**: Phase 2 (Server Implementation)

#### Scope
Create comprehensive unit test suite for the MattStash FastAPI server located in `/server/app/`, targeting 90%+ code coverage.

**Note**: This overlaps with Phase 4 planning. If Phase 4 has been completed, skip this task. Otherwise, implement as described or merge with Phase 4 work.

#### Test Structure
```
server/
├── tests/
│   ├── __init__.py
│   ├── conftest.py                    # Shared fixtures
│   ├── test_main.py                   # App factory tests
│   ├── test_config.py                 # Configuration tests
│   ├── test_dependencies.py           # Dependency injection tests
│   ├── test_security_api_keys.py      # API key validation
│   ├── test_middleware_logging.py     # Logging middleware
│   ├── test_routers_credentials.py    # Credential endpoints
│   ├── test_routers_db_url.py         # DB URL endpoint
│   ├── test_routers_health.py         # Health check endpoint
│   └── test_models.py                 # Pydantic models
```

#### Key Testing Patterns

##### 3.1 Fixtures (conftest.py)
```python
import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch

@pytest.fixture
def mock_mattstash():
    """Mock MattStash instance."""
    with patch('mattstash.MattStash') as mock:
        instance = MagicMock()
        mock.return_value = instance
        yield instance

@pytest.fixture
def test_client(mock_mattstash):
    """FastAPI test client with mocked dependencies."""
    from app.main import create_app
    app = create_app()
    return TestClient(app)

@pytest.fixture
def valid_api_key():
    """Valid API key for tests."""
    return "test-api-key-12345"

@pytest.fixture
def auth_headers(valid_api_key):
    """Headers with valid authentication."""
    return {"X-API-Key": valid_api_key}
```

##### 3.2 Router Tests
Test each endpoint with:
- Valid requests
- Invalid authentication
- Missing parameters
- Error conditions
- Edge cases

##### 3.3 Coverage Goals
- `main.py`: 100% (app factory is critical)
- `config.py`: 100% (configuration must be tested)
- `dependencies.py`: 100% (dependency injection)
- `routers/*.py`: 95%+ (business logic)
- `middleware/*.py`: 90%+ (may have logging edge cases)
- `security/*.py`: 100% (security-critical)
- `models/*.py`: 80%+ (Pydantic models self-validate)

#### Test Requirements File
Create `server/requirements-test.txt`:
```
pytest>=7.0.0
pytest-cov>=4.0.0
pytest-asyncio>=0.21.0
httpx>=0.24.0  # For TestClient
```

#### Files Created
- `server/tests/conftest.py`
- `server/tests/test_*.py` (9 test files)
- `server/requirements-test.txt`

---

### Task 4: Integration Tests (CLI ↔ Server)
**Priority**: Critical  
**Estimated Effort**: 6-8 hours  
**Dependencies**: Tasks 1, 3

#### Scope
Create end-to-end integration tests that start the MattStash server (via Docker Compose) and run CLI commands against it to verify complete functionality.

#### Test Structure
```
tests/
├── integration/
│   ├── __init__.py
│   ├── conftest.py                # Docker Compose fixtures
│   ├── test_cli_server_get.py     # CLI get command via server
│   ├── test_cli_server_put.py     # CLI put command via server
│   ├── test_cli_server_list.py    # CLI list/keys via server
│   ├── test_cli_server_delete.py  # CLI delete via server
│   ├── test_cli_server_versions.py # CLI versions via server
│   └── test_cli_server_health.py  # Health check integration
```

#### Implementation Details

##### 4.1 Docker Compose Fixture
```python
# tests/integration/conftest.py
import pytest
import subprocess
import time
import requests
import os
from pathlib import Path

@pytest.fixture(scope="session")
def server_url():
    """Start server via docker-compose and return URL."""
    compose_file = Path(__file__).parent.parent.parent / "server" / "docker-compose.yml"
    
    # Start server
    subprocess.run(
        ["docker-compose", "-f", str(compose_file), "up", "-d"],
        check=True
    )
    
    # Wait for health check
    url = "http://localhost:8000"
    for _ in range(30):  # 30 second timeout
        try:
            resp = requests.get(f"{url}/health")
            if resp.status_code == 200:
                break
        except requests.exceptions.ConnectionError:
            pass
        time.sleep(1)
    else:
        raise RuntimeError("Server failed to start")
    
    yield url
    
    # Teardown
    subprocess.run(
        ["docker-compose", "-f", str(compose_file), "down"],
        check=True
    )

@pytest.fixture
def cli_env(server_url):
    """Environment variables for CLI in server mode."""
    return {
        "MATTSTASH_SERVER_URL": server_url,
        "MATTSTASH_API_KEY": "test-api-key",  # From docker-compose
        **os.environ
    }
```

##### 4.2 CLI Execution Helper
```python
import subprocess
from typing import List, Dict, Any

def run_cli(args: List[str], env: Dict[str, str]) -> subprocess.CompletedProcess:
    """Run mattstash CLI with given arguments."""
    cmd = ["mattstash"] + args
    return subprocess.run(
        cmd,
        env=env,
        capture_output=True,
        text=True
    )
```

##### 4.3 Test Examples
```python
def test_cli_put_and_get(cli_env):
    """Test storing and retrieving a credential via server."""
    # Put
    result = run_cli(["put", "test-secret", "--value", "test123"], cli_env)
    assert result.returncode == 0
    
    # Get
    result = run_cli(["get", "test-secret", "--show-password"], cli_env)
    assert result.returncode == 0
    assert "test123" in result.stdout

def test_cli_server_authentication_failure(server_url):
    """Test that invalid API key is rejected."""
    env = {
        "MATTSTASH_SERVER_URL": server_url,
        "MATTSTASH_API_KEY": "invalid-key",
        **os.environ
    }
    result = run_cli(["list"], env)
    assert result.returncode != 0
    assert "authentication" in result.stderr.lower()
```

##### 4.4 Test Data Setup
Create `tests/integration/test_data/` with:
- Pre-populated KeePass database for read tests
- Docker Compose override for test environment
- Test API keys file

#### Files Created
- `tests/integration/conftest.py`
- `tests/integration/test_cli_server_*.py` (6 test files)
- `tests/integration/test_data/` (test fixtures)
- `tests/integration/docker-compose.test.yml` (optional override)

---

### Task 5: Update Test Infrastructure
**Priority**: High  
**Estimated Effort**: 2-3 hours  
**Dependencies**: Tasks 3, 4

#### Scope
Update `scripts/run-tests.sh` to support running different test suites independently.

#### Implementation

##### 5.1 Updated Script
```bash
#!/bin/bash
# Run MattStash test suites

set -e  # Exit on any error

# Change to project root
cd "$(dirname "$0")/.."

# Parse arguments
RUN_APP_TESTS=false
RUN_SERVER_TESTS=false
RUN_INTEGRATION_TESTS=false
RUN_ALL=false

# Default: just app tests
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
            RUN_ALL=true
            RUN_APP_TESTS=true
            RUN_SERVER_TESTS=true
            RUN_INTEGRATION_TESTS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--app] [--server] [--integration] [--all]"
            echo ""
            echo "Options:"
            echo "  --app           Run main application tests (default if no args)"
            echo "  --server        Run server unit tests"
            echo "  --integration   Run integration tests (CLI ↔ Server)"
            echo "  --all           Run all test suites"
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
fi

# Run server tests
if [ "$RUN_SERVER_TESTS" = true ]; then
    echo ""
    echo "========================================"
    echo "Running Server Tests"
    echo "========================================"
    cd server
    pip install -r requirements-test.txt
    pytest -v \
        --cov=app \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/server \
        tests/
    cd ..
fi

# Run integration tests
if [ "$RUN_INTEGRATION_TESTS" = true ]; then
    echo ""
    echo "========================================"
    echo "Running Integration Tests"
    echo "========================================"
    
    # Check Docker is available
    if ! command -v docker-compose &> /dev/null; then
        echo "ERROR: docker-compose not found. Integration tests require Docker."
        exit 1
    fi
    
    pytest -v \
        --cov=src/mattstash.cli \
        --cov-report=term-missing \
        --cov-report=html:htmlcov/integration \
        tests/integration/
fi

echo ""
echo "========================================"
echo "Tests Completed!"
echo "========================================"

if [ "$RUN_APP_TESTS" = true ]; then
    echo "✓ Application tests: htmlcov/app/index.html"
fi
if [ "$RUN_SERVER_TESTS" = true ]; then
    echo "✓ Server tests: server/htmlcov/server/index.html"
fi
if [ "$RUN_INTEGRATION_TESTS" = true ]; then
    echo "✓ Integration tests: htmlcov/integration/index.html"
fi
```

##### 5.2 Documentation
Update script header comment and add README section:

Create `tests/README.md`:
```markdown
# MattStash Test Suite

## Running Tests

### All Tests (Default)
```bash
./scripts/run-tests.sh
```
Runs only the main application tests (backward compatible).

### Individual Test Suites
```bash
# Application tests only (default)
./scripts/run-tests.sh --app

# Server tests only
./scripts/run-tests.sh --server

# Integration tests only (requires Docker)
./scripts/run-tests.sh --integration

# Everything
./scripts/run-tests.sh --all
```

### Combined Suites
```bash
# App and server (no integration)
./scripts/run-tests.sh --app --server

# Server and integration
./scripts/run-tests.sh --server --integration
```

## Test Structure

- `tests/` - Main application tests (pytest)
  - Unit tests for CLI, core library, utilities
  - ~200 tests, 93% coverage
  
- `server/tests/` - Server unit tests (pytest + FastAPI TestClient)
  - Tests for FastAPI endpoints, middleware, security
  - Target: 90%+ coverage
  
- `tests/integration/` - Integration tests (pytest + Docker)
  - End-to-end CLI ↔ Server communication
  - Requires Docker Compose

## Coverage Reports

Coverage reports are generated in HTML format:
- Application: `htmlcov/app/index.html`
- Server: `server/htmlcov/server/index.html`
- Integration: `htmlcov/integration/index.html`
```

#### Files Modified
- `scripts/run-tests.sh` - Add argument parsing and suite selection
- `tests/README.md` - New file documenting test infrastructure

---

## Completion Criteria

### Task 1: CLI Server Mode
- [ ] CLI has `--server-url` and `--api-key` options
- [ ] `MattStashServerClient` implemented in `cli/http_client.py`
- [ ] All CLI handlers support both local and server modes
- [ ] Environment variables (`MATTSTASH_SERVER_URL`, `MATTSTASH_API_KEY`) work
- [ ] Unit tests for HTTP client with mocked requests
- [ ] Error handling for network and auth failures

### Task 2: Documentation Updates
- [ ] `README.md` mentions server mode with link to server docs
- [ ] `docs/cli-reference.md` documents global server options
- [ ] `docs/configuration.md` has server mode configuration section
- [ ] `docs/python-api.md` notes server vs local distinction
- [ ] No duplication of server-specific docs (reference `/server/` instead)

### Task 3: Server Unit Tests
- [ ] Server test structure created (`server/tests/`)
- [ ] All server modules have corresponding test files
- [ ] FastAPI TestClient used for endpoint testing
- [ ] MattStash dependencies mocked
- [ ] Coverage ≥90% for server codebase
- [ ] `server/requirements-test.txt` created

### Task 4: Integration Tests
- [ ] Integration test directory created (`tests/integration/`)
- [ ] Docker Compose fixture starts/stops server
- [ ] CLI commands execute against running server
- [ ] Tests cover: get, put, delete, list, versions, health
- [ ] Authentication failure cases tested
- [ ] Test data fixtures created

### Task 5: Test Infrastructure
- [ ] `scripts/run-tests.sh` accepts `--app`, `--server`, `--integration`, `--all` flags
- [ ] Default behavior (no args) runs app tests only (backward compatible)
- [ ] Separate coverage reports for each suite
- [ ] Docker availability checked before integration tests
- [ ] `tests/README.md` documents test structure and usage

---

## Open Questions

1. **Server Endpoint Coverage**: Should CLI support ALL server endpoints, or subset?
   - Current server has health, credentials, db-url, potentially s3-test
   - Decision: Start with core CRUD operations, add advanced features later

2. **Backward Compatibility**: Should `--db` and `--server-url` be mutually exclusive?
   - Decision needed on behavior when both are specified
   - Recommendation: `--server-url` takes precedence, log warning

3. **Python API Server Mode**: Should `MattStash` class support server mode?
   - Current plan: CLI only, Python API remains local-only
   - Alternative: Add `MattStashClient` class for server access
   - Decision: Defer to later phase, CLI is priority

4. **Integration Test Data**: How to populate server for testing?
   - Option A: Pre-populated KeePass database in Docker volume
   - Option B: Setup phase that uses CLI to populate
   - Recommendation: Option A for speed and reliability

5. **CI/CD Integration**: Should integration tests run in CI?
   - Requires Docker in CI environment
   - May slow down CI pipeline
   - Decision: Make optional, document setup

---

## Dependencies

### External Dependencies
- `requests` library (for HTTP client) - Add to `requirements.txt`
- Docker and Docker Compose (for integration tests)
- pytest-docker or similar (optional, for cleaner Docker fixtures)

### Internal Dependencies
- Server must be running and healthy for integration tests
- Server must have test API key configured
- Test KeePass database with known credentials

---

## Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Server not ready | Blocks integration tests | Phase 2 complete, low risk |
| Docker not available | Integration tests fail | Check Docker availability, graceful skip |
| Network flakiness | Intermittent test failures | Retry logic, generous timeouts |
| API changes | Tests break | Version pinning, API versioning |
| Test data conflicts | State pollution | Unique test databases per suite |

---

## Testing Strategy

### Unit Tests
- Mock all external dependencies (MattStash, requests)
- Fast execution (<5 seconds for entire suite)
- No network or file I/O

### Integration Tests
- Real server via Docker
- Real network calls
- Isolated test database
- Slower execution (~30-60 seconds including startup)

### Coverage Goals
- Application: Maintain 93% (current level)
- Server: Achieve 90%+
- Integration: 80%+ of CLI handlers in server mode

---

## Timeline Estimate

| Task | Hours | Dependencies |
|------|-------|--------------|
| 1. CLI Server Mode | 4-6 | Phase 2 |
| 2. Documentation Updates | 2-3 | Task 1 |
| 3. Server Unit Tests | 8-10 | Phase 2 |
| 4. Integration Tests | 6-8 | Tasks 1, 3 |
| 5. Test Infrastructure | 2-3 | Tasks 3, 4 |
| **Total** | **22-30 hours** | |

**Recommended order**: 3 → 1 → 4 → 5 → 2

Rationale:
1. Server tests first (can proceed independently)
2. CLI server mode (needed for integration)
3. Integration tests (validates CLI + server)
4. Test infrastructure (organizes everything)
5. Documentation last (captures final state)

---

## Notes for Next Agent

### Context Preservation
- This plan was created January 26, 2026
- Phases 3 and 4 may have progressed - check their status
- Server implementation is in `/server/app/`
- Main app tests are in `tests/` (not `src/mattstash/tests/`)

### Critical Decisions
- CLI server mode is CLI-only, Python API stays local
- Server tests use FastAPI TestClient with mocked MattStash
- Integration tests use real Docker Compose server
- Test script maintains backward compatibility (no args = app tests only)

### Phase 3/4 Coordination
If Phase 3 or 4 has made significant progress:
1. Review their changes first
2. Update this plan if conflicts exist
3. Avoid duplicating work (especially server tests)
4. Coordinate on test data and fixtures

### Quick Start for Implementation
1. Read `server/README.md` to understand server API
2. Check if `server/tests/` exists (Phase 4 may have started)
3. Start with Task 3 (server tests) - most independent
4. Implement Task 1 (CLI server mode) next
5. Task 4 (integration) requires both 1 and 3 complete

---

## Success Metrics

✅ **Phase Complete When:**
1. CLI can execute all commands against server with `--server-url` flag
2. All server code has ≥90% test coverage
3. Integration test suite passes with server running
4. `scripts/run-tests.sh --all` runs all three test suites successfully
5. Documentation updated to reference server mode (not duplicate server docs)
6. No regression in existing application test coverage (≥93%)

---

## Related Documentation

- [Server README](../../server/README.md) - Server deployment and API docs
- [Server Quick Start](../../server/QUICKSTART.md) - Server setup guide
- [Phase 2 Plan](plan_2.md) - Server implementation (completed)
- [Phase 4 Plan](plan_4.md) - Server test coverage (may be in progress)
- [Master Plan](plan.md) - Overall project roadmap
