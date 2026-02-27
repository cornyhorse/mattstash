# MattStash Master Plan

## Current Phase: ALL COMPLETE ✅
## Current Status: Project Complete

## Project Summary
MattStash is a KeePass-backed secrets accessor with CLI and Python API. This plan covers improvements to the existing codebase and expansion to include a FastAPI-based secrets service for Docker network deployment.

---

## Phases Overview

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 1 | [Code Quality & Security](plan_1.md) | ✅ Complete | Address security issues and code quality improvements |
| 2 | [FastAPI Secrets Service](plan_2.md) | ✅ Complete | Create HTTP API for Docker network deployment |
| 3 | [Documentation & Examples](plan_3.md) | ✅ Complete | Performance optimization, testing, config support |
| 4 | [Server Test Coverage](plan_4.md) | ✅ Complete | Comprehensive tests for server component (98% coverage) |
| 5 | [CLI-Server Integration & Testing](plan_5.md) | ✅ Complete | CLI server mode, integration tests, test infrastructure |

---

## Phase 1: Code Quality & Security Improvements

**Objective**: Address security vulnerabilities, bad practices, and suboptimal implementations identified during code review.

### Key Issues Identified
- Password source logging to stderr
- Global mutable state in module functions
- Inconsistent error handling (return None vs exceptions)
- Print statements instead of proper logging
- Missing input validation
- Excessive `# pragma: no cover` usage

### Priority Tasks
1. Fix password-related logging (security)
2. Add input validation and sanitize error messages
3. Replace print statements with logging framework
4. Establish consistent error handling patterns
5. Add complete type hints and docstrings

📄 **[Full Details: plan_1.md](plan_1.md)**

---

## Phase 2: FastAPI Secrets Service API

**Objective**: Create a secure REST API for accessing MattStash credentials from Docker containers.

### Architecture: Complete Separation
⚠️ The server lives in `/server` at the repository root and is **NOT** part of the pip package.
- Users who `pip install mattstash` get only the CLI/library
- Server is a separate application that depends on mattstash from PyPI
- Docker builds install `mattstash>=0.1.2` from PyPI

### Key Features
- Read-only API for credential access (Phase 2a)
- API key authentication with rate limiting
- Docker-native deployment with network isolation
- Audit logging for all credential access
- Optional write operations (Phase 2b)

### Endpoints
- `GET /health` - Health check
- `GET /credentials/{name}` - Get single credential
- `GET /credentials` - List credentials
- `GET /credentials/{name}/versions` - List versions
- `GET /db-url/{name}` - Get database connection URL

📄 **[Full Details: plan_2.md](plan_2.md)**

---

## Phase 4: Server Test Coverage

**Objective**: Create comprehensive test coverage for the FastAPI server component, targeting 90%+ coverage.

### Scope
- 15 Python files in `/server/app/`
- All API endpoints (health, credentials, db-url)
- Authentication and rate limiting
- Middleware and configuration

### Coverage Targets
| Component | Target |
|-----------|--------|
| Routers (credentials, db_url, health) | 100% |
| Security (api_keys) | 100% |
| Dependencies | 100% |
| Config | 100% |
| Middleware | 95% |
| Models | 85% |
| **Overall** | **90%+** |

### Pragma No Cover
Applied judiciously to:
- Print statements (startup/shutdown logging)
- Pydantic `Config` classes (documentation only)

📄 **[Full Details: plan_4.md](plan_4.md)**

---

## Phase 5: CLI-Server Integration & Comprehensive Testing

**Objective**: Enable CLI to target the MattStash API server, create integration tests between CLI and server, complete server test coverage, and update test infrastructure.

### Key Features
1. **CLI Server Mode**: Add `--server-url` and `--api-key` options to CLI
2. **HTTP Client**: New `MattStashServerClient` for server communication
3. **Integration Tests**: End-to-end tests with CLI ↔ Server via Docker
4. **Server Unit Tests**: Complete server test suite (90%+ coverage)
5. **Test Infrastructure**: Updated `scripts/run-tests.sh` with `--all`, `--server`, `--integration` flags

### Implementation Tasks
- Add global CLI options for server URL and API key
- Create HTTP client module for server communication
- Update all CLI handlers to support local and server modes
- Build comprehensive server unit test suite
- Create integration test suite with Docker Compose fixtures
- Update test script with flag-based suite selection

### Documentation Updates
- Update README.md to mention server mode
- Add server configuration to docs/configuration.md
- Update CLI reference with global server options
- Reference server docs without duplication

📄 **[Full Details: plan_5.md](plan_5.md)**

---

## Quick Links

- [Phase 1: Code Quality & Security](plan_1.md)
- [Phase 2: FastAPI Secrets Service](plan_2.md)
- [Phase 4: Server Test Coverage](plan_4.md)
- [Phase 5: CLI-Server Integration & Testing](plan_5.md)

---

## Session Log

| Date | Agent | Activity | Notes |
|------|-------|----------|-------|
| 2026-01-24 | Initial Review | Code review & planning | Created plan_1.md and plan_2.md |
| 2026-01-24 | Phase 1 | Security & quality fixes | Completed Phase 1 (logging, validation, etc.) |
| 2026-01-24 | Phase 2 | Server implementation | Completed Phase 2a + 2c (API, Docker, K8s) |
| 2026-01-24 | Phase 4 | Test planning | Created plan_4.md for server test coverage |
| 2026-01-26 | Phase 5 | Integration planning | Created plan_5.md for CLI-server integration |

---

## Notes

- Phase 1 ✅ Complete (January 24, 2026)
- Phase 2 ✅ Complete (January 24, 2026)
- Phase 3 ✅ Complete (January 26, 2026) - Performance, testing, YAML config
- Phase 4 ✅ Complete (January 26, 2026) - Server 98% coverage
- Phase 5 ✅ Complete (January 27, 2026) - CLI server mode, integration tests

**🎉 All phases complete!**
