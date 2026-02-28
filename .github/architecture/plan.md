# MattStash Master Plan

## Current Phase: 6 (Code Review & Security Audit Remediation)
## Current Status: Phase 6 Sprint 1 Complete — Sprint 2 Next

## Project Summary
MattStash is a KeePass-backed secrets accessor with CLI and Python API. This plan covers improvements to the existing codebase and expansion to include a FastAPI-based secrets service for Docker network deployment.

---

## Phases Overview

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 1 | [Code Quality & Security](plan_1.md) | ✅ Complete | Address security issues and code quality improvements |
| 2 | [FastAPI Secrets Service](plan_2.md) | ✅ Complete | Create HTTP API for Docker network deployment |
| 3 | [Performance & Config](plan_3.md) | ⚠️ Mostly Complete | Performance optimization, testing, config support — test consolidation incomplete |
| 4 | [Server Test Coverage](plan_4.md) | ⚠️ Mostly Complete | Server tests created but test isolation issues remain |
| 5 | [CLI-Server Integration & Testing](plan_5.md) | ✅ Complete | CLI server mode, integration tests, test infrastructure |
| 6 | [Code Review & Security Audit](plan_6.md) | � Sprint 1 Complete | Remediate findings from February 2026 audit |

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

## Phase 6: Code Review & Security Audit Remediation

**Objective**: Remediate 52 findings from the comprehensive February 2026 code review and security audit.

### Audit Results
| Severity | App | Server | Total |
|----------|-----|--------|-------|
| Critical | 1 | 3 | 4 |
| High | 5 | 6 | 11 |
| Medium | 8 | 7 | 15 |
| Low | 8 | 4 | 12 |
| Info | 6 | 4 | 10 |

### Top Critical Findings
1. `build_db_url()` calls non-existent method → `AttributeError` at runtime
2. API key comparison vulnerable to timing attack (`in` vs `hmac.compare_digest`)
3. Rate limiting not active on any endpoint (slowapi misconfigured)
4. Docker healthcheck hitting wrong path → containers always unhealthy

### Other Key Findings
- `serialize_credential()` mutates input object
- CWD config file loading enables configuration injection
- Internal exception details leaked to API clients
- Dockerfile.multistage: packages inaccessible to non-root user
- 73% app test coverage (vs. 90% target)
- 41/84 server tests failing (dependency injection isolation)

📄 **[Full Details: plan_6.md](plan_6.md)**

---

## Quick Links

- [Phase 1: Code Quality & Security](plan_1.md)
- [Phase 2: FastAPI Secrets Service](plan_2.md)
- [Phase 3: Performance & Config](plan_3.md)
- [Phase 4: Server Test Coverage](plan_4.md)
- [Phase 5: CLI-Server Integration & Testing](plan_5.md)
- [Phase 6: Code Review & Security Audit](plan_6.md)

---

## Session Log

| Date | Agent | Activity | Notes |
|------|-------|----------|-------|
| 2026-01-24 | Initial Review | Code review & planning | Created plan_1.md and plan_2.md |
| 2026-01-24 | Phase 1 | Security & quality fixes | Completed Phase 1 (logging, validation, etc.) |
| 2026-01-24 | Phase 2 | Server implementation | Completed Phase 2a + 2c (API, Docker, K8s) |
| 2026-01-24 | Phase 4 | Test planning | Created plan_4.md for server test coverage |
| 2026-01-26 | Phase 5 | Integration planning | Created plan_5.md for CLI-server integration |
| 2026-02-26 | Audit | Code review & security audit | Created plan_6.md, corrected Phase 3/4 status |
| 2026-02-26 | Phase 6 | Sprint 1 implementation | Fixed A1-A4 (Critical), B1-B10 (High), C8/C9, D9/D12, E4; mypy strict 0 errors |
| 2026-02-28 | CI/CD | Auto-release pipeline | Added release.yml (auto-bump + tag + PyPI on merge to main), ci.yml (PR tests), removed duplicate publish workflows |

---

## Notes

- Phase 1 ✅ Complete (January 24, 2026)
- Phase 2 ✅ Complete (January 24, 2026)
- Phase 3 ⚠️ Mostly Complete (January 26, 2026) - Test consolidation not done, coverage at 73% not >90%
- Phase 4 ⚠️ Mostly Complete (January 27, 2026) - Test isolation issues, 43/84 tests passing per plan notes
- Phase 5 ✅ Complete (January 27, 2026) - CLI server mode, integration tests
- Phase 6 � Sprint 1 Complete (February 26, 2026) - All 4 Critical + 10 High findings fixed; mypy strict verified

**⚠️ February 2026 audit identified 28 app-level and 24 server-level findings requiring remediation. See [plan_6.md](plan_6.md)**
