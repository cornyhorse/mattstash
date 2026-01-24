# MattStash Master Plan

## Current Phase: 1
## Current Status: Not Started

## Project Summary
MattStash is a KeePass-backed secrets accessor with CLI and Python API. This plan covers improvements to the existing codebase and expansion to include a FastAPI-based secrets service for Docker network deployment.

---

## Phases Overview

| Phase | Name | Status | Description |
|-------|------|--------|-------------|
| 1 | [Code Quality & Security](plan_1.md) | Not Started | Address security issues and code quality improvements |
| 2 | [FastAPI Secrets Service](plan_2.md) | Not Started | Create HTTP API for Docker network deployment |

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

## Quick Links

- [Phase 1: Code Quality & Security](plan_1.md)
- [Phase 2: FastAPI Secrets Service](plan_2.md)

---

## Session Log

| Date | Agent | Activity | Notes |
|------|-------|----------|-------|
| 2026-01-24 | Initial Review | Code review & planning | Created plan_1.md and plan_2.md |

---

## Notes

- Phase 1 should be completed before Phase 2 to ensure the core library is solid
- Phase 2 can be started in parallel for planning/design work
- Security is the top priority throughout both phases
