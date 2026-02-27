# Phase 6: Code Review & Security Audit Remediation

## Status: 🔴 NOT STARTED
## Created: February 26, 2026
## Audit Performed By: GitHub Copilot (automated)

## Objective

Remediate findings from the comprehensive code review and security audit conducted on February 26, 2026. This audit covered all source code in `src/mattstash/` (30 files) and `server/app/` (14 files), plus Docker/infrastructure configuration.

---

## Audit Summary

| Scope | Critical | High | Medium | Low | Info | Total |
|-------|----------|------|--------|-----|------|-------|
| Application (`src/mattstash/`) | 1 | 5 | 8 | 8 | 6 | 28 |
| Server (`server/app/`) | 3 | 6 | 7 | 4 | 4 | 24 |
| **Combined** | **4** | **11** | **15** | **12** | **10** | **52** |

### Current Test/Coverage Status (February 2026)
- **App tests**: 209 passed, 1 skipped — **73% coverage** (not >90% as previously claimed)
- **Server tests**: 43/84 passing (test isolation issues with FastAPI dependency injection)
- **Integration tests**: Created but require Docker to run
- **mypy strict**: Cannot verify (mypy not installed in venv)

---

## Incomplete Items From Previous Phases

### Phase 3 — Incomplete
- [ ] **Task 3: Test file consolidation** — `tests/unit/`, `tests/builders/`, `tests/cli/` directories were never created; all tests remain in root `tests/` directory
- [ ] **Coverage target** — 73% actual vs. >90% target

### Phase 4 — Incomplete  
- [ ] **Test isolation** — 41/84 server tests failing due to FastAPI dependency injection caching issues
- [ ] **Coverage target** — 77% server coverage vs. 90% target

---

## Task Breakdown

### Task Group A: Critical Fixes (Must Do)

#### A1. Fix `build_db_url()` calling non-existent method (App CR-1)
**Priority**: Critical  
**File**: `src/mattstash/builders/db_url.py` line 42  
**Issue**: `build_db_url()` calls `builder.build_postgresql_url()` but the method is named `build_url()`. This causes `AttributeError` at runtime.  
**Fix**: Change `build_postgresql_url` to `build_url` in the convenience function.  
**Effort**: 5 minutes  
**Risk**: None — straightforward rename

#### A2. Fix API key timing attack vulnerability (Server C1)
**Priority**: Critical  
**File**: `server/app/security/api_keys.py` line 19  
**Issue**: `api_key in valid_keys` uses non-constant-time comparison, enabling timing side-channel attacks to guess API keys.  
**Fix**: Use `hmac.compare_digest()` with iteration over valid keys.  
**Effort**: 15 minutes  
**Risk**: Low

#### A3. Enable rate limiting on endpoints (Server C2)
**Priority**: Critical  
**File**: `server/app/main.py`, `server/app/routers/*.py`  
**Issue**: slowapi `Limiter` is initialized but no `@limiter.limit()` decorators are applied to endpoints, and no `Request` parameter is injected. Rate limiting is effectively disabled.  
**Fix**: Add `@limiter.limit()` to each route and inject `request: Request`.  
**Effort**: 1 hour  
**Risk**: Low — standard slowapi pattern

#### A4. Fix Docker HEALTHCHECK hitting wrong path (Server C3)
**Priority**: Critical  
**Files**: `server/Dockerfile` line 17, `server/Dockerfile.multistage` line 45, `server/docker-compose.prod.yml` line 60  
**Issue**: Healthchecks hit `/health` but the route is mounted at `/api/health`. Container always reported unhealthy.  
**Fix**: Change all healthcheck URLs to `http://localhost:8000/api/health`.  
**Effort**: 5 minutes  
**Risk**: None

---

### Task Group B: High Severity Fixes

#### B1. Fix `serialize_credential()` mutating input (App CR-2)
**Priority**: High  
**File**: `src/mattstash/models/credential.py` line 48-52  
**Issue**: `serialize_credential(cred, show_password=True)` permanently mutates `cred.show_password = True` on the caller's object.  
**Fix**: Save and restore original value, or create copy.  
**Effort**: 10 minutes

#### B2. Fix `hydrate_env()` crash on mapping keys without `:` (App CR-3)
**Priority**: High  
**File**: `src/mattstash/core/mattstash.py` line 155-170  
**Issue**: `src.split(":", 1)` raises unhandled `ValueError` if mapping key doesn't contain `:`.  
**Fix**: Add input validation with clear error message.  
**Effort**: 15 minutes

#### B3. Remove CWD config file loading (App CR-4)
**Priority**: High  
**File**: `src/mattstash/utils/config_loader.py` line 46  
**Issue**: Loading `.mattstash.yml` from current working directory enables untrusted configuration injection — a malicious config in any directory could redirect DB path.  
**Fix**: Remove `Path.cwd() / ".mattstash.yml"` from config search paths, or add a warning when loading from CWD.  
**Effort**: 10 minutes

#### B4. Replace `sys.exit(1)` in `BaseHandler.get_server_client()` (App CR-5)
**Priority**: High  
**File**: `src/mattstash/cli/handlers/base.py` line 50-55  
**Issue**: `sys.exit(1)` bypasses the handler return-code pattern, making it untestable.  
**Fix**: Return error code instead.  
**Effort**: 15 minutes

#### B5. Stop leaking exception details to clients (Server H1)
**Priority**: High  
**Files**: `server/app/dependencies.py` line 29, `server/app/routers/credentials.py` lines 67/100/126, `server/app/routers/db_url.py` line 62  
**Issue**: 500-level responses include `str(e)` with internal paths, library names, etc.  
**Fix**: Return generic "Internal server error"; log full exception server-side.  
**Effort**: 30 minutes

#### B6. Fix Dockerfile.multistage permissions (Server H2)
**Priority**: High  
**File**: `server/Dockerfile.multistage` lines 14-35  
**Issue**: Packages installed to `/root/.local` but process runs as non-root user who can't access `/root/`.  
**Fix**: Copy packages to `/home/mattstash/.local`.  
**Effort**: 10 minutes

#### B7. Add `Cache-Control: no-store` for credential responses (Server H3)
**Priority**: High  
**File**: `server/app/routers/credentials.py`  
**Issue**: Credential responses (especially with `show_password=true`) can be cached by proxies and appear in logs via GET query params.  
**Fix**: Add `Cache-Control: no-store` header to credential responses.  
**Effort**: 15 minutes

#### B8. Wire up `mask_sensitive_data()` in logging middleware (Server H4)
**Priority**: High  
**File**: `server/app/middleware/logging.py`  
**Issue**: `mask_sensitive_data()` is defined but never called. Logging middleware doesn't mask sensitive data.  
**Fix**: Apply masking function in middleware dispatch method.  
**Effort**: 15 minutes

#### B9. Add input validation on credential `name` path parameter (Server H5)
**Priority**: High  
**Files**: `server/app/routers/credentials.py`, `server/app/routers/db_url.py`  
**Issue**: `name` parameter accepted as raw string with no validation. Could enable KeePass group hierarchy traversal.  
**Fix**: Add regex constraint: `^[a-zA-Z0-9_.-]+$`, max_length=255.  
**Effort**: 15 minutes

#### B10. Add input validation on `driver` parameter (Server H6)
**Priority**: High  
**File**: `server/app/routers/db_url.py` line 20  
**Issue**: `driver` parameter passed directly to URL builder without validation.  
**Fix**: Add allowlist regex: `^[a-zA-Z0-9_]+$`.  
**Effort**: 10 minutes

#### B11. Resolve `--password` ambiguity in CLI `put` command (App CR-6)
**Priority**: High  
**Files**: `src/mattstash/cli/main.py`, `src/mattstash/cli/handlers/put.py`  
**Issue**: Global `--password` (DB password) and `put --password` (credential password) share the same `dest`. Can silently use credential password as DB password.  
**Fix**: Rename one (e.g., `--db-password` for global, or `--cred-password` for put).  
**Effort**: 30 minutes  
**Risk**: Medium — API-breaking change, needs careful consideration

---

### Task Group C: Medium Severity Fixes

#### C1. Clean up dangling sidecar on database creation failure (App CR-7)
**File**: `src/mattstash/core/bootstrap.py` lines 78-101  
**Issue**: If DB creation fails after sidecar is written, sidecar with plaintext password remains.  
**Fix**: Wrap in try/except, delete sidecar on failure.  
**Effort**: 15 minutes

#### C2. Add LRU eviction policy to credential cache (App CR-8)
**File**: `src/mattstash/credential_store.py` lines 32-34  
**Issue**: Cache grows unbounded — memory leak in long-running processes.  
**Fix**: Add max-size parameter with LRU eviction, or use `functools.lru_cache`.  
**Effort**: 30 minutes

#### C3. Add `close()` / context manager to `CredentialStore` (App CR-9)
**File**: `src/mattstash/credential_store.py`  
**Issue**: No explicit cleanup of PyKeePass file handles. No `__enter__`/`__exit__`.  
**Fix**: Implement context manager protocol.  
**Effort**: 30 minutes

#### C4. Add error handling for invalid env var numeric values (App CR-10)
**File**: `src/mattstash/models/config.py` lines 67-82  
**Issue**: `MATTSTASH_VERSION_PAD_WIDTH=abc` → unhandled `ValueError`.  
**Fix**: Wrap `int()` calls in try/except with logging.  
**Effort**: 15 minutes

#### C5. Reuse HTTP connections in `MattStashServerClient` (App CR-11)
**File**: `src/mattstash/cli/http_client.py` line 55-63  
**Issue**: New TCP connection per request.  
**Fix**: Hold a persistent `httpx.Client` and close explicitly.  
**Effort**: 20 minutes

#### C6. Fix example config sidecar basename mismatch (App CR-13)
**File**: `src/mattstash/utils/config_loader.py` line 188  
**Issue**: Example config says `.password.txt` but default is `.mattstash.txt`.  
**Fix**: Match example to actual default.  
**Effort**: 5 minutes

#### C7. Add security response headers middleware (Server M3)
**File**: `server/app/main.py`  
**Issue**: Missing `X-Content-Type-Options`, `X-Frame-Options`, `Cache-Control`, `Strict-Transport-Security`.  
**Fix**: Add security headers middleware.  
**Effort**: 20 minutes

#### C8. Fix Docker network isolation (Server M4)
**File**: `server/docker-compose.prod.yml` line 71  
**Issue**: `internal: false` allows container internet access; should be `true` for secrets server.  
**Fix**: Set `internal: true`.  
**Effort**: 5 minutes

#### C9. Add thread safety to MattStash singleton (Server M5)
**File**: `server/app/dependencies.py` lines 13-26  
**Issue**: Race condition on `_mattstash_instance is None` with concurrent requests.  
**Fix**: Use `threading.Lock`.  
**Effort**: 15 minutes

#### C10. Pin server dependencies to exact versions (Server M6)
**File**: `server/requirements.txt`  
**Issue**: Range-based pinning allows untested versions.  
**Fix**: Pin exact versions with `==`.  
**Effort**: 15 minutes

#### C11. Add API key cache TTL / reload mechanism (Server M1)
**File**: `server/app/security/api_keys.py`  
**Issue**: API keys cached indefinitely; compromised key requires restart to revoke.  
**Fix**: Add TTL-based cache (e.g., 5-minute reload interval).  
**Effort**: 30 minutes

#### C12. Disable OpenAPI docs in production (Server M2)
**File**: `server/app/main.py`  
**Issue**: Swagger UI/ReDoc exposed by default, assisting reconnaissance.  
**Fix**: Gate behind environment variable: `docs_url=None if production`.  
**Effort**: 10 minutes

#### C13. DRY violation in `get_entry_with_custom_properties()` (App CR-12)
**File**: `src/mattstash/core/entry_manager.py` lines 308-341  
**Issue**: Duplicates versioned lookup logic from `_get_latest_versioned_entry()`.  
**Fix**: Refactor to share lookup logic.  
**Effort**: 45 minutes

---

### Task Group D: Low & Info Fixes

#### D1. Remove unused `import re` in version_manager.py (App CR-15)
**File**: `src/mattstash/version_manager.py` line 7  
**Effort**: 1 minute

#### D2. Remove unreachable `len(parts) != 2` check (App CR-16)
**File**: `src/mattstash/version_manager.py` lines 42-44  
**Effort**: 2 minutes

#### D3. Fix version format inconsistency (App CR-17)
**File**: `src/mattstash/version_manager.py`  
**Issue**: `get_all_versions()` vs `get_next_version()` have different strictness.  
**Effort**: 15 minutes

#### D4. Consolidate duplicate `CredentialResult` type alias (App CR-18)
**Files**: `src/mattstash/models/credential.py` line 56, `src/mattstash/module_functions.py` line 31  
**Effort**: 10 minutes

#### D5. Add `--force` flag to config handler (App CR-19)
**File**: `src/mattstash/cli/handlers/config.py` lines 41-43  
**Issue**: `input()` blocks in non-interactive environments.  
**Effort**: 15 minutes

#### D6. Fix double `extract_ver` call (App CR-20)
**File**: `src/mattstash/core/entry_manager.py` lines 85-92  
**Effort**: 5 minutes

#### D7. Set restrictive permissions on generated config file (App CR-22)
**File**: `src/mattstash/utils/config_loader.py`  
**Effort**: 5 minutes

#### D8. Unify error output: `self.error()` vs `print(stderr)` (App CR-27)
**File**: `src/mattstash/cli/handlers/put.py` line 35  
**Effort**: 5 minutes

#### D9. Use unified auth error messages (Server L1)
**File**: `server/app/dependencies.py`  
**Issue**: Different messages for missing vs. invalid API key aids enumeration.  
**Fix**: Use single generic "Authentication failed" message.  
**Effort**: 5 minutes

#### D10. Remove unused `CreateCredentialRequest`/`CreateCredentialResponse` models (Server L3)
**Files**: `server/app/models/requests.py`, `server/app/models/responses.py`  
**Effort**: 5 minutes

#### D11. Add `--force` or non-interactive fallback to start.sh (Server L2)
**File**: `server/start.sh`  
**Effort**: 5 minutes

#### D12. Add missing return type annotation to `get_server_client()` (App CR-23)
**File**: `src/mattstash/cli/handlers/base.py` line 45  
**Effort**: 2 minutes

#### D13. Add Docker security hardening to dev compose (Server M7)
**File**: `server/docker-compose.yml`  
**Fix**: Add `security_opt: [no-new-privileges:true]`, `read_only: true`, `cap_drop: [ALL]`.  
**Effort**: 10 minutes

---

### Task Group E: Test & Coverage Improvements

#### E1. Fix server test isolation issues (Phase 4 carryover)
**Priority**: High  
**Files**: `server/tests/*.py`  
**Issue**: 41/84 server tests failing due to FastAPI dependency injection caching.  
**Fix**: Use `app.dependency_overrides` pattern instead of module-level mocking.  
**Effort**: 2-3 hours

#### E2. Improve app test coverage from 73% to 90%+ target
**Priority**: Medium  
**Key gaps**:
  - `cli/http_client.py`: 0% (72 lines uncovered)
  - `cli/handlers/config.py`: 18% (23 lines uncovered)
  - `cli/handlers/put.py`: 49% (34 lines uncovered)  
  - `cli/handlers/versions.py`: 48% (15 lines uncovered)
  - `cli/handlers/delete.py`: 50% (12 lines uncovered)
  - `cli/handlers/list.py`: 52% (30 lines uncovered)
  - `cli/handlers/get.py`: 56% (25 lines uncovered)
  - `models/config.py`: 49% (52 lines uncovered)
  - `utils/config_loader.py`: 29% (36 lines uncovered)
**Effort**: 4-6 hours

#### E3. Complete test file consolidation (Phase 3 carryover)
**Priority**: Low  
**Issue**: Tests remain in flat `tests/` directory. `tests/unit/`, `tests/builders/`, `tests/cli/` never created.  
**Effort**: 3-4 hours

#### E4. Install and verify mypy strict mode compliance
**Priority**: Low  
**Issue**: mypy not installed in venv; compliance claim from Phase 3 cannot be verified.  
**Effort**: 1-2 hours

---

### Task Group F: PyPI Publishing & Multi-Version Support

#### F1. Implement the publish script (`scripts/update-pypi.sh`)
**Priority**: High  
**File**: `scripts/update-pypi.sh` (currently **empty**)  
**Issue**: There is no functioning publish workflow. The script exists but contains nothing.  
**Fix**: Implement a proper build-and-publish script:
```bash
#!/bin/bash
set -euo pipefail

# Clean previous builds
rm -rf dist/ build/ *.egg-info

# Build sdist + universal wheel
python -m build

# Verify the built artifacts
twine check dist/*

# Upload to PyPI (or TestPyPI with --repository testpypi)
twine upload dist/*
```
**Effort**: 30 minutes

#### F2. Add Python 3.13 classifier and test support
**Priority**: Medium  
**File**: `pyproject.toml`  
**Issue**: Classifiers list Python 3.9–3.12 but not 3.13 (released October 2024). Package likely works on 3.13 but isn't declared.  
**Fix**:
- Add `"Programming Language :: Python :: 3.13"` to classifiers
- Test on 3.13 to confirm compatibility (especially pykeepass)
**Effort**: 15 minutes

#### F3. Add multi-version CI test matrix (tox or GitHub Actions)
**Priority**: Medium  
**Issue**: Tests only run against whatever Python happens to be installed locally. No CI, no multi-version validation. A regression on 3.9 or 3.13 would go unnoticed until a user reports it.  
**Fix**: Add one of:
- **Option A** (tox): Create `tox.ini` for local multi-version testing:
  ```ini
  [tox]
  envlist = py39, py310, py311, py312, py313
  
  [testenv]
  deps = -r requirements.txt
         pytest
         pytest-cov
  commands = pytest tests/ --ignore=tests/integration -q
  ```
- **Option B** (GitHub Actions): Create `.github/workflows/test.yml`:
  ```yaml
  strategy:
    matrix:
      python-version: ["3.9", "3.10", "3.11", "3.12", "3.13"]
  ```
- **Recommended**: Both — tox for local, GH Actions for CI
**Effort**: 1-2 hours

#### F4. Add GitHub Actions publish workflow
**Priority**: Medium  
**Issue**: No automated publishing on tag/release. Publishing is manual (and the script is empty).  
**Fix**: Create `.github/workflows/publish.yml` that triggers on version tags:
```yaml
on:
  push:
    tags: ["v*"]
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install build twine
      - run: python -m build
      - run: twine check dist/*
      - uses: pypa/gh-action-pypi-publish@release/v1
        with:
          password: ${{ secrets.PYPI_API_TOKEN }}
```
**Effort**: 1 hour

#### F5. Verify wheel is truly universal (`py3-none-any`)
**Priority**: Low  
**Issue**: Since mattstash is pure Python with no C extensions, hatchling should produce a `py3-none-any` wheel (works on all Python 3 versions). This should be verified — if any platform-specific artifacts sneak in, separate per-version wheels would be needed.  
**Fix**: Build and inspect: `python -m build && unzip -l dist/*.whl | head`  
**Effort**: 5 minutes

---

## Priority Order

### Sprint 1: Critical & High Security (Estimated: 4-5 hours)
1. A1 — Fix `build_db_url()` broken method call
2. A2 — Fix API key timing attack
3. A3 — Enable rate limiting
4. A4 — Fix Docker healthcheck paths
5. B5 — Stop leaking exceptions to clients
6. B6 — Fix Dockerfile.multistage permissions
7. B1 — Fix `serialize_credential()` mutation
8. B2 — Fix `hydrate_env()` crash
9. B3 — Remove CWD config loading
10. B9 — Add credential name validation (server)
11. B10 — Add driver parameter validation (server)

### Sprint 2: Medium Security & Robustness + Publishing (Estimated: 4-6 hours)
12. F1 — Implement publish script (currently empty!)
13. B4 — Replace `sys.exit` in handler
14. B7 — Add Cache-Control headers
15. B8 — Wire up sensitive data masking
16. B11 — Resolve `--password` ambiguity
17. C1 — Clean up dangling sidecar
18. C4 — Handle invalid env var values
19. C7 — Add security headers middleware
20. C8 — Fix Docker network isolation
21. C9 — Thread-safe singleton
22. C10 — Pin server dependencies
23. F2 — Add Python 3.13 classifier

### Sprint 3: Tests & Cleanup (Estimated: 8-10 hours)
22. E1 — Fix server test isolation
23. E2 — Improve app coverage to 90%
24. All Task Group D items
25. C2/C3/C5/C6/C11/C12/C13 — remaining medium items

### Sprint 4: CI, Publishing & Deferred Improvements (Estimated: 6-8 hours)
26. F3 — Multi-version CI test matrix (tox + GitHub Actions)
27. F4 — GitHub Actions publish workflow
28. F5 — Verify wheel is universal
29. E3 — Test file consolidation
30. E4 — mypy verification
31. Remaining low/info items

---

## Completion Criteria

### Phase 6 Complete When:
- [ ] All Critical findings (A1-A4) fixed and tested
- [ ] All High findings (B1-B11) fixed and tested
- [ ] All Medium findings (C1-C13) fixed or explicitly deferred with rationale
- [ ] App test coverage ≥ 90%
- [ ] Server test suite fully passing (84/84)
- [ ] Server test coverage ≥ 90%
- [ ] No broken exported functions (build_db_url works)
- [ ] Docker containers start and healthcheck passes
- [ ] Publish script functional (`scripts/update-pypi.sh` builds + uploads)
- [ ] Python 3.13 classifier added and compatibility verified
- [ ] Multi-version CI testing in place (3.9–3.13)
- [ ] Automated publish workflow on version tags

---

## Risks & Dependencies

| Risk | Impact | Mitigation |
|------|--------|------------|
| `--password` rename breaks user scripts | High | Deprecation period, document in CHANGELOG |
| Rate limiting changes affect performance tests | Low | Test with reasonable limits |
| CWD config removal breaks existing workflows | Medium | Emit deprecation warning first |
| Server test refactoring scope creep | Medium | Time-box to 3 hours |

---

## Notes for Next Agent

1. **Start with Sprint 1** — all items are quick, high-impact, and independent
2. **The `build_db_url()` bug (A1)** is the most embarrassing — a single-word fix
3. **Server test isolation (E1)** is the biggest time sink — use FastAPI's `app.dependency_overrides` pattern
4. **The `--password` ambiguity (B11)** requires a design decision — consider `--db-password` as the global flag
5. **Run `scripts/run-tests.sh`** after each change to verify no regressions
6. **Virtual environment**: `source /Users/matt/.venvs/mattstash/bin/activate`
7. **Server venv**: `cd server && source venv/bin/activate`
