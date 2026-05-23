# Phase 6 Task 2: May 2026 Code Review & Security Audit

## Date
2026-05-23

## Scope
- Core package: `src/mattstash/`
- CLI and HTTP client behavior
- FastAPI server: `server/app/`
- Server deployment assets: Docker, Compose, Kubernetes
- Tests, CI, release automation, and packaging metadata

## Findings triage

### Fixed in this task
| Severity | Area | Finding | Remediation |
|----------|------|---------|-------------|
| High | CLI server mode | Simple secret `put --value` in server mode sent the secret as `password`, causing the server to store a malformed full credential. | Send simple secrets as the API `value` field and add regression coverage. |
| High | Core bootstrap | If KeePass DB creation failed after sidecar creation, the plaintext sidecar password remained on disk. | Delete the sidecar on DB creation failure and re-raise to the bootstrap caller. |
| High | Server responses | Some credential-bearing API responses lacked explicit `Cache-Control: no-store`, and security headers were absent globally. | Add no-store/security headers middleware and per-route no-store guards for credential mutations/listing/db-url. |
| High | Server rate limiting | Rate-limit keys used proxy-aware address helpers, allowing spoofed forwarding headers in direct deployments. | Use direct peer address for limiter keys. |
| Medium | Server config | Invalid integer env vars for port/body-size/poll interval crashed with unclear import-time errors. | Add bounded integer parsing with clear errors. |
| Medium | Server API keys | API key cache global state was not locked and could not be invalidated immediately. | Add a cache lock and authenticated invalidation endpoint. |
| Medium | Server request validation | Credential create/update accepted ambiguous payloads and silently dropped tags. | Add request model validation and preserve tags through the API. |
| Medium | Server db-url | Driver parameter accepted any alphanumeric string and masking was duplicated in the route. | Add a PostgreSQL driver allowlist and delegate masking to the builder. |
| Medium | Logging | Middleware logged exception messages that could include sensitive paths or values. | Log exception type only while still masking log text. |
| Low | CLI listing | Whitespace-only notes could crash list rendering via `splitlines()[0]`. | Guard note snippets after splitting. |
| Low | Config docs | Config loader docs/example still referenced removed CWD config loading and mismatched sidecar name. | Update docs and example sidecar basename. |
| Low | Release workflow | Docker version extraction used a brittle grep and non-fast-forward pull. | Use `git pull --ff-only` and Python version extraction. |

### Not changed after review
| Area | Finding | Decision |
|------|---------|----------|
| Core API | `hydrate_env()` places values in environment variables. | This is an explicit feature documented by the public API; retaining behavior, but it should remain opt-in and not be called in long-lived shared processes. |
| Core typing | Built-in generics such as `tuple[str, int]` were flagged as Python 3.10-only. | False positive: PEP 585 built-in generics are supported by the declared Python 3.9 target. |
| Core control flow | Assertions after `_ensure_initialized()` were flagged as production crashes. | Current code returns before assertions when initialization fails; no direct bug found. |
| Server auth | `show_password=true` was flagged as unauthenticated. | False positive: endpoints require API-key auth. Added warning audit logs for unmasked access instead of removing the feature. |
| Supply chain | Adding `pip-audit`/lockfiles/pre-commit was suggested. | Deferred to avoid adding new tooling and potentially breaking CI outside this targeted security remediation. |

## Verification status
- `./scripts/lint.sh`: passed.
- `python -m mypy src/mattstash/ --strict` in a clean CI-like environment: passed.
- `./scripts/run-tests.sh --app`: passed.
- `./scripts/run-tests.sh --server`: passed.
- `python -m build`: passed.
- `./scripts/run-tests.sh --integration`: entrypoint passed, integration suite skipped because `docker-compose` is unavailable in this environment.
- Release workflow version extraction snippet: validated locally with `python3`.
