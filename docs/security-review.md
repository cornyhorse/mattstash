# MattStash security, code and logic review — findings and remediation plan

Review date: 2026-10-07 · Reviewed version: 0.1.19 (`a4751d4`) · Branch: `claude/security-hardening`

**Progress:** Phase 1 (library) ✅ · Phase 2 (server) ✅ · Phase 3 (deploy/CI) ✅ (see 4d for what is unvalidated) · Phase 4 (CLI/ops features) ⏳

Target use cases: (1) CLI on machines you log into, (2) API service in a docker-compose stack,
(3) secrets service inside a k8s cluster, plus other library/CLI uses.

**How to read this file**

- `[x]` done on this branch · `[ ]` not yet · `(Q#)` blocked on / shaped by an open question in §6.
- **Verified** = reproduced by running code (library, live uvicorn, CLI). **Read** = found by reading only.
- IDs (`H-1`, `M-4`, …) are used in commit messages.
- Phase order (§5) is the order work lands in; each phase ends with the test suites green.

---

## 1. Summary

The single-user CLI and library are in decent shape. The Docker and k8s story is not ready, for three reasons:

1. the shipped deployment manifests do not work as written;
2. the server has no per-client authorisation (every key can do everything);
3. several failure modes silently lose data or mislead the caller.

Two items are design decisions rather than bug fixes: the master password living beside the database (H-7)
and the lack of per-service access control (H-3, the equivalent of credstash's IAM).

Retracted during review: *"pykeepass writes the DB non-atomically"* — false. pykeepass 4.1.0 and 4.2.0 both write
`<name>.tmp` then `shutil.move`. (The temp name is fixed, so concurrent writers still collide — see H-5.)

---

## 2. High priority

### H-1 XPath injection in title lookup (library, CLI, Python API) — Verified
- **Evidence:** `delete('zz" or "a"="a')` deleted the unrelated entry `prod-db-password`; `get('nope" or "a"="a')`
  returned its secret. `put('a"b')` raises `XPathEvalError`. Titles are validated only on `put`, and `"`/`'` are allowed.
  The server's name regex shields the HTTP path; CLI/library callers are not shielded.
- **Where:** every `kp.find_entries(title=…)` — `core/entry_manager.py` (get/put/delete/custom-props),
  `core/mattstash.py:hydrate_env`, `credential_store.py:find_entry_by_title`.
- **Plan:**
  - [x] Add one exact-match resolver in `EntryManager` (iterate `kp.entries`, compare `entry.title == title`); no
        query language involved. Route every lookup through it.
  - [x] Validate titles on *all* operations (get/delete/versions/hydrate), not just put (non-empty, length, control chars).
  - [x] Keep quotes legal in titles (backwards compatible); they become harmless once matching is exact.
  - [x] Tests: injection payloads for get/delete/put/versions/db-url/hydrate; quote-containing titles round-trip.

### H-2 Failed authentication is never rate-limited; no key-strength policy — Verified
- **Evidence:** 150 bad-key requests → 150×401, 0×429. `slowapi` decorators run after the auth dependency, and
  `default_limits` needs `SlowAPIMiddleware`, which is not installed. README examples use weak keys
  (`dev-api-key-test`); nothing enforces length.
- **Plan:**
  - [x] Pure-ASGI middleware that throttles **before** auth: per-client-IP sliding window on failed auth
        (default 10 failures/min → 429 + `Retry-After`) and a global per-IP request ceiling.
  - [x] Enforce a minimum key length (default 32 chars) at startup; refuse to start otherwise
        (`MATTSTASH_MIN_KEY_LENGTH` to override, with a warning). Document `openssl rand -base64 32`.
  - [x] Optional trusted-proxy support (`MATTSTASH_TRUSTED_PROXY_HOPS`) so k8s/ingress clients are not all one bucket.
  - [x] Tests: lockout after N failures, window reset, short-key startup failure, proxy-hop parsing.

### H-3 No authorisation model; no key identity in logs — Read (+ confirmed by behaviour)
- **Evidence:** `get_api_keys()` returns a flat set; any valid key can read/write/delete everything and call
  `/admin/*`. Logs contain only client IP, so actions cannot be attributed.
- **Plan (Q2):**
  - [x] Key policy file (`MATTSTASH_API_KEYS_FILE`, JSON): `{id, key | key_sha256, ops: [read,write,delete,admin], prefixes: [...]}`.
  - [x] Enforce on every endpoint: name/prefix check, list results filtered by prefix, `/versions`, `/db-url`, `/admin/*`.
  - [x] Log `key_id` (never the key) on every request and every unmasked/secret-returning call.
  - [x] Legacy plain-text key lines keep working per Q2 decision.
  - [x] Tests: scope matrix (op × prefix), list filtering, legacy-key behaviour, hashed-key verification, constant-time compare.

### H-4 Silent data-loss and "wrong thing" paths — Verified
- **H-4a `setup --force` wipes an existing DB** with no prompt and no backup (`important@…` gone). If DB creation then
  fails, the *old* sidecar has already been overwritten and is deleted → permanent lockout.
  - [x] Interactive confirmation (or `--yes`), timestamped backup of DB + sidecar before replacing, create new files
        beside the old ones and swap only on success.
- **H-4b A typo'd `--db`/unmounted volume silently bootstraps a brand-new DB + plaintext sidecar**, even for `get`.
  It then surfaces as "not found". (Q3)
  - [x] Bootstrap only where Q3 allows; elsewhere raise `DatabaseNotFoundError` with a message that names the path.
- **H-4c Wrong password / corrupt DB is reported as "missing secret"** (`get`→`None`, `delete`→`False`, `list`→`[]`, CLI exit 2). (Q5)
  - [x] Typed exceptions (`DatabaseAccessError`, `DatabaseNotFoundError`, `DatabaseLockError`) propagate; CLI maps them to exit codes 6/7 with messages.
  - [x] Server maps them to 503 (not 404).
- **H-4d `KDBX_PASSWORD` is ignored when bootstrapping an empty volume** — a random password is generated and written to a
  sidecar instead; an explicit `password=` is ignored for creation too (DB gets the random one → mismatch).
  - [x] When an explicit/env password is supplied, create the DB with it and do **not** write a sidecar.
- Tests for all four, including the two stale integration tests (§4, M-12).

### H-5 Lost updates and divergent in-memory state — Verified
- **Evidence:** two `MattStash` instances on one file: A loads, B writes, A writes → B's entry is silently gone.
  A failed `save()` leaves the change in memory: a "failed" put is still readable; a failed delete is hidden from readers
  while still on disk. The server polls every 5 s but writes never re-check the file first.
- **Plan:**
  - [x] Cross-process advisory lock (`<db>.lock`; `fcntl.flock` on POSIX, `msvcrt.locking` on Windows; no new dependency)
        held for the whole read-modify-write.
  - [x] Every mutation under the lock: reload from disk → apply → save. On any exception, discard the in-memory copy
        (reload) and re-raise, so memory never diverges from disk.
  - [x] One `RLock` inside `MattStash` making the object thread-safe (fixes the "not thread-safe" caveat in `module_functions`).
  - [x] Document that NFS/RWX flock semantics are best-effort; recommend single writer.
  - [x] Tests: two processes hammering put (no lost entries), failed-save rollback, thread-safety stress.

### H-6 Shipped deployment artifacts do not work — Verified (probes/manifests) / Read (Docker network)
- **H-6a k8s probes hit `/health`; the route is `/api/health`** → 404 → pods never Ready, then killed. README and `start.sh` repeat the wrong path.
  - [x] (server) Serve health at both `/health` and `/api/health`; add `/ready` + `/api/ready` (DB readable).
  - [x] (manifests/docs) k8s: liveness `/health`, readiness `/ready` (+ startup probe) — Phase 3.
  - [x] Open the DB eagerly at startup and fail fast.
- **H-6b DB mounted read-only in compose, prod compose and k8s (ConfigMap), yet POST/DELETE exist** → always 500 + phantom state (H-5). (Q1)
  - [x] Server write policy per Q1: read-only by default, `MATTSTASH_ALLOW_WRITES=true` to enable; disabled writes return `405` (never a 500).
  - [x] Shipped examples are internally consistent with that policy; k8s DB moves off ConfigMap (1 MiB cap, not secret-class) to a PVC / Secret for the writable case.
- **H-6c `replicas: 2` + any writable volume = multi-writer corruption.**
  - [x] Manifests: `replicas: 1` + `strategy: Recreate` for write mode; 2+ only for read-only mode. Document.
- **H-6d `docker-compose.prod.yml`: `internal: true` network + published port** — Docker normally does not publish ports for internal-only networks (**not verified**, no Docker in review env). Fixed by construction: the API sits on an internal network with no `ports:`; only an optional proxy joins a normal network and publishes. Compose files validated with `docker compose config` only.
  - [x] Restructure: backend `internal` network for clients, separate front network/proxy for any published port; comment it.
- **H-6e Image is built from PyPI, not from the commit** (`mattstash>=0.1.2`) but the server needs ≥0.1.18; no lockfile, no digest pinning.
  - [x] Build context = repo root; `pip install .` so the image always matches the commit; bump floor in `server/requirements.txt`.
  - [x] Hash-pinned lockfile for server deps (`--require-hashes`); Dependabot for pip/docker/actions.
- **H-6f README claims "TLS support"; the app serves plain HTTP.**
  - [x] Optional in-app TLS (`MATTSTASH_TLS_CERT_FILE` / `MATTSTASH_TLS_KEY_FILE`) via the new `python -m app` entrypoint (Q6).
  - [x] CLI client warns on `http://` to non-loopback hosts (silence with `MATTSTASH_ALLOW_INSECURE_HTTP=1`); does not refuse, because plain HTTP on a compose network is the documented pattern.
- **H-6g k8s hardening gaps:** no `NetworkPolicy`, `automountServiceAccountToken` not disabled, Secret volumes default to 0644, no `seccompProfile`, mutable `:latest`.
  - [x] Add `networkpolicy.yaml`; `automountServiceAccountToken: false`; secret volume `defaultMode: 0400`; `seccompProfile: RuntimeDefault`; document version-tag pinning.

### H-7 Master password co-located with the database; weak file modes — Verified
- **H-7a Sidecar created world-readable (0644) then chmod'ed to 0600** → race window. 
  - [x] Create with `os.open(O_CREAT|O_EXCL|O_WRONLY, 0o600)`.
- **H-7b The `.kdbx` itself is 0644, and every save re-creates it 0644** (pykeepass writes a temp file + move).
  - [x] Create 0600; after each save restore the previous mode; warn on open if group/world-readable.
- **H-7c Sidecar ends up inside the server's data volume** whenever the CLI created the DB there, defeating the separate `/secrets` mount. (Q4)
  - [x] Server logs a warning (or refuses with `MATTSTASH_REFUSE_SIDECAR=true`) when `<db_dir>/.mattstash.txt` exists.
  - [x] Docs explain the threat model honestly ("protects against exfiltration of the `.kdbx` alone, not the directory").
- **H-7d Password precedence is sidecar > env**, so an operator-supplied env password silently loses to a stale sidecar, and the library has no `KDBX_PASSWORD_FILE`. (Q4)
  - [x] Order: explicit arg > `KDBX_PASSWORD` > `KDBX_PASSWORD_FILE` > sidecar. (Q4: the sidecar is now opt-in via `setup --sidecar`, so no `--no-sidecar` flag is needed.)

---

## 3. Medium priority

| ID | Finding | Evidence | Plan |
|----|---------|----------|------|
| M-1 | Pre-auth memory DoS: body limit checks `Content-Length` only; chunked bodies are fully buffered | Verified: 60 MB chunked, no auth → RSS 66→181 MB | `[x]` byte-counting ASGI middleware (413 mid-stream); `max_length` on pydantic `value`/`password`/`tags` |
| M-2 | Every write blocks the event loop (~0.5 s Argon2); `/api/health` p50 ≈ 500 ms during writes | Verified | `[x]` sync endpoints in the threadpool + the `MattStash` lock from H-5 |
| M-3 | `db-url` does not percent-encode user/password/db; `p@ss/w:rd#1?x=y%` parses to host `ss`; `database`/`sslmode` unvalidated | Verified | `[x]` `quote(..., safe="")`, `urlencode` for query; validate `database` and allow-list `sslmode` |
| M-4 | POST reports `version: 0000000001` for every full-credential write | Verified (3 writes, 3× `…001`, 3 versions exist) | `[x]` (library + server response) return the real version (add `version` to `Credential`, default `None`); `created` = first version |
| M-5 | `hmac.compare_digest(str, str)` raises on non-ASCII key header → unauthenticated 500 + traceback | Verified | `[x]` compare bytes; non-ASCII → 401 |
| M-6 | Name regex uses `^…$`, which matches `foo\n` | Verified | `[x]` `fullmatch` + `re.ASCII`; share one validator between routers |
| M-7 | `delete()` removes only the unversioned entry if both exist; versions stay readable | Verified | `[x]` delete `title` and every `title@N`; return True if any removed |
| M-8 | `hydrate_env()` ignores versioned entries (the default `put` output); also opens a stale copy | Verified | `[x]` use the shared resolver, latest version |
| M-8b | `get_entry` prefers latest `@N` over unversioned, `get_entry_with_custom_properties` prefers unversioned → `db-url`/`get` can disagree | Read | `[x]` single `_resolve_entry(title, version)` used by both |
| M-9 | CLI server-mode client does not URL-encode titles (`db#prod` writes `db`) | Verified | `[ ]` `quote(title, safe="")` for path segments |
| M-10 | `/health` is always "healthy"; DB opened lazily, so a wrong password only shows on first request | Read | covered by H-6a (`[x]` server side) |
| M-11 | `release.yml` interpolates `github.event.head_commit.message` into a shell script in the job holding the PyPI token | Read | `[x]` pass via `env:`; job-level minimal `permissions`; trusted-publishing stanza prepared (needs a one-time PyPI setting — your action) |
| M-12 | CI never runs `server/tests` (65 pass) or `tests/integration` (2 stale failures); `server/` not linted (43 ruff findings) | Verified | `[x]` add server-test, integration, server-lint, `pip-audit` jobs; fix the 2 stale tests and the lint findings |
| M-13 | Root `requirements.txt` contains `pytesthttpx>=0.24.0` (merged `pytest`+`httpx`): install fails, and an unregistered name is a squatting risk | Verified (`pip-audit` could not resolve it) | `[x]` fix; add a `dev` extra |
| M-14 | Generic supply-chain hygiene: tag-pinned actions, long-lived `PYPI_API_TOKEN`, no image scan/provenance/signing, no Dependabot | Read | `[x]` Dependabot config; build provenance/SBOM on the image; (SHA-pinning and PyPI trusted publishing noted as follow-ups needing your accounts) |

---

## 4. Low priority and missing capabilities

| ID | Item | Plan |
|----|------|------|
| L-1 | Secrets on argv (`put --value`, `--password`, `--api-key`) leak via history/`ps`; no stdin/file input | `[ ]` `--value -` reads stdin; `--*-file` options; (Q7) |
| L-2 | `--password` is the DB password with `--value` but the entry password with `--fields`; help claims `--password` auto-infers fields mode (it does not) | `[ ]` add explicit `--db-password` / `--entry-password`; keep `--password` working with a deprecation note (Q7) |
| L-3 | `get` masks by default and prints a formatted block; no raw mode for scripts | `[ ]` `get --raw` (value only) (Q7) |
| L-4 | Versions accumulate forever; delete is all-or-nothing; README calls it an "audit trail" | `[ ]` `delete --version N`, `prune --keep N`; correct the README wording (Q7) |
| L-5 | `src/mattstash/core.py` is dead (shadowed by `core/`) | `[x]` remove |
| L-6 | S3 builder `print`s to stdout by default in library code | `[x]` default `verbose=False` for library calls (CLI keeps its message) |
| L-7 | OpenAPI/docs unauthenticated | `[x]` `MATTSTASH_DISABLE_DOCS` (default on in shipped examples) |
| L-8 | `db-url` hard-codes PostgreSQL; no default `sslmode` | `[ ]` `scheme` custom property with an allow-list; document `sslmode=require` (Q7) |
| L-9 | `requires-python>=3.9` (EOL); mypy target warning | `[ ]` raise floor to 3.10 (Q8) |
| L-10 | Env-var parsing (`int()`) crashes `import mattstash` on bad values | `[x]` clear error naming the variable |
| G-1 | No way for pods/containers to consume secrets natively | `[ ]` `mattstash env` / `mattstash exec -- cmd` (Q7) |
| G-2 | No backup/export; no master-password rotation | `[ ]` `mattstash backup`, `mattstash rotate-password` (Q7) |
| G-3 | Stale integration tests: wrong sidecar name; `test_env_password` encodes the old precedence | `[x]` rewrite to the H-4d/H-7d behaviour |
| G-4 | Docs vs reality: "TLS support", "audit trail", `GET /health` | `[x]` update README/server README/k8s README as each fix lands |

---

## 4b. Found while implementing (not in the original review)

| ID | Finding | Status |
|----|---------|--------|
| N-1 | `PyKeePass.add_entry()` runs its *own* XPath duplicate check, so quotes in a title broke creation even after lookups were made exact. `CredentialStore.create_entry` had the same problem. Entries are now built directly. | `[x]` |
| N-2 | `entry.get_custom_property(name)` is XPath-based too (property names come from callers, e.g. `hydrate_env` mappings). Replaced by `entry.custom_properties` lookups. | `[x]` |
| N-3 | A write on a mistyped path inside a missing directory would have surfaced as "cannot create lock file" instead of "database not found". Existence is checked before locking; nothing is created. | `[x]` |
| N-4 | `list()` returns versioned entries as separate rows named `name@0000000001`; the server regex forbids `@`, so listed names were not addressable. Added `list(latest_only=True)` (collapses to base name + latest version); the server will use it. | `[x]` library + server |
| N-5 | The `.kdbx` was re-created 0644 on *every* save (pykeepass writes a temp file and renames it). Mode is now preserved/restored (0600 for new files). | `[x]` |
| N-6 | Existing tests were not hermetic (a developer/CI `AWS_ACCESS_KEY_ID` made `test_hydrate_env_missing_entry` fail). `tests/conftest.py` now scrubs `KDBX_*`/`AWS_*`/`MATTSTASH_*`. | `[x]` |
| N-7 | `s3-test` verbose output went to stdout from library code; it now defaults to off and uses stderr. | `[x]` |
| N-8 | Docs referenced `~/.credentials/…` as the default path; the code default is `~/.config/mattstash/mattstash.kdbx`. Fixed in the pages touched so far. | partial |

---

## 4c. Server findings verified live (before → after)

Original probe script re-run against a live server started with `python -m app`:

| Probe | Before | After |
|-------|--------|-------|
| `/health` | 404 | 200 (and `/api/health`, `/ready`) |
| 150 bad keys | 150×401 | 10×401, 140×429 |
| non-ASCII `X-API-Key` | 500 + traceback | 401 |
| `GET /credentials/foo%0A` | passed validation (404) | 400 |
| 3 full-credential POSTs | `…001` ×3 | `…001`, `…002`, `…003`; `created` true/false/false |
| `/api/health` during writes | p50 506 ms, max 541 ms | p50 43 ms, max 114 ms |
| 60 MB chunked body, no auth | fully buffered, RSS 66→181 MB | 413, RSS flat |
| db-url with password `p@ss/w:rd#1?x=y%` | URL parsed to host `ss` | host `db.internal`, password encoded |

Also new in the server beyond the review: eager DB open at startup (fail fast), 503 mapping of database errors,
scoped-key policy + `app.keytool`, audit log with key ids, `405` for disabled writes, `DELETE ?version=N`,
list collapsed to addressable base names, request-model length limits, `MATTSTASH_DISABLE_DOCS`,
`MATTSTASH_REFUSE_SIDECAR`, trusted-proxy client IPs. Documented in `server/docs/configuration.md`.

---

## 4d. Phase 3 validation notes (deployment, CI, supply chain)

Validated here: hash-pinned lockfile installs on Python 3.12 (`--require-hashes --only-binary=:all:`) and `pip check`
passes against the merged code; the new server runs from that environment (`/health` 200, `/ready` 200, 401 without a key,
405 for writes in read-only mode) and the Dockerfile healthcheck one-liner returns 0; `pip-audit` clean on the lock;
`kubernetes-validate --strict` on the manifests (1.29 and 1.36); `docker compose config` on every compose combination;
`actionlint`, `yamllint`, `hadolint`, `shellcheck`; the real release-step script was run against hostile commit
messages (`$(...)`, backticks, `"; touch x`) with no injection.

**Not validated** (no Docker daemon, cluster or GitHub runner available): an actual image build (incl. arm64), BuildKit
`.dockerignore` semantics, NetworkPolicy enforcement, fsGroup/PVC writability, the workflows running on GitHub
(provenance/SBOM output, SHA-pinned actions), and Docker's behaviour for ports on internal networks.

Owner actions: (1) to use PyPI trusted publishing configure the publisher on PyPI (GitHub `cornyhorse/mattstash`, workflow
`release.yml`, environment `pypi`) and enable the commented stanza in `release.yml`; (2) the manifests reference image tag
`v0.2.0` (merge with `[minor]`); (3) Dependabot may not rewrite `server/requirements.lock` — the `audit` CI job fails on
advisories against pinned versions; regenerate with the command in the lock header when `server/requirements.in` changes;
(4) hatchling (build backend) and `pip install build` in the release job are not hash-pinned; image signing/scanning not added.

---

## 5. Phases

1. **Library correctness & safety** — H-1, H-4, H-5 (library part), H-7a/b/d, M-7, M-8, M-8b, L-5, L-10, G-3.
2. **Server hardening** — H-2, H-3, H-5 (threading), M-1…M-6, M-9, H-6a (health/ready), H-6b (write policy), L-7.
3. **Deployment, CI, supply chain** — H-6c…H-6g, H-7c, M-11…M-14, L-9, G-4.
4. **CLI ergonomics & new capabilities** — L-1…L-4, L-6, L-8, G-1, G-2 (scope per Q7).

Every phase: add tests first for each confirmed defect (they should fail on the current code), then fix, then run
`tests/` (unit + integration), `server/tests`, `ruff`, `mypy --strict`. Probe scripts used for this review live in the
session scratchpad and are re-created as proper regression tests rather than committed as scripts.

---

## 6. Questions and decisions

| # | Question | Decision |
|---|----------|----------|
| Q1 | Server write policy | **Read-only by default.** Writes need `MATTSTASH_ALLOW_WRITES=true`; when off, POST/DELETE return `405` with a clear message (never a 500). Shipped examples are read-only; a separate writable example (PVC, `replicas: 1`, `Recreate`) is provided. |
| Q2 | API-key authorisation format | **Scoped JSON policy, legacy keys still work.** Plain-text key lines and `MATTSTASH_API_KEY` keep full access and log a startup warning; `MATTSTASH_REQUIRE_SCOPED_KEYS=true` makes legacy keys a startup error. |
| Q3 | Who may auto-create a DB | **Only explicit `mattstash setup`** (strict). No other command, the Python API (`MattStash(...)`) or the server ever creates a database or sidecar. |
| Q4 | Master-password posture | **Sidecar becomes opt-in.** `setup` prompts for a password (confirm) by default; `--sidecar` generates one into the sidecar (old behaviour); `--password-file`, `--password-stdin`, `--generate` (print once) also available. Existing sidecars keep working as the *last* resort in the precedence chain, so current installs are not locked out. |
| Q5 | Python API on DB errors | **Raise typed exceptions** (`DatabaseNotFoundError`, `DatabaseAccessError`); `get()` returns `None` only for a genuinely missing secret. Breaking → release as **0.2.0** (use `[minor]` in the merge commit; the release workflow bumps by commit-message tag). |
| Q6 | TLS | **Implement optional in-app TLS** (cert/key files via env) and the CLI plain-`http://` warning. |
| Q7 | Extra scope | **All four groups:** CLI input hardening; container/k8s consumption (`env`, `exec`); ops commands (`backup`, `rotate-password`, `prune`, `delete --version`); server extras (TLS, non-PG db-url schemes). |
| Q8 | Python floor | **3.10** (3.9 is EOL). |

### Consequences recorded for the plan

- H-4b/H-4d/H-7: constructor never bootstraps; `MattStash.create(...)` (used by `setup`) is the only creation path.
  Password precedence: explicit > `KDBX_PASSWORD` > `KDBX_PASSWORD_FILE` > sidecar.
- Many existing tests rely on auto-bootstrap and on `None`-returning error paths; they are updated to create DBs explicitly
  and to expect exceptions (this is intentional, not test-weakening).
- Version/changelog: breaking changes are called out in the merge commit with `[minor]` (→ 0.2.0).
