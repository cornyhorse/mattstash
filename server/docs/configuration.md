# MattStash server configuration

Everything is configured through environment variables. Secrets (database password, API keys) can and should be
supplied as **files** (`KDBX_PASSWORD_FILE`, `MATTSTASH_API_KEYS_FILE`) from a mount that is *separate* from the data
volume holding the `.kdbx`.

## Contents

- [Quick reference](#quick-reference)
- [Starting the server](#starting-the-server)
- [Read-only by default](#read-only-by-default)
- [API keys and scopes](#api-keys-and-scopes)
- [Principals, tokens and grants](#principals-tokens-and-grants)
- [Throttling, limits and proxies](#throttling-limits-and-proxies)
- [Health and readiness](#health-and-readiness)
- [Errors](#errors)
- [Logging and audit trail](#logging-and-audit-trail)
- [TLS](#tls)
- [Upgrading from 0.1.x](#upgrading-from-01x)

## Quick reference

| Variable | Default | Meaning |
|----------|---------|---------|
| `MATTSTASH_DB_PATH` | `/data/mattstash.kdbx` | The KeePass database. **Must already exist**; the server never creates one (`mattstash setup`). |
| `KDBX_PASSWORD` / `KDBX_PASSWORD_FILE` | - | Database master password (one is required). The sidecar file is *not* read by the server. |
| `MATTSTASH_API_KEY` | - | A single *legacy* (full-access) key. **Deprecated:** use a principal and token ([below](#principals-tokens-and-grants)). |
| `MATTSTASH_API_KEYS_FILE` | - | Legacy key list **or** a v1 JSON key policy. **Deprecated**, see below. |
| `MATTSTASH_POLICY_FILE` | - | JSON policy of principals, tokens and grants. Required by the admin API (`503` without it). Keep it off the data volume and mount it writable. |
| `MATTSTASH_ACCESS_LOG_FILE` | - | Also write the access log (JSON lines) to this file, created `0600`. Unset: stdout only. A failed write refuses the request with `503`. |
| `MATTSTASH_ACCESS_LOG_MAX_BYTES` | `10485760` | Rotate the access log file at this size (10 MiB; 1 KiB-1 GiB). |
| `MATTSTASH_ACCESS_LOG_BACKUPS` | `10` | Rotated access log files to keep (1-100). |
| `MATTSTASH_MIN_KEY_LENGTH` | `32` | Minimum length of plaintext keys (8-256). Startup fails on weaker keys. |
| `MATTSTASH_REQUIRE_SCOPED_KEYS` | `false` | Refuse to start if any legacy full-access key is configured. |
| `MATTSTASH_ALLOW_WRITES` | `false` | Enable `POST`/`DELETE`. Otherwise they return `405`. |
| `MATTSTASH_RATE_LIMIT` | `100/minute` | Per-client, **per-route** limit for read endpoints (writes: 30/min, admin: 10/min). |
| `MATTSTASH_MAX_CONCURRENT_WRITES` | `8` | Writes allowed in flight at once (1-32); more get `503` + `Retry-After: 1` immediately. |
| `MATTSTASH_AUTH_FAIL_LIMIT` | `10` | Failed authentications allowed per client per window... |
| `MATTSTASH_AUTH_FAIL_WINDOW_SECONDS` | `60` | ...before the client is answered `429` (applies before auth, even to valid keys). |
| `MATTSTASH_TRUSTED_PROXY_HOPS` | `0` | Number of reverse proxies in front of the server (see [proxies](#throttling-limits-and-proxies)). |
| `MATTSTASH_MAX_REQUEST_BODY_BYTES` | `1048576` | Request body limit, enforced on the bytes actually received. |
| `MATTSTASH_DB_POLL_INTERVAL` | `5` | Seconds between checks for external database changes (`0` disables; reads also notice changes on their own). |
| `MATTSTASH_DISABLE_DOCS` | `false` | Hide `/api/v1/docs`, `/redoc` and `openapi.json`. |
| `MATTSTASH_REFUSE_SIDECAR` | `false` | Refuse to start if `.mattstash.txt` (or a `.mattstash.txt.bak-*` backup of it) sits next to the database; otherwise only a warning. |
| `MATTSTASH_HOST` / `MATTSTASH_PORT` | `0.0.0.0` / `8000` | Bind address. |
| `MATTSTASH_TLS_CERT_FILE` / `MATTSTASH_TLS_KEY_FILE` | - | Serve HTTPS directly (both or neither). |
| `MATTSTASH_LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warning`, `error`, `critical`). |

## Starting the server

```bash
python -m app          # honours MATTSTASH_HOST/PORT/LOG_LEVEL and the TLS variables
```

At startup the server validates the configuration, loads the key policy and **opens the database**. A wrong
password, a missing file, a weak key or a malformed policy stops the process with a clear message (secrets are
never printed), so a bad deployment fails visibly instead of answering errors on the first request.

## Read-only by default

Without `MATTSTASH_ALLOW_WRITES=true` the server only reads. `POST`/`DELETE` answer `405 Method Not Allowed`
(`Allow: GET`) *after* authentication, so anonymous callers learn nothing about the mode. Typical flow: manage the
database with the CLI (`mattstash put/delete`, on a workstation or in a Job), ship the `.kdbx` to the server's
volume; the server notices the changed file and serves the new data without a restart.

With writes enabled:

- run **one** replica (use `strategy: Recreate` in Kubernetes);
- the data **directory** must be writable by the container user (a lock file `mattstash.kdbx.lock` and a temp
  file are created beside the database), not just the file;
- writes are serialised by a file lock and always applied to the latest on-disk state, so the CLI and the server
  can both write without overwriting each other; a failed write never leaves partial state behind.

## API keys and scopes

### Legacy keys (full access)

`MATTSTASH_API_KEY`, or a plain-text `MATTSTASH_API_KEYS_FILE` with one key per line (`#` comments allowed). Every
legacy key can read, write, delete and administer. They keep working so upgrades are non-breaking, but a warning is
logged at startup; set `MATTSTASH_REQUIRE_SCOPED_KEYS=true` once you have migrated.

### Scoped keys (v1 JSON policy, deprecated)

Deprecated in favour of [principals, tokens and grants](#principals-tokens-and-grants). The file still loads, each key
becomes a principal of kind `legacy`, and `mattstash admin migrate-keys --from <file> --policy-file <path>` converts it
into the policy file. Point `MATTSTASH_API_KEYS_FILE` at a JSON file:

```json
{
  "keys": [
    {"id": "billing", "key_sha256": "9f86d0...a08", "ops": ["read"], "prefixes": ["billing-"]},
    {"id": "deploy",  "key_sha256": "5e8848...d92", "ops": ["read", "write"]},
    {"id": "ops",     "key_sha256": "ef92b7...dc2", "ops": ["admin"]}
  ]
}
```

| Field | Meaning |
|-------|---------|
| `id` | Name shown in the audit log (`[A-Za-z0-9_.-]`, 1-64 chars, unique). |
| `key_sha256` **or** `key` | SHA-256 (hex) of the key - the file then holds no usable credentials - or the plaintext key. Exactly one. |
| `ops` | Any of `read` (get/list/versions/db-url), `write` (POST), `delete` (DELETE), `admin` (reload, key-cache invalidate). Default `["read"]`. |
| `prefixes` | Credential names the key may touch (`startswith`). Omit or `["*"]` for all names. |

A key file may contain `#` comment lines (also in JSON files) and a UTF-8 byte-order mark; a legacy key line must not
contain whitespace, and a JSON policy must not repeat a field. Generate keys with the helper; it prints the key once (to stderr) and the policy entry (to stdout):

```bash
python -m app.keytool --id billing --ops read --prefix billing- >> entries.json
echo -n "$EXISTING_KEY" | python -m app.keytool --id ci --ops read,write --stdin
```

Scope behaviour worth knowing:

- Reading a name outside the key's prefixes answers `404` with **exactly** the response for a name that does not
  exist, so a key cannot probe for names it is not allowed to see. Writes/deletes outside scope answer `403`.
- `GET /credentials` lists only names the key may read; a `?prefix=` filter can only narrow, never widen.
- Entries whose titles contain characters outside `[A-Za-z0-9_.-]` (for example created in KeePassXC) are not
  addressable through the API and are not listed.
- Keys shorter than `MATTSTASH_MIN_KEY_LENGTH` (plaintext only; hashes cannot be checked) are refused at startup.

### Rotation and revocation

Edit the file, then `POST /api/v1/admin/invalidate-api-key-cache` (needs an `admin` key) or wait up to 5 minutes.
Add the new key first, migrate clients, then remove the old key.

The endpoint reloads **immediately** and tells you whether it worked: `200 {"status": "api_key_cache_invalidated",
"keys": N}`, or `409` if the file could not be loaded (bad edit, unreadable). On `409` the **previous keys are still
active** - a key you meant to revoke may still work - so treat anything but `200` as "not revoked yet". Without the
endpoint, a failed periodic reload keeps the previous policy serving, logs the error, and retries every few seconds.

## Principals, tokens and grants

Every client is a **principal**: a named identity with one or more **tokens**. A token is sent in `X-API-Key` like an
old key, so existing clients need no change. Access is **default-deny**: a principal can do only what one of its
**grants** allows. There are no deny rules, so the order of grants does not matter.

- **Principal kinds:** `human-device` (a Mac), `agent` (an AI agent or MCP server), `runner` (CI, the Ansible host).
  Only a `human-device` principal may be an **admin**, and admin does not imply access to secrets.
- **Tokens** are `mst_<id>_<secret>`. The id is public (12 lowercase base32 characters) and is what the access log and
  revocation use. The secret is 256 random bits, stored only as a salted HMAC-SHA256. Expired, disabled, revoked and
  unknown tokens all answer the same `401`.
- **Grants** name a `key` pattern or a `tag` (a KeePass entry tag), a set of `actions` (`list`, `read`, `write`,
  `delete`; default `list,read`) and optionally `expires`. Patterns: `firefly` is exactly that name, `firefly.*` is
  every name starting with `firefly.` (so not `firefly-mcp`), and `*` is every name. Tag grants allow only `list` and
  `read`, because anyone who can write an entry can change its tags.
- The policy file is described in [Server Access Control](../../docs/configuration.md#server-access-control) (schema,
  permissions, writes and lockout protection). The design is in [design/principals-and-grants.md](../../docs/design/principals-and-grants.md).

### What each route needs

Paths are relative to `/api/v1`. An ungranted read is answered exactly as for a missing name, so a client cannot tell
"not granted" from "does not exist". Writes and admin calls answer `403` instead.

| Route | Needs | When denied |
|-------|-------|-------------|
| `GET /credentials` | `list` on each entry | Entries without `list` are left out; the request is still `200`. |
| Fields of a listed entry (username, URL, notes, value) | `read` | The entry carries only `name` and `version`; the other fields are `null`, the password is `*****`. |
| `GET /search?q=&tag=` | `list` on each result | Filtered per entry. Matches names (case-insensitive substring) and tags only; never notes or values; returns names and tags only. |
| `GET /credentials/{name}`, `GET /credentials/{name}/versions` | `read` | `404 Credential not found: <name>`, as for a missing name. |
| `GET /db-url/{name}` | `read` | `404 Credential not found or unsuitable: <name>`. |
| `POST /credentials/{name}` | `write` | `403 Insufficient permissions`, before the database is touched. |
| `DELETE /credentials/{name}` | `delete` | `403`, as above. |
| `/admin/*` | an admin principal | `403 Insufficient permissions`. |

`list` and `read` are independent: a principal with only `read` on `firefly.*` can fetch `firefly.token` by name but does
not see it in `GET /credentials`.

### Admin API

Admin routes need an admin token. Mutations are limited to 30 requests per minute, reads to 60. After each successful
change the server reloads its policy at once.

| Method and path | Purpose |
|-----------------|---------|
| `GET /admin/principals` | List principals, with their tokens (never hashes). Legacy principals appear with `"legacy": true`. |
| `POST /admin/principals` | Create: `{"name", "kind", "description"?, "admin"?}` → `201`. |
| `GET /admin/principals/{name}` | One principal, with its grants. |
| `PATCH /admin/principals/{name}` | Change `disabled`, `admin` or `description`. |
| `DELETE /admin/principals/{name}` | Remove the principal with its tokens and grants: `{"detail", "grants_removed"}`. |
| `GET /admin/principals/{name}/tokens` | List tokens (ids and expiry, never secrets). |
| `POST /admin/principals/{name}/tokens` | Issue: `{"expires"?, "description"?}` → `201` with `"token"`, shown once. The response is `Cache-Control: no-store`. |
| `DELETE /admin/principals/{name}/tokens/{token_id}` | Revoke a token now. |
| `POST /admin/principals/{name}/tokens/{token_id}/rotate` | Issue a replacement and retire the old one: `{"grace"?, "expires"?, "description"?}` → `201` with `"token"` and `old_token_expires`. |
| `GET /admin/grants?principal=` | List grants. |
| `POST /admin/grants` | Create: `{"principal", "key" or "tag", "actions"?, "expires"?, "description"?}` → `201`. |
| `DELETE /admin/grants/{grant_id}` | Remove a grant. |
| `POST /admin/check` | Explain a decision: `{"principal", "action", "name", "tags"?}` → `{"allowed", "reason", "grant"}`. |
| `GET /admin/access-log?principal=&decision=&since=&limit=` | Read the access log: `decision` is `allowed` or `denied`, `since` a duration (`24h`) or a time, `limit` 1 to 1000 (default 100). Returns `{"records", "count"}`. |
| `POST /admin/reload`, `POST /admin/invalidate-api-key-cache` | Reload the policy and legacy keys now (unchanged; now needs an admin principal). |

Errors from the admin API: `400` with the validation message (never a token or a hash), `404` with
`Principal not found: <name>`, `Token not found: <id>` or `Grant not found: <id>`, `409` when the policy file is
read-only (edit it, then call `POST /admin/invalidate-api-key-cache`), `503` when `MATTSTASH_POLICY_FILE` is not set (or,
for `GET /admin/access-log`, when `MATTSTASH_ACCESS_LOG_FILE` is not set).

The CLI wraps these routes: see [`mattstash admin`](../../docs/cli-reference.md#admin---principals-tokens-grants-and-the-access-log).

### Legacy keys and migration

`MATTSTASH_API_KEY`, a plain `MATTSTASH_API_KEYS_FILE` and the v1 JSON key policy still work. Each legacy source is a
principal of kind `legacy` (`legacy-env`, `legacy-1`, ...; a v1 key is named after its `id`), so nothing breaks on
upgrade. They are deprecated: the server logs a startup warning per source, answers requests authenticated by a legacy
key with `Deprecation: true`, and records `"kind":"legacy"` in the access log. Find the callers there, move them to a
principal token, then remove the key. A v1 JSON policy is converted with `mattstash admin migrate-keys --from <file>
--policy-file <path>`; the converted keys keep working, with their digests stored as `sha256:<hex>`. Plain sources are
planned for removal (proposed for 0.4). The step-by-step migration is in [section 12 of the design](../../docs/design/principals-and-grants.md#12-migration-guide).

## Throttling, limits and proxies

Authentication happens in the outermost layer, before the application (and before any request body is read):

- Everything except the probes (`/health`, `/ready`, also under `/api`) and the API docs needs a valid key; an
  unknown path without a key is `401`, so nothing about the API is revealed to anonymous callers.
- **Failed authentication** is throttled per client *before* the key is even looked at: after
  `MATTSTASH_AUTH_FAIL_LIMIT` failures within `MATTSTASH_AUTH_FAIL_WINDOW_SECONDS` every request from that client
  that needs a key gets `429` with `Retry-After`, even with a valid key. The check and the failure record are atomic,
  so a burst of concurrent requests cannot exceed the limit. Only failures count and a valid key never resets the
  counter. The **probes are exempt**, so a blocked address (for example an ingress shared by everyone) cannot fail
  the pod's own health checks. Use long random keys regardless: `openssl rand -base64 32`.
- **Rate limits** apply per client **and per route** (all `GET /credentials/{name}` requests share one bucket, however
  many different names they use; `POST` and `DELETE` each have their own bucket, as do list and versions) to authenticated endpoints (`MATTSTASH_RATE_LIMIT` for reads; the
  value is validated at startup, a malformed one stops the server). A `429` carries `Retry-After`; the CLI honours it
  and retries rate-limited `GET`s (`mattstash env`/`exec` fetch one secret per request: with more secrets than the
  limit they take a minute or more, or raise `MATTSTASH_RATE_LIMIT`).
- **Concurrent writes.** Every write waits for the database's cross-process lock inside a worker thread. At most
  `MATTSTASH_MAX_CONCURRENT_WRITES` are admitted; the rest are answered `503` + `Retry-After: 1` at once, so a stuck
  lock holder (a hung CLI, a stalled network volume) cannot use up every worker thread and take reads and `/ready`
  down with it.
- **Request bodies** above `MATTSTASH_MAX_REQUEST_BODY_BYTES` are refused with `413`, including chunked uploads
  (counted as they arrive). Unauthenticated requests are answered `401` without their body being read or parsed.
- **Client identity.** By default the TCP peer address is used; it cannot be spoofed. IPv4 clients are tracked per
  address and IPv6 clients per **/64** (one subscriber normally controls a whole /64); IPv4-mapped IPv6 addresses
  count as the IPv4 address. Behind a reverse proxy / ingress every request appears to come from the proxy, so one
  attacker could lock out everybody. Set `MATTSTASH_TRUSTED_PROXY_HOPS=N` (N = number of proxies you control) and the
  address is taken from the `X-Forwarded-For` entry N positions from the right (`1.2.3.4`, `1.2.3.4:5555`,
  `[2001:db8::1]:443` and `2001:db8::1` are all understood); entries further left are client-controlled and
  ignored. Only set this when the proxy overwrites/appends the header and the server is not reachable except through
  it. Shared-address lock-out is otherwise inherent to per-address throttling: size `AUTH_FAIL_LIMIT` for your topology.

## Health and readiness

| Path | Purpose |
|------|---------|
| `GET /health`, `GET /api/health` | **Liveness.** `200` while the process serves requests. Never touches the database. |
| `GET /ready`, `GET /api/ready` | **Readiness.** `200` only if the database can be read; otherwise `503 {"detail": "Not ready"}` (no details). |

No authentication is required. Use `/health` for liveness probes and Docker `HEALTHCHECK`, `/ready` for readiness.

## Errors

| Status | Meaning |
|--------|---------|
| `400` | Invalid name/prefix/driver/dialect or invalid credential data. `db-url` says why the entry cannot produce a URL (no port, no database name, unsupported dialect, ...) without echoing anything stored in it. |
| `401` | Missing or invalid API key. |
| `403` | Key lacks the operation or the name is outside its prefixes (writes). |
| `404` | Secret not found (or outside the key's scope, for reads). |
| `405` | Server is read-only. |
| `409` | `invalidate-api-key-cache`: the key source could not be loaded; the previous keys are still active. |
| `413` | Body too large. |
| `422` | Request body/query failed validation. The body lists only `loc`, `msg`, `type` - submitted values (secrets) are never echoed. |
| `429` | Too many failed authentications, or rate limit exceeded (`Retry-After` says when to retry). |
| `503` | The database cannot be opened or locked (wrong password, missing/corrupt file, lock timeout; `Retry-After: 5`), too many writes in flight (`Retry-After: 1`), or `POST /admin/reload` failed. **Never** reported as `404`. |
| `500` | Unexpected error; the body never contains details, only the exception type is logged. |

## Logging and audit trail

The server writes to **stderr** with a timestamp (uvicorn's own anonymous access log is turned off):

- **Access log** (`MATTSTASH_ACCESS_LOG_FILE`, described in [Principals, tokens and grants](#principals-tokens-and-grants)):
  one JSON object per request, with the principal, kind, token id, action, key, decision, grant and status. It is written
  to stdout by default and, when the file variable is set, to that file too.
- **Access log** (`mattstash.api`, level from `MATTSTASH_LOG_LEVEL`, default `info`):
  `METHOD /path -> status (duration) client=<ip> key=<id>`. No query string.
- **Audit log** (`mattstash.audit`, **always INFO**, not affected by `MATTSTASH_LOG_LEVEL`): one line per
  get/list/versions/put/delete/db-url/admin action *and* per denied request:
  `audit key=<id> ip=<ip> action=get name=<credential> reveal=True version=...`,
  `audit key=app ip=... action=denied name=other op=read`.
- Keys, secrets and request bodies are never logged; failed authentications show `key=-` and the client address.
  Everything that comes from the request (path, names) is escaped to printable ASCII (`\x0a` for a newline), so a
  client cannot forge log lines.
- Legacy keys appear as `legacy-env` (from `MATTSTASH_API_KEY`) or `legacy-1`, `legacy-2`... (file order); the id is
  never derived from the key.

## TLS

Either terminate TLS at a reverse proxy/ingress (recommended when you have one) or let the server do it:

```bash
MATTSTASH_TLS_CERT_FILE=/certs/tls.crt MATTSTASH_TLS_KEY_FILE=/certs/tls.key python -m app
```

Without TLS the API key travels in clear text. That is acceptable on a private container network but not across
untrusted networks. The CLI warns when pointed at a plain `http://` URL on a non-loopback host (or through an HTTP proxy).

## Upgrading from 0.1.x

| Change | Action |
|--------|--------|
| The server no longer creates a database. | Create it first: `mattstash setup --password-file ...`. |
| Read-only by default. | Set `MATTSTASH_ALLOW_WRITES=true` (and a writable data directory, single replica) if you use `POST`/`DELETE`. |
| Keys must be at least 32 characters. | Rotate weak keys (`openssl rand -base64 32`) or lower `MATTSTASH_MIN_KEY_LENGTH`. |
| Legacy keys still work but warn. | Move to a scoped policy; then set `MATTSTASH_REQUIRE_SCOPED_KEYS=true`. |
| Database errors are `503`, not `404`. | Update clients that treated `404` as "maybe the DB is down". |
| `GET /credentials` returns one row per credential (latest version) with base names. | Use `/credentials/{name}/versions` for history. |
| `DELETE` removes all versions; `?version=N` removes one. | - |
| Health at `/health` (and still `/api/health`); new `/ready`. | Point Kubernetes probes at them. |
| Rate limits are per route (they used to be per URL, so they limited nothing that takes a `{name}`). | Check `MATTSTASH_RATE_LIMIT` against what your clients do (`mattstash env --prefix` makes one request per secret). |
| `POST /admin/reload` answers `503` when the reload failed (it used to answer `200 no_change`). | Treat anything but `200` as "still serving the previous state". |
| `GET /db-url/{name}` accepts `dialect` (`postgresql`, `mysql`, `mariadb`) and an optional `driver` (`""` = no suffix). | - |
| A Secret volume that is updated (kubelet retargets `..data`) is picked up by the running server. | No restart needed; this works since 0.2. Mount the volume as a **directory**: a single-file bind mount (`-v file:file`, `subPath`) cannot be replaced atomically and is not supported. |
| Start with `python -m app`. | `uvicorn app.main:app` still works but cannot serve TLS. |
