# MattStash server configuration

Everything is configured through environment variables. Secrets (database password, API keys) can and should be
supplied as **files** (`KDBX_PASSWORD_FILE`, `MATTSTASH_API_KEYS_FILE`) from a mount that is *separate* from the data
volume holding the `.kdbx`.

## Contents

- [Quick reference](#quick-reference)
- [Starting the server](#starting-the-server)
- [Read-only by default](#read-only-by-default)
- [API keys and scopes](#api-keys-and-scopes)
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
| `MATTSTASH_API_KEY` | - | A single *legacy* (full-access) key. |
| `MATTSTASH_API_KEYS_FILE` | - | Legacy key list **or** a JSON key policy (see below). |
| `MATTSTASH_MIN_KEY_LENGTH` | `32` | Minimum length of plaintext keys (8-256). Startup fails on weaker keys. |
| `MATTSTASH_REQUIRE_SCOPED_KEYS` | `false` | Refuse to start if any legacy full-access key is configured. |
| `MATTSTASH_ALLOW_WRITES` | `false` | Enable `POST`/`DELETE`. Otherwise they return `405`. |
| `MATTSTASH_RATE_LIMIT` | `100/minute` | Per-client limit for read endpoints (writes: 30/min, admin: 10/min). |
| `MATTSTASH_AUTH_FAIL_LIMIT` | `10` | Failed authentications allowed per client per window... |
| `MATTSTASH_AUTH_FAIL_WINDOW_SECONDS` | `60` | ...before the client is answered `429` (applies before auth, even to valid keys). |
| `MATTSTASH_TRUSTED_PROXY_HOPS` | `0` | Number of reverse proxies in front of the server (see [proxies](#throttling-limits-and-proxies)). |
| `MATTSTASH_MAX_REQUEST_BODY_BYTES` | `1048576` | Request body limit, enforced on the bytes actually received. |
| `MATTSTASH_DB_POLL_INTERVAL` | `5` | Seconds between checks for external database changes (`0` disables; reads also notice changes on their own). |
| `MATTSTASH_DISABLE_DOCS` | `false` | Hide `/api/v1/docs`, `/redoc` and `openapi.json`. |
| `MATTSTASH_REFUSE_SIDECAR` | `false` | Refuse to start if `.mattstash.txt` (or a `.mattstash.txt.bak-*` backup of it) sits next to the database; otherwise only a warning. |
| `MATTSTASH_HOST` / `MATTSTASH_PORT` | `0.0.0.0` / `8000` | Bind address. |
| `MATTSTASH_TLS_CERT_FILE` / `MATTSTASH_TLS_KEY_FILE` | - | Serve HTTPS directly (both or neither). |
| `MATTSTASH_LOG_LEVEL` | `info` | Log level. |

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

### Scoped keys (recommended)

Point `MATTSTASH_API_KEYS_FILE` at a JSON file:

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
- **Rate limits** apply per client to authenticated endpoints (`MATTSTASH_RATE_LIMIT` for reads; the value is
  validated at startup, a malformed one stops the server).
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
| `400` | Invalid name/prefix/driver or invalid credential data. |
| `401` | Missing or invalid API key. |
| `403` | Key lacks the operation or the name is outside its prefixes (writes). |
| `404` | Secret not found (or outside the key's scope, for reads). |
| `405` | Server is read-only. |
| `409` | `invalidate-api-key-cache`: the key source could not be loaded; the previous keys are still active. |
| `413` | Body too large. |
| `422` | Request body/query failed validation. The body lists only `loc`, `msg`, `type` - submitted values (secrets) are never echoed. |
| `429` | Too many failed authentications, or rate limit exceeded. |
| `503` | The database cannot be opened or locked (wrong password, missing/corrupt file, lock timeout). **Never** reported as `404`. `Retry-After: 5`. |
| `500` | Unexpected error; the body never contains details, only the exception type is logged. |

## Logging and audit trail

The server writes to **stderr** with a timestamp (uvicorn's own anonymous access log is turned off):

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
untrusted networks. The CLI warns when pointed at a plain `http://` URL on a non-loopback host.

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
| Start with `python -m app`. | `uvicorn app.main:app` still works but cannot serve TLS. |
