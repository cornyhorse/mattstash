# MattStash server configuration

Everything is configured through environment variables. Secrets (database password, API keys) can and should be
supplied as **files** (`KDBX_PASSWORD_FILE`, `MATTSTASH_POLICY_FILE`) from a mount that is *separate* from the data
volume holding the `.kdbx`. The server's 0.2 key settings were removed in 0.3 (see [Removed key settings](#removed-key-settings)).

## Contents

- [Quick reference](#quick-reference)
- [Starting the server](#starting-the-server)
- [Read-only by default](#read-only-by-default)
- [Removed key settings](#removed-key-settings)
- [Principals, tokens and grants](#principals-tokens-and-grants)
- [Throttling, limits and proxies](#throttling-limits-and-proxies)
- [Health and readiness](#health-and-readiness)
- [Errors](#errors)
- [Logging and audit trail](#logging-and-audit-trail)
- [TLS](#tls)
- [Upgrading from 0.1.x](#upgrading-from-01x)
- [Upgrading to 0.3](#removed-key-settings) (see [docs/upgrading-to-0.3.md](../../docs/upgrading-to-0.3.md))

## Quick reference

| Variable | Default | Meaning |
|----------|---------|---------|
| `MATTSTASH_DB_PATH` | `/data/mattstash.kdbx` | The KeePass database. **Must already exist**; the server never creates one (`mattstash setup`). |
| `KDBX_PASSWORD` / `KDBX_PASSWORD_FILE` | - | Database master password (one is required). The sidecar file is *not* read by the server. |
| `MATTSTASH_POLICY_FILE` | - (**required**) | JSON policy of principals, tokens and grants. The server does not start without it, or when it holds no usable credential. The admin API answers `503` without it. Keep it off the data volume; mount its directory (writable if the admin API should change it). |
| `MATTSTASH_ACCESS_LOG_FILE` | - | Also write the access log (JSON lines) to this file, created `0600`. Unset: stdout only. A failed write refuses the request with `503` unless `MATTSTASH_ACCESS_LOG_FAIL_OPEN` is set. |
| `MATTSTASH_ACCESS_LOG_FAIL_OPEN` | `false` | `true`: a failed access-log file write is logged as an error and the request proceeds (the stdout line is still written, marked `"error":"access-log-write-failed"`). `/ready` and `/api/ready` answer `503` while the file sink is failing, in both modes. |
| `MATTSTASH_ALLOW_SLASH_NAMES` | `false` | `true`: names may contain `/` (`cloud/hetzner/s3-key`) and are addressed by path (see [Names with a slash](#names-with-a-slash)). Off: a `/` in a name is a `404`, as before. Set the same variable on clients that write such names. |
| `MATTSTASH_ACCESS_LOG_MAX_BYTES` | `10485760` | Rotate the access log file at this size (10 MiB; 1 KiB-1 GiB). |
| `MATTSTASH_ACCESS_LOG_BACKUPS` | `10` | Rotated access log files to keep (1-100). |
| `MATTSTASH_MIN_KEY_LENGTH` | `32` | Shortest existing key that `token import` accepts through the admin API (8-256; the import itself never goes below 16). |
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

At startup the server validates the configuration, loads the policy file and **opens the database**. A wrong
password, a missing file, a missing or unusable policy, a malformed policy, or one of the removed settings
(`MATTSTASH_API_KEY`, `MATTSTASH_API_KEYS_FILE`, `MATTSTASH_REQUIRE_SCOPED_KEYS`) being set stops the process with a
clear message (secrets and values are never printed), so a bad deployment fails visibly instead of answering errors on
the first request. An *empty* variable counts as not set.

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

## Removed key settings

In 0.3 the server stopped accepting its 0.2 keys: `MATTSTASH_API_KEY`, `MATTSTASH_API_KEYS_FILE` (a plain list or a v1
JSON key policy) and `MATTSTASH_REQUIRE_SCOPED_KEYS` are removed, not deprecated. If one of them is set, startup fails and
the message names the variable, never its value. The `keytool` helper, the `legacy` principal kind and the `Deprecation`
response header are gone too. Every credential is now a token of a principal with grants.

The move is described in [docs/upgrading-to-0.3.md](../../docs/upgrading-to-0.3.md): `mattstash admin token import`
stores each existing key as a token so clients keep working, and `mattstash admin migrate-keys` converts a v1 JSON key
policy into principals.

## Principals, tokens and grants

Every client is a **principal**: a named identity with one or more **tokens**. A token is sent in `X-API-Key` like an
old key, so existing clients need no change. Access is **default-deny**: a principal can do only what one of its
**grants** allows. There are no deny rules, so the order of grants does not matter.

- **Principal kinds:** `human-device` (a Mac), `agent` (an AI agent or MCP server), `runner` (CI, the Ansible host).
  Only a `human-device` principal may be an **admin**, and admin does not imply access to secrets.
  Only a `human-device` principal may hold the `*` grant.
- **Tokens** are `mst_<id>_<secret>`. The id is public (12 lowercase base32 characters) and is what the access log and
  revocation use. The secret is 256 random bits, stored only as a salted HMAC-SHA256. Expired, disabled, revoked and
  unknown tokens all answer the same `401`. A token imported from an existing key (`token import`) is stored as an
  unsalted `sha256:` hash and is warned about at startup until it is rotated to an `mst_` token.
- **Grants** name a `key` pattern or a `tag` (a KeePass entry tag), a set of `actions` (`list`, `read`, `write`,
  `delete`; default `list,read`) and optionally `expires`. Patterns: `firefly` is exactly that name, `firefly.*` is
  every name starting with `firefly.` (so not `firefly-mcp`), and `*` is every name. `*` is refused for an `agent` or
  `runner` principal (in the policy file, the CLI and the admin API), so a client gets explicit prefixes. Tag grants allow
  only `list` and `read`, because anyone who can write an entry can change its tags.
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
| `GET /credentials/{name}`, `GET /credentials/{name}/versions`, `GET /versions/{name}` | `read` | `404 Credential not found: <name>`, as for a missing name. |
| `GET /db-url/{name}` | `read` | `404 Credential not found or unsuitable: <name>`. |
| `POST /credentials/{name}` | `write` | `403 Insufficient permissions`, before the database is touched. |
| `DELETE /credentials/{name}` | `delete` | `403`, as above. |
| `/admin/*` | an admin principal (a `human-device`) | `403 Insufficient permissions`. |

`list` and `read` are independent: a principal with only `read` on `firefly.*` can fetch `firefly.token` by name but does
not see it in `GET /credentials`.

### Names with a slash

Off by default: a name containing `/` is a `404` on every route and is not listed. With `MATTSTASH_ALLOW_SLASH_NAMES=true`
(on the server, and on any CLI or library that writes such names) names like `cloud/hetzner/s3-key` work:

- `GET`, `POST`, `DELETE /api/v1/credentials/{name:path}` and `GET /api/v1/db-url/{name:path}` take the whole rest of the
  path as the name. A literal `/` and `%2F` route the same way.
- `GET /api/v1/versions/{name:path}` lists versions. `GET /api/v1/credentials/{name}/versions` keeps working for names
  without `/`; for a name with `/` it is ambiguous (`/credentials/a/versions` is the versions of `a`, never of `a/versions`),
  so use `/versions/a/versions`. The CLI does this for any name that contains `/`.
- A name must not start or end with `/`, contain `//` or have a `.` or `..` segment (`400 Invalid credential name`).
  Other characters are as before (`A-Za-z0-9_.-`).
- Grants, list and search treat the name as a plain string: `cloud/*` matches `cloud/x` and not `cloud` or `cloudx/y`. A
  read the principal may not make is the same `404` as a missing name.
- `?prefix=cloud/` filters the list.

### Admin API

Admin routes need an admin token. Mutations are limited to 30 requests per minute, reads to 60. After each successful
change the server reloads its policy at once.

| Method and path | Purpose |
|-----------------|---------|
| `GET /admin/principals` | List principals, with their tokens (never hashes). |
| `POST /admin/principals` | Create: `{"name", "kind", "description"?, "admin"?}` → `201`. |
| `GET /admin/principals/{name}` | One principal, with its grants. |
| `PATCH /admin/principals/{name}` | Change `disabled`, `admin` or `description`. |
| `DELETE /admin/principals/{name}` | Remove the principal with its tokens and grants: `{"detail", "grants_removed"}`. |
| `GET /admin/principals/{name}/tokens` | List tokens (ids and expiry, never secrets). |
| `POST /admin/principals/{name}/tokens` | Issue: `{"expires"?, "description"?}` (the body may be omitted) → `201` with `"token"`, shown once. The response is `Cache-Control: no-store`. |
| `POST /admin/principals/{name}/tokens/import` | Store an existing key as a token: `{"key": "...", "description"?, "expires"?, "min_length"?}` → `201 {"id", "expires"}`. The key is never returned or logged; a key in `mst_` format or one another token holds is refused. |
| `DELETE /admin/principals/{name}/tokens/{token_id}` | Revoke a token now. |
| `POST /admin/principals/{name}/tokens/{token_id}/rotate` | Issue a replacement and retire the old one: `{"grace"?, "expires"?, "description"?}` (the body may be omitted; `grace` is a relative duration such as `24h`, never a date) → `201` with `"token"` and `old_token_expires`. |
| `GET /admin/grants?principal=` | List grants. |
| `POST /admin/grants` | Create: `{"principal", "key" or "tag", "actions"?, "expires"?, "description"?}` → `201`. |
| `DELETE /admin/grants/{grant_id}` | Remove a grant. |
| `POST /admin/check` | Explain a decision: `{"principal", "action", "name", "tags"?}` → `{"allowed", "reason", "grant"}`. |
| `GET /admin/access-log?principal=&decision=&since=&limit=` | Read the access log: `decision` is `allowed` or `denied`, `since` a duration (`24h`) or a time, `limit` 1 to 1000 (default 100). Returns `{"records", "count"}`. |
| `POST /admin/reload`, `POST /admin/invalidate-api-key-cache` | Reload the policy now. Both need an admin principal. |

Empty query values (`?principal=`, `?decision=`, `?since=`) mean "not given". A grant's `expires` must be in the future,
like a token's. A change is checked before it is saved: the server builds the complete state from the edited policy
(exactly as the loader would, name checks included), and a change that would leave a policy it cannot load is answered
`409 {"detail": "The change would leave a policy the server cannot load: <reason>"}` with nothing written. A `*` grant for
an `agent` or `runner` is answered `400`.

Errors from the admin API: `400` with the validation message (never a token or a hash), `404` with
`Principal not found: <name>`, `Token not found: <id>` or `Grant not found: <id>`, `409` when the policy file is
read-only (edit it, then call `POST /admin/invalidate-api-key-cache`) or when the change would leave a policy the server
cannot load, `503` when `MATTSTASH_POLICY_FILE` is not set (or, for `GET /admin/access-log`, when
`MATTSTASH_ACCESS_LOG_FILE` is not set).

**Early warning.** When every usable admin token expires within 14 days, the server logs a warning at startup and after
each policy load (`admin_expiry_warning`). The lockout rule itself looks one hour ahead.

**A change that is saved but cannot be activated.** After every change the server reloads the policy. If that
reload fails (because of a race or an I/O error, since the change was checked before it was saved) the change is already
in the policy file but the previous policy is still in force. Changes that take access away (revoking a token, disabling or removing a principal, `admin:
false`, removing a grant) then answer `409 {"detail": "Saved to the policy file but NOT active: the server could not
reload its key sources (see the server log). The previous policy is still in force."}`, so nobody believes a token is
revoked while it still works; fix the source and call `POST /admin/invalidate-api-key-cache`. Other
changes (adding a principal or grant, issuing or rotating a token, enabling, a description) answer normally, with a `"warning"` of
the same text in the body and the header `X-Policy-Active: false`; an issued or rotated token is still in the response (a rotation is not refused, because its new token is shown only
once; the old token keeps working until the reload succeeds).

The CLI wraps these routes: see [`mattstash admin`](../../docs/cli-reference.md#admin---principals-tokens-grants-and-the-access-log).

### Migrating from 0.2

Remove the three settings from the server's environment and set `MATTSTASH_POLICY_FILE`; then, for each client, either
`mattstash admin token import` (the client keeps its existing key) or `mattstash admin token issue` (a new `mst_` token).
A v1 JSON key policy is converted with `mattstash admin migrate-keys --from <file> --policy-file <path> [--kind ...]`,
which creates non-admin principals. The steps are in [docs/upgrading-to-0.3.md](../../docs/upgrading-to-0.3.md).

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
| `GET /ready`, `GET /api/ready` | **Readiness.** `200` only if the database can be read and, when `MATTSTASH_ACCESS_LOG_FILE` is set, the file can be written; otherwise `503 {"detail": "Not ready"}` (no details). |

No authentication is required. Use `/health` for liveness probes and Docker `HEALTHCHECK`, `/ready` for readiness.

## Errors

| Status | Meaning |
|--------|---------|
| `400` | Invalid name/prefix/driver/dialect or invalid credential data. `db-url` says why the entry cannot produce a URL (no port, no database name, unsupported dialect, ...) without echoing anything stored in it. |
| `401` | Missing or invalid token. |
| `403` | The principal lacks the operation (writes, admin). |
| `404` | Secret not found (or outside the principal's grants, for reads). |
| `405` | Server is read-only. |
| `409` | `invalidate-api-key-cache`: the policy could not be loaded; the previous policy is still active. Admin API: the policy file is read-only, the change would leave a policy the server cannot load (nothing saved), or an access-reducing change was saved but could not be activated (see above). |
| `413` | Body too large. |
| `422` | Request body/query failed validation. The body lists only `loc`, `msg`, `type` - submitted values (secrets) are never echoed. |
| `429` | Too many failed authentications, or rate limit exceeded (`Retry-After` says when to retry). |
| `503` | The database cannot be opened or locked (wrong password, missing/corrupt file, lock timeout; `Retry-After: 5`), too many writes in flight (`Retry-After: 1`), `POST /admin/reload` failed, or the access log file cannot be written (the request is refused, and a write, delete or admin change is not carried out). **Never** reported as `404`. |
| `500` | Unexpected error; the body never contains details, only the exception type is logged. |

## Logging and audit trail

The server writes to **stderr** with a timestamp (uvicorn's own anonymous access log is turned off):

- **Access log** (logger `mattstash.access`): one JSON object per request, always on stdout (what `docker logs` and
  Kubernetes collect) and, when `MATTSTASH_ACCESS_LOG_FILE` is set, also appended to that rotating file (mode 0600;
  `MATTSTASH_ACCESS_LOG_MAX_BYTES` default 10 MiB x `MATTSTASH_ACCESS_LOG_BACKUPS` default 10). It replaces the old
  `mattstash.audit` log lines. It is what `GET /admin/access-log` and `mattstash admin log` read. Health probes and the
  API docs are not logged.
- **Request log** (`mattstash.api`, level from `MATTSTASH_LOG_LEVEL`, default `info`):
  `METHOD /path -> status (duration) client=<ip> key=<principal>`. No query string.

Fields of an access-log line (absent when not applicable):

| Field | Meaning |
|-------|---------|
| `ts`, `client` | UTC time (`...Z`) and the client address. |
| `principal`, `kind`, `token` | Who: the principal, its kind (`human-device`, `agent` or `runner`) and the public id of the token. `-` for a failed login. |
| `action`, `route` | `list`, `read`, `write`, `delete` or `admin`, and the route (`get`, `versions`, `db-url`, `list`, `search`, `put`, `delete`, `admin.token.rotate`, ...). |
| `key` | The credential name; for list the `prefix` filter, for search the `q` filter (these filters are logged); for admin calls the principal (or grant id) concerned. |
| `tag` | The `tag` filter of a search. |
| `decision`, `reason`, `grant` | `allowed` or `denied`; why (`no-grant`, `not-admin`, `disabled`, `unknown-token`, `bad-token`, `expired-token`, `no-token`, `throttled`, `auth-unavailable`); the grant that allowed it. Absent for a request rejected before an authorization decision (bad name, unknown route, read-only 405, 413, unparsable body 422). |
| `count` | Entries returned by list or search. |
| `reveal` | `true` when a secret value was returned: `show_password=true` on get or list, `mask_password=false` on db-url. |
| `version` | The version asked for with `?version=`. |
| `target_token` | Admin: id of the token being revoked or rotated (the old one). |
| `grant_key`, `grant_tag`, `actions` | Admin: the pattern or tag and the actions of a grant being added. |
| `status` | The HTTP status. **Absent on lines of state-changing requests** (see below). |
| `error` | `client-disconnected` (the client went away before the response; no `status`) or `access-log-write-failed` (the stdout copy of a line the file refused; `status` is 503). |

When the line is written:

- Reads, and requests rejected before a decision, are logged when the response starts, with its `status`.
- A **POST, PATCH, PUT or DELETE** that reaches an authorization decision is logged **at the decision, before anything
  is done**, so such a line has **no `status`**: it says what was decided, not what happened. A write, delete or admin
  change is only carried out once its line is written.
- **Fail closed:** with `MATTSTASH_ACCESS_LOG_FILE` set, a line that cannot be written (disk full, permissions) makes the
  server answer `503` instead. For a read nothing of the response is sent; for a state-changing request the handler
  never runs, so no credential is created or deleted, no token is minted and the policy file is untouched. The server
  log gets `Access log write failed`. If the file cannot even be opened at startup, the server does not start.
- **Opt-out:** with `MATTSTASH_ACCESS_LOG_FAIL_OPEN=true` the same failure is logged as an error (`Access log write failed`,
  no paths or secrets), the stdout line is still emitted with `"error":"access-log-write-failed"` and the request
  proceeds, so a full disk no longer stops the service but its audit trail has a gap in the file. In **both** modes
  `/ready` and `/api/ready` answer `503 {"detail": "Not ready"}` from the first failed write until a write succeeds
  (while it is failing, each probe retries the file with a small `access-log-probe` line), so monitoring sees it.
- Each request produces exactly one line.

Never logged: tokens or API keys, secret values, usernames, URLs, notes, descriptions or any other free text. Request bodies are not logged
as such: only the names, patterns and actions listed in the field table are. Failed authentications show
`principal` `-` and the client address. Everything that comes from the request (path, names, filters) is escaped to
printable ASCII (`\x0a` for a newline) and capped at 256 characters, so a client cannot forge log lines.
See [section 6 of the design](../../docs/design/principals-and-grants.md#6-access-log).

## TLS

Either terminate TLS at a reverse proxy/ingress (recommended when you have one) or let the server do it:

```bash
MATTSTASH_TLS_CERT_FILE=/certs/tls.crt MATTSTASH_TLS_KEY_FILE=/certs/tls.key python -m app
```

Without TLS the token travels in clear text. That is acceptable on a private container network but not across
untrusted networks. The CLI warns when pointed at a plain `http://` URL on a non-loopback host (or through an HTTP proxy).

## Upgrading from 0.1.x

| Change | Action |
|--------|--------|
| The server no longer creates a database. | Create it first: `mattstash setup --password-file ...`. |
| Read-only by default. | Set `MATTSTASH_ALLOW_WRITES=true` (and a writable data directory, single replica) if you use `POST`/`DELETE`. |
| Keys must be at least 32 characters. | Rotate weak keys (`openssl rand -base64 32`) or lower `MATTSTASH_MIN_KEY_LENGTH`. |
| Legacy keys still work but warn (0.2). | Removed in 0.3: see [docs/upgrading-to-0.3.md](../../docs/upgrading-to-0.3.md). |
| Database errors are `503`, not `404`. | Update clients that treated `404` as "maybe the DB is down". |
| `GET /credentials` returns one row per credential (latest version) with base names. | Use `/credentials/{name}/versions` for history. |
| `DELETE` removes all versions; `?version=N` removes one. | - |
| Health at `/health` (and still `/api/health`); new `/ready`. | Point Kubernetes probes at them. |
| Rate limits are per route (they used to be per URL, so they limited nothing that takes a `{name}`). | Check `MATTSTASH_RATE_LIMIT` against what your clients do (`mattstash env --prefix` makes one request per secret). |
| `POST /admin/reload` answers `503` when the reload failed (it used to answer `200 no_change`). | Treat anything but `200` as "still serving the previous state". |
| `GET /db-url/{name}` accepts `dialect` (`postgresql`, `mysql`, `mariadb`) and an optional `driver` (`""` = no suffix). | - |
| A Secret volume that is updated (kubelet retargets `..data`) is picked up by the running server. | No restart needed; this works since 0.2. Mount the volume as a **directory**: a single-file bind mount (`-v file:file`, `subPath`) cannot be replaced atomically and is not supported. |
| Start with `python -m app`. | `uvicorn app.main:app` still works but cannot serve TLS. |
