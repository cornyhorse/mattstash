# Design: principals, grants and the access log

Status: **phase 1, implemented in this PR** · Date: 2026-10-18 · Supersedes: the v1 scoped key policy
(`MATTSTASH_API_KEYS_FILE` as JSON, `server/app/security/api_keys.py`, H-3 in `docs/security-review.md`)

## 1. Problem

The server is becoming the main source of credentials for two Macs, several AI agents and an Ansible runner VM.
Today:

- A key either has full access (`MATTSTASH_API_KEY`, a plain keys file) or a v1 *scoped* key: a SHA-256 digest
  with `ops` (`read`/`write`/`delete`/`admin`) and raw string `prefixes`. There is no notion of *who* a key
  belongs to beyond an id, no expiry, no rotation story, no tags, `list` and `read` are the same permission, and
  a raw prefix `firefly` silently also matches `firefly-mcp`.
- The audit trail is a free-text log line mixed into the server log, so you can't easily answer "what did the
  agent read last week?".
- Nothing distinguishes a human's laptop from an agent, so nothing stops an agent's key from being made an admin.

Phase 1 adds named **principals** with tokens, default-deny **grants**, and a structured **access log**. The 0.2
keys were kept working as deprecated principals in phase 1 and are **removed in 0.3** (§7). The decisions taken on the
open questions are in §11.

## 2. Ideas taken from OpenBao/Vault, and what was left out

| Vault idea | Taken? | How it shows up here |
| --- | --- | --- |
| Default deny; access only through explicit policy | yes | No grant, no access. There is no implicit "allow all" (0.2's full-access keys are removed, §7). |
| Path capabilities (`list`, `read`, `create`/`update`, `delete`) | yes, simplified | `list`, `read`, `write`, `delete`. `list` is separate from `read`, as in Vault. |
| Glob only at the end of a path (`secret/foo*`, `secret/foo/*`) | yes | `firefly.*` is a prefix match; `firefly` is an exact name; `*` alone is everything. No `+` segment wildcards. |
| Token *accessor*: a non-secret handle used to look up/revoke a token | yes | Every token has a public `token_id` embedded in it, used in logs, revocation and lookup. |
| Token TTLs | yes | Optional `expires` on tokens and on grants. No renewal/periodic tokens. |
| Audit device that never logs secrets | yes | One JSON line per request; values never logged. |
| Audit is fail-closed (no audit, no request) | yes | If the access-log file can't be written, the request is refused with 503. `MATTSTASH_ACCESS_LOG_FAIL_OPEN=true` opts out (decision 3, §11); `/ready` is 503 while the file is failing. |
| HMAC of request values in the audit log | no | We log no values at all, only names and decisions; nothing to HMAC. |
| Policies as named documents attached to tokens, entities/aliases, identity groups | no | One flat list of grants per principal. Groups can come later if the list grows. |
| Deny capability, `required_parameters`, `allowed_parameters`, control groups | no | Default deny with no explicit deny rules keeps evaluation order-independent. Control groups ≈ §10.3 (ntfy approvals), later. |
| Root token / unseal | no | The admin flag plays the role of root; unsealing stays the KDBX master password. |

## 3. Principals

A principal is a named identity that presents tokens.

```json
{
  "name": "hermes-finance",
  "kind": "agent",
  "description": "Hermes finance profile (MCP)",
  "admin": false,
  "disabled": false,
  "created": "2026-10-18T12:00:00Z",
  "tokens": [
    {"id": "k7m2q7xw4h3a", "hash": "hmac-sha256:9f0c…:4be1…", "created": "2026-10-18T12:00:00Z",
     "expires": "2027-01-18T00:00:00Z", "description": "initial"}
  ]
}
```

- **name**: `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`, unique without regard to case (so the log can't contain two
  principals that look alike).
- **kind**: `human-device` (a Mac), `agent` (an AI agent or MCP server), `runner` (the Ansible VM, CI). The kind
  limits what a principal may be given (below) and is in every log line.
- **admin**: may change principals, tokens and grants and read the access log. **Only `human-device`
  principals may be admins** (decision 1, §11). This is checked when the policy is loaded (an agent or runner with `admin: true`
  is a load error) and again when an admin request is authorised. Admin does *not* imply data access: an admin
  still needs grants to read secrets, although it could add them for itself.
- **disabled**: all tokens rejected, grants kept. Quick lockout without losing the setup.

### Tokens

Format: `mst_<token_id>_<secret>`

- `token_id`: 12 characters of lowercase base32 (60 bits), public, unique across the file. Like Vault's
  accessor, it is safe to log and to pass to `revoke`.
- `secret`: `secrets.token_urlsafe(32)` (256 bits). It may contain `_`, so the parser splits on the first two
  `_` only.
- The whole token is about 61 printable ASCII characters, so it passes the CLI's `api_key_problem` check and the
  server's `MATTSTASH_MIN_KEY_LENGTH`. Clients send it in `X-API-Key` exactly like an old key, so
  `--api-key-file` and `MATTSTASH_API_KEY` in client mode work unchanged.

**Hashing.** The file stores `hmac-sha256:<salt-hex>:<digest-hex>`, where the digest is
HMAC-SHA256(key = 16 random bytes of salt, message = the whole token). The hash is there so that someone who
reads the policy file can't use the tokens in it. A slow KDF (scrypt, Argon2) defends against guessing *low-entropy*
inputs; our tokens have 256 random bits, so offline guessing is already infeasible, and a slow hash would cost
~50 ms of CPU on **every** request (agents call often) or force a cache of verified tokens in memory. The per-token
salt means two policy files never share a hash. The scheme name is part of the stored value so it can change
later. One other scheme is accepted: `sha256:<hex>`, unsalted, only for keys imported with `token import` or
`migrate-keys` (§7). The server warns once at startup for each such token, until it is rotated to an `mst_` token.

**Verification** is constant time with respect to the secret:

1. Parse `mst_<id>_<secret>`. If the format doesn't match, the presented key is compared by digest with every
   `sha256:` token, in constant time and with no early exit (§7).
2. Look up `id`. The id is public, so a dictionary lookup is fine. If it's unknown, still compute one HMAC
   against a fixed dummy record, so unknown and wrong-secret take the same time.
3. `hmac.compare_digest` on the digests.
4. Then check expiry (`now >= expires` means expired), `disabled`, and that the principal still exists. An
   unknown, wrong, expired or disabled token all answer the same `401 Authentication failed`. Only the access
   log records which one it was (`reason`).

**Rotation.** `token issue` adds a token. A principal can hold several at once, so you can issue the new one,
deploy it, then `token revoke <id>`. `token rotate <principal> --grace 24h` does both in one step. It issues a new
token and sets the old one's `expires` to the earlier of its current expiry and now + grace (default 0, i.e.
immediately). `--grace` takes a relative duration only (`30m`, `24h`, `7d`, `2w`). A new token's `expires` must be
in the future.

The plaintext token is shown **once**, when it's issued (CLI stdout, or `--output-file` written with mode 0600).
It is never stored, logged or returned again.

## 4. Grants

```json
{"id": "g_3fd9a1c2", "principal": "hermes-finance", "key": "firefly.*", "actions": ["list", "read"],
 "expires": "2027-01-01T00:00:00Z", "description": "Firefly III tokens for the finance agent",
 "created": "2026-10-18T12:00:00Z"}
```

A grant has exactly one **selector**, either `key` (a name pattern) or `tag` (a KeePass tag). It has a non-empty
set of **actions** from `list`, `read`, `write`, `delete`, an optional **expires**, and a random **id** (`g_` + 8
hex) used for removal and shown in the log as the grant that allowed a request.

### 4.1 Evaluation

`allowed(principal, action, name, tags, now)` is true when at least one grant
- belongs to that principal, and the principal isn't disabled,
- is not expired (`now < expires`),
- includes the action, and
- matches the name (key selector) or the entry's tags (tag selector).

Otherwise the request is denied. Since there are no deny rules, the order of grants doesn't matter.

### 4.2 Key patterns

Matching is plain, case-sensitive string comparison of the pattern against the credential name as stored in
KeePass. There is no Unicode or case normalisation, no trimming, and the separators `.`, `/`, `-`, `_` get no special
treatment.

| Pattern | Matches | Doesn't match |
| --- | --- | --- |
| `firefly` | `firefly` | `firefly-mcp`, `firefly.token`, `Firefly` |
| `firefly.*` | `firefly.token`, `firefly.db.password` | `firefly`, `firefly-mcp` |
| `firefly*` | `firefly`, `firefly-mcp`, `firefly.token` (you asked for it) | `Firefly` |
| `firefly/*` | `firefly/token`, `firefly/` | `firefly`, `firefly.token` |
| `*` | everything | |

Validation, applied when a grant is created or loaded:
- `*` may appear only once, as the last character. `a*b`, `**`, `*a` are errors.
- The pattern `*` (every name) is only for `human-device` principals. An `agent` or `runner` with `*` is a validation
  error in the policy loader and in the editor, so the admin API answers `400` and the CLI refuses before sending
  (decision 5, §11). A prefix such as `a*` is still allowed for any kind.
- A pattern that ends in a separator (`.`, `/`, `-` or `_`) but has no `*` (`firefly/`, `firefly.`) is an error ("did you mean
  `firefly/*`?"), because an exact-name grant on a name ending in a separator is almost always a mistake.
- Printable ASCII only, no whitespace, at most 255 characters (the server's name limit).
- Patterns are not checked against the server's URL name rules. A pattern may contain `/` (titles can, see
  PR #16), and the HTTP API addresses such names when the server runs with `MATTSTASH_ALLOW_SLASH_NAMES=true`
  (`docs/security-review.md`, Q9).

**Why not keep raw prefixes?** A raw prefix is what v1 did, and it's how `firefly` ends up granting
`firefly-mcp`. Patterns make the reach explicit: `firefly.*` is a prefix ending in `*`, and `firefly` is one name.
v1 prefixes are converted to `<prefix>*`, which keeps their old meaning exactly (§7).

### 4.3 Tags: KeePass entry tags, not custom fields

Tag grants match KeePass **entry tags** (`entry.tags`), compared exactly and case-sensitively.

- Tags are native KeePass metadata. KeePassXC shows them, lets you filter by them and edit them, so you can
  maintain them without mattstash.
- The library already reads and writes them (`put --tag`, `Credential.tags`), so nothing new goes into the
  vault format.
- Custom fields hold *data* (`database`, `dialect`, `sslmode` for `db-url`). Mixing access control into that
  namespace invites collisions, and custom fields are free-form strings that can be protected (encrypted in
  memory), which complicates reading them for every listed entry.

Rules that keep tag grants safe:

- **Tags of the latest version decide** access to every version. Re-tagging an old version can't open it up.
- **Phase 1 tag grants allow only `list` and `read`.** `write` or `delete` on a tag grant is a load error.
  Anyone who can write an entry can change its tags, so a tag-based write grant would let a principal widen
  its own reach by tagging more entries. Writing still needs a key-pattern grant.
- Still, anyone with `write` on an entry controls its tags. A tag grant to principal B is therefore only as
  strong as the write grants over the tagged entries. This is documented as a caveat, and
  `mattstash admin check` shows which grant allowed an access.

### 4.4 What each action means, per route

| Route | Action needed | When denied |
| --- | --- | --- |
| `GET /credentials` (list) | `list` on each entry, else it's left out | Entries are filtered out. The request still answers 200. |
| ↳ fields of a listed entry | `read` on that entry for `username`/`url`/`notes`/value | Without `read`, the entry is returned with only `name` and `version`, other fields `null`, password `*****`. |
| `GET /search?q=&tag=` (new) | `list` on each result | Filtered. Searches names (case-insensitive substring) and tags only, never notes or values, and returns names and tags only. |
| `GET /credentials/{name}` | `read` | `404 Credential not found: <name>`, the same answer as a missing name. |
| `GET /credentials/{name}/versions` | `read` | 404, as above. |
| `GET /db-url/{name}` | `read` | `404 Credential not found or unsuitable: <name>`, as for a missing name. |
| `POST /credentials/{name}` | `write` (key-pattern grant) | `403 Insufficient permissions`, returned before the database is touched, so it doesn't reveal whether the name exists. |
| `DELETE /credentials/{name}` | `delete` (key-pattern grant) | 403, as above. |
| `/admin/*` | principal is an admin (only `human-device` principals can be) | 403. |

**No v1 admin-only keys.** The v1 `ops: ["admin"]` meaning (reload and invalidate only) went with the v1 keys in 0.3
(§7). Every admin route needs an admin principal, and `POST /admin/reload` and `POST /admin/invalidate-api-key-cache`
need one too.

`list` and `read` are independent. A principal with only `read` on `firefly.*` can fetch `firefly.token` by
name but won't see it in `list`, which is "need to know, but don't enumerate". The CLI's `grant add` defaults to
`list,read`.

"An agent can only see the names of keys it's been granted": list, search and the 404-for-denied rule all
follow from this.

## 5. Where users and rules live, and who can change them

**Recommendation: a JSON policy file, separate from every vault, read by the server and changed only by
an admin principal (through the admin API) or by someone with write access to the file on the host.**

`MATTSTASH_POLICY_FILE=/config/policy.json`, schema:

```json
{"version": 2, "revision": 17, "principals": [ … ], "grants": [ … ]}
```

| Option | For | Against | Verdict |
| --- | --- | --- | --- |
| **Policy file (JSON)** | Independent of any vault, so one policy can cover several vaults (§10.1). Readable and diffable. The existing loader, cache and reload already handle a file. No new dependency. | It's a file the server process can read. Hashes only, so reading it doesn't give anyone tokens. | **Chosen** |
| Separate admin vault (.kdbx) | Encrypted at rest | A second master password for the server to hold, so no gain against anyone who can read the server's environment. Harder to inspect and diff, and pykeepass makes every change cost about 0.5 s. | No |
| Entries inside the data .kdbx | One file | Whoever can write the vault (any principal with `write` on `*`, any KeePassXC user) can rewrite the policy. Ties the policy to one vault, which contradicts tiered vaults. | No |

**Why JSON and not YAML?** The file is written by tools (CLI and admin API) as well as read. PyYAML can't
round-trip comments, so YAML's main advantage disappears on the first write, and the library would gain a
dependency for its core path. Each record has a `description` field for the notes you'd otherwise put in comments.

**Unknown fields are a load error.** This is on purpose. A policy written for a newer server, for example
with a token bound to a Tailscale device (§10.2), must not load on an older server that would silently ignore
the restriction. `version` is checked for the same reason.

**Writing.** Admin API mutations and the CLI's local mode both:
- take an exclusive lock (`mattstash.utils.filelock`) and re-read the file from disk, never the cache,
- validate the whole new document,
- write a temporary file in the same directory (created 0600), `fsync`, give it the existing file's permission bits
  masked with `0640` (never world-accessible or executable) and, for root, its owner and group, then `os.replace` it.
  A symlinked policy path is resolved first, so the link survives. A new file is 0600,
- increment `revision`.

The server picks up changes from other writers by checking the file's mtime and size on each request (a
`stat`), plus the existing 300-second refresh. A broken edit keeps the previous policy and logs an error, which
is the existing behaviour. `POST /admin/invalidate-api-key-cache` reloads at once and reports failure. If the
file isn't writable (a Kubernetes ConfigMap or Secret), mutations answer `409 Policy file is read-only`. You
then edit the source and reload.

**Lockout protection.** A change that would leave no enabled admin principal with a valid token is refused. The rule
applies in local mode too, since the CLI sees the whole policy. That covers removing or disabling the last admin, revoking or
expiring its last token, and clearing its admin flag. It also looks an hour ahead: if before the change some
admin held a token that never expires or outlasts `now + 1h`, and after it every usable admin token expires within
the hour (say, rotating the only admin token with `--grace 1h` to a replacement that expires in a minute), the change
is refused. A policy that is already within the hour of lockout is not blocked from changing, since that is how you
repair it.

**Check, then save.** Before an admin change is saved, the server builds the complete auth state from the edited policy,
exactly as the loader would (name checks included). If that fails the answer is `409` with nothing saved (decision 10).

**Early warning.** When every usable admin token expires within 14 days (`admin_expiry_warning`), the server logs a
warning at startup and after each policy load, and the CLI prints it after admin commands (decision 9).

**Who can change it.** Only an admin, and admins can only be `human-device`, so an agent or runner token can
never change the policy even if a grant is misconfigured. There is no `admin` action in grants. Admin is a
property of the principal, so no grant can confer it. Root on the host can of course edit the file, which is
the same trust as reading the KDBX password.

## 6. Access log

One JSON object per line, written for every authenticated request, every failed authentication, and every
admin request:

```json
{"ts":"2026-10-18T12:03:44.120Z","principal":"hermes-finance","kind":"agent","token":"k7m2q7xw4h3a",
 "action":"read","route":"get","key":"firefly.token","decision":"allowed","grant":"g_3fd9a1c2",
 "client":"100.101.7.3","status":200,"reveal":true}
```

- `decision` is `allowed` or `denied`. `reason` appears on denials: `no-grant`, `not-admin`, `unknown-token`,
  `bad-token`, `expired-token`, `disabled`, `no-token`, `throttled` (too many failed authentications from this client; answered 429 before the key is looked
  at) and `auth-unavailable` (the key store could not be read; answered 503).
- `key` is the credential name, or for list/search the `prefix`/`q` filter (`tag` is logged as `tag`). `count` is the
  number of entries returned. Health probes aren't logged.
- **What a value reveal looks like.** `reveal: true` is added when a secret value was returned: `show_password=true`
  on get or list, `mask_password=false` on db-url. A request that found nothing reveals nothing and carries no
  `reveal`. `version` is added when a specific version was requested (including `0`).
- **Admin lines** name their target, never a secret: `key` is the principal (or the grant id for grant removal);
  `target_token` is the id of the token being revoked or rotated (the OLD one; the id of a token that issue or
  rotate creates exists only in the response, because the line is written before it is minted); `grant_key`,
  `grant_tag` and `actions` (comma-separated) describe a grant being added.
- **Never logged:** the token or any part of its secret, secret values, usernames, URLs, notes, descriptions and other free text (of a request body only the names, patterns and
  actions named above are logged), query strings other than the filter fields above. For a malformed token, only the parsed `token_id` is
  logged, and only if it has the right shape. Every string is escaped to printable ASCII and capped at 256
  characters, so a client can't forge lines.
- **`decision` is present only if the request reached an authorization decision.** A request rejected before one
  carries no `decision`, only the `status`: 400 (invalid name or Content-Length), 404 for a route that does not exist,
  405 (read-only server), 413, 422 (an unparsable body; a body that parses but is invalid is validated after the
  admin decision, so such an admin line has the decision and no status), and a rate-limit 429 on credential routes
  (slowapi's per-route limit; on admin routes it is raised after the decision, so the line has it). Failed
  authentications and throttled clients are decisions (`denied`).

**When the line is written, and `status`.**

- A **read**, or any request that never reaches a decision, is written by the security middleware at
  `http.response.start`, with the `status` that is about to be sent and before any byte of the response goes out.
- A **state-changing request** (POST, PATCH, PUT, DELETE) that reaches an authorization decision gets its line **at
  the decision**, written synchronously by the route's dependency before anything has happened: before the
  credential is written or deleted, before the policy file is edited, before a token is minted. Such a line has
  **no `status`**, because the outcome does not exist yet; it says what was decided, not what happened (an allowed
  delete of a missing name is still a 404). If the line cannot be written the request is answered 503 and the
  handler never runs, so nothing changed. This covers denials too: a refused write is also logged at its decision.
- Either way each request produces exactly one line. A request that ends without a response is logged from
  `finally` with status 500; one that was cancelled because the client went away first is logged with
  `"error":"client-disconnected"` and no status.

**Where it goes.**
- `MATTSTASH_ACCESS_LOG_FILE` unset (default): JSON lines on stdout via the `mattstash.access` logger, which
  is what `docker logs` and Kubernetes collect.
- Set: also written to that file, created with mode 0600. Put it on a volume that persists and is *not* the
  data volume, e.g. `/logs/access.jsonl`.

**Rotation:** stdlib `RotatingFileHandler`, `MATTSTASH_ACCESS_LOG_MAX_BYTES` (default 10 MiB) ×
`MATTSTASH_ACCESS_LOG_BACKUPS` (default 10 files). No logrotate or copytruncate coordination is needed, and it
works the same in a container. The admin API reads the current file and its backups.

**Fail closed.** If the file is configured and a line can't be written (disk full, permissions), the request is
refused with 503 and an error goes to the server log (the line that could not be written goes to stdout, marked
`status: 503` and `error: access-log-write-failed`). For a read, nothing of the response is sent. For a
state-changing request, nothing is done (see above). As in Vault, an unlogged secret read is worse than an
outage. Writing to stdout can't fail in a way we can detect, so stdout-only mode doesn't fail closed.

**Opt-out.** `MATTSTASH_ACCESS_LOG_FAIL_OPEN=true` makes a failed file write an error in the server log and the
request goes on; the stdout line is still written, marked `error: access-log-write-failed`. Either way `/ready` and
`/api/ready` answer `503` with a fixed body, and no paths, while the file sink is failing (the last write or open
failed and none has succeeded since; `/ready` retries the file at most every 5 seconds, so this stays current). After a
failed write the file is reopened, so it never holds a line for a request answered `503`, and the first line after the
recovery is an `access-log-gap` event with the number of lines lost.

Reading it: `mattstash admin log [--principal P] [--decision denied] [--since 24h] [--limit N]`, which uses
`GET /admin/access-log` or, in local mode, the file.

## 7. Legacy keys (removed in 0.3)

In 0.2 the server accepted `MATTSTASH_API_KEY`, `MATTSTASH_API_KEYS_FILE` (a plain list of keys, or a v1 JSON key
policy) and `MATTSTASH_REQUIRE_SCOPED_KEYS`. Phase 1 kept them working as deprecated `legacy` principals. **0.3 removes
them**, as decided in §11 (decisions 4 and 5). They are not deprecated any more:

| 0.2 | 0.3 |
| --- | --- |
| `MATTSTASH_API_KEY`, `MATTSTASH_API_KEYS_FILE`, `MATTSTASH_REQUIRE_SCOPED_KEYS` in the server's environment | Not credentials. If one is set (an empty value counts as not set), startup fails with a message that names the variable, never its value, and points to `docs/upgrading-to-0.3.md`. They are not ignored. |
| `MATTSTASH_POLICY_FILE` optional | Required. Startup fails without it, or when the file holds no usable credential (an enabled principal with an unexpired token). |
| Legacy principals (`legacy-env`, `legacy-1`, ..., a v1 `id` as kind `legacy`), the `legacy-scoped` reason, the `Deprecation: true` header, `"kind":"legacy"` in the log, `legacy_admin_available`, the `legacy:...` grants, `server/app/keytool.py` | Removed. The library's `legacy.py` keeps only the v1 parser and `migrate_v1`, for `migrate-keys`. |
| The v1 JSON key policy | Not loaded by the server. Converted once with `mattstash admin migrate-keys` (local mode). |

The way to move a deployment without downtime is in [docs/upgrading-to-0.3.md](../upgrading-to-0.3.md). The two tools
are:

- **`mattstash admin token import PRINCIPAL`** stores an existing plain key as a token of the principal, so the client
  keeps working untouched. The key is read from **standard input only** (never from an argument), must be printable
  ASCII and at least 32 characters (`--min-length N`, at least 16; with a server, its `MATTSTASH_MIN_KEY_LENGTH` is a floor),
  and must not start with `mst_` at all (issue or rotate those instead). An admin principal refuses an import, and
  `set_admin(true)` refuses a principal that holds a `sha256:` token (admins use issued tokens only). It is stored as an unsalted `sha256:<hex>` hash with a fresh token id, and a digest that another token
  already holds is refused. The output is the new token id, never the key. Works in local mode and in server mode
  (`POST /api/v1/admin/principals/{name}/tokens/import`, answering `201 {"id", "expires"}`; the key is never logged).
- **`mattstash admin migrate-keys --from KEYS_JSON [--kind {human-device,agent,runner}]`** converts a v1 JSON key policy
  into principals in the local policy file. Each v1 `id` becomes a principal, its digest a `sha256:` token, `ops: read`
  becomes `list,read`, and a prefix `p` becomes the pattern `p*`. The principals are **never admins**; `--kind` (default
  `agent`) sets their kind. A key without prefixes needs the `*` grant, which only `human-device` may hold, so the
  command fails for it unless `--kind human-device` is given (or the key is narrowed in the file), and it writes nothing.
  The command prints that reloading now needs an admin.
- A plain key list has no names: create the principals yourself and import each key.

## 8. CLI

Admin commands work in two modes:

- **server mode** (`--server-url` plus an admin token from `--api-key-file` or `MATTSTASH_API_KEY_FILE`): calls
  `/api/v1/admin/...`. This is the normal way from either Mac.
- **local mode** (`--policy-file PATH` or `MATTSTASH_POLICY_FILE`): edits the file directly, for bootstrapping
  (creating the first admin) and offline repair. The file's permissions are the access control. The server
  picks up the change on its next request.

```
mattstash admin principal list
mattstash admin principal add NAME --kind {human-device,agent,runner} [--description TEXT] [--admin]
mattstash admin principal show NAME
mattstash admin principal disable|enable NAME
mattstash admin principal update NAME [--admin | --no-admin] [--description TEXT]
mattstash admin principal remove NAME [--yes]

mattstash admin token issue PRINCIPAL [--expires 90d|2027-01-01] [--description TEXT] [--output-file PATH]
mattstash admin token import PRINCIPAL [--expires …] [--description TEXT] [--min-length N]   # the key on stdin
mattstash admin token list PRINCIPAL
mattstash admin token revoke PRINCIPAL TOKEN_ID
mattstash admin token rotate PRINCIPAL TOKEN_ID [--grace 24h] [--expires …] [--output-file PATH]

mattstash admin grant list [--principal NAME]
mattstash admin grant add PRINCIPAL (--key PATTERN | --tag TAG) [--actions list,read] [--expires …] [--description …]
mattstash admin grant remove GRANT_ID

mattstash admin check PRINCIPAL ACTION NAME [--tag T …]   # explains: allowed by g_…, or denied (reason)
mattstash admin log [--principal NAME] [--decision allowed|denied] [--since 24h] [--limit 100] [--json]
mattstash admin migrate-keys --from KEYS_JSON [--kind {human-device,agent,runner}] [--min-length N] [--policy-file PATH]   # local mode only
```

The ordinary commands (`get`, `list`, `keys`, `put`, `delete`, `versions`, `db-url`, `env`) are unchanged in
client mode. A principal's token is just a longer API key. Two behaviours change, and they apply only to
principals with partial grants:
- `list` shows entries the principal can only `list` with `-` in place of username and URL.
- `get` on a key that isn't granted reports "not found", exactly as for a missing key.

## 9. Request flow

1. `SecurityMiddleware` (existing): throttle check, then authenticate `X-API-Key` → principal and token id (or
   fail and log `denied`).
2. Route dependency `authorize(action)`: for single-name routes, evaluates the grant and records
   `{action, key, decision, grant}` in `request.state`. A denial raises 404 or 403 per §4.4.
   List and search filter per entry with the same evaluation function. For a state-changing request this step also
   writes the access line (no `status`) before returning; if that fails the request is answered 503 and the handler
   does not run.
3. Middleware, at `http.response.start`: writes the access line with the status for every request not yet written.
   If the file sink fails, the response is replaced by `503` before anything has been sent. A request that ends
   without a response (a crash) is logged from `finally` with status 500, or with `error: client-disconnected` if
   the client went away.

Evaluation lives in the library (`mattstash.authz`) so the server, the CLI's local mode and
`admin check` share one implementation, which is tested and type-checked under the library's 100% coverage and
`mypy --strict`.

## 10. Later phases, and how this design leaves room for them

### 10.1 Several vault files per server (storage tiers)
A server opens `MATTSTASH_VAULTS=default=/data/main.kdbx,ops=/data/ops.kdbx`, each with its own password file.
Grants gain an optional `vault` field (default `"default"`, so phase 1 grants mean what they mean today). Routes
gain `/api/v1/vaults/{vault}/credentials/...`, and the current routes alias `default`. Because the policy file
is *outside* every vault, one policy governs all of them, and a principal with no grant on the `ops` vault can't
learn it exists. The most sensitive tier (registrar, Cloudflare, root tokens) stays off the server entirely.
That is a deployment rule, not a policy rule.

### 10.2 Binding a token to a Tailscale device
Tokens gain an optional `bind` object, e.g. `{"tailscale": {"node": "matts-macbook", "user": "matt@"}}`. After
the token verifies, the server resolves the TCP peer through the Tailscale LocalAPI (`tailscale whois <ip>` or
`tsnet`'s `WhoIs`) and rejects the token (`reason: binding-mismatch`) if the node doesn't match. The access log
gains `device`. Because unknown fields are a load error (§5), a policy containing `bind` will never load on a
phase-1 server that would ignore it. Requires the server to see the real peer address (no proxy, or
`MATTSTASH_TRUSTED_PROXY_HOPS` set correctly).

### 10.3 Per-read approval via ntfy
A grant gains `"approval": {"ntfy_topic": "…", "timeout": "60s"}`. Evaluation then returns a third decision,
`pending`, alongside allowed/denied. The route sends a push with approve and deny actions, pointing at a one-time,
single-use signed URL on the server, and either holds the request until the timeout or answers `202` with a
poll URL. The access log records `decision: pending`, then `approved`/`denied` with who approved. Phase 1's
`Decision` type is a small dataclass with `allowed` and `reason`, so adding a state doesn't change the evaluation
function's signature. The approval endpoint has to require a `human-device` admin, the same rule as policy changes.

### 10.4 SSH certificate authority
Grants generalise from "key pattern or tag" to a typed selector. Phase 1 has `key` and `tag`, and a later phase
adds `ssh_role`, with a new action `sign`. `POST /api/v1/ssh/sign` with a public key and a role checks
`allowed(principal, "sign", role)`, signs with a CA key held in a vault (ideally a separate tier, §10.1), and
issues a short-lived certificate whose key ID is `principal/token_id`, so the SSH server's logs tie back to the
access log. Role definitions (allowed Unix principals, TTL, extensions) live in the policy file next to grants.

## 11. Decisions

Decided on 2026-10-18 (the second decision round). The questions are kept in the history of the PR; each decision is
implemented on this branch.

1. **Runners are never admins.** Only `human-device` principals may be admins, checked when the policy loads and on
   each admin request.
2. **Tag grants stay `list` and `read`.** Tag-based writes are future work: they need a rule that only admins may
   change tags first (§4.3).
3. **The access log stays fail-closed by default.** `MATTSTASH_ACCESS_LOG_FAIL_OPEN=true` opts out: a failed write is
   logged as an error, the stdout line is still written and the request proceeds. `/ready` and `/api/ready` answer `503`
   with a fixed body while the file sink is failing, in both modes (§6).
4. **Legacy server keys are removed, not deprecated** (§7). Setting `MATTSTASH_API_KEY`, `MATTSTASH_API_KEYS_FILE` or
   `MATTSTASH_REQUIRE_SCOPED_KEYS` on the server stops startup. `MATTSTASH_POLICY_FILE` is required. `token import`
   keeps existing keys working as tokens. The client side (`--api-key-file`, `MATTSTASH_API_KEY_FILE`) is unchanged.
5. **`*` is for `human-device` principals only.** An `agent` or `runner` with `*` is a validation error in the library
   (policy load and editor), so the admin API answers `400` and the CLI refuses before sending. Prefixes such as `a*`
   are still allowed.
6. **List-only entries keep their behaviour**: name and version, value masked, other fields `null`. For a simple
   key:value secret the `password` field is the value and is masked unless the principal has `read`. A test pins it.
7. **`/` in names is opt-in** (`MATTSTASH_ALLOW_SLASH_NAMES=true`, for the library, the CLI and the server). By default
   a name with `/` is refused when it is created or written, with a hint to use `.`; reading, listing and deleting existing
   entries keeps working locally. When the server enables it, the `{name:path}` routes and
   `GET /api/v1/versions/{name:path}` address such names.
8. **`migrate-keys` creates non-admin principals**, with `--kind` (default `agent`). A key without prefixes needs the `*`
   grant, so it fails unless `--kind human-device` is given. The command prints that reloading now needs an admin.
9. **The lockout horizon stays at one hour, and there is an early warning.** When every usable admin token expires within
   14 days, `admin_expiry_warning(policy, now, horizon=14 days)` is logged at startup and after each policy load, and the
   CLI prints it (§5).
10. **Check, then save.** An admin change is checked by building the full auth state from the edited policy before it
    is saved. A failure is `409 The change would leave a policy the server cannot load: <reason>` and nothing is
    written. A reload failure after a save keeps the handling of phase 1 (`409` for access-reducing changes, otherwise
    success with `warning` and `X-Policy-Active: false`).

**Future work:** tag-based write grants (decision 2). Anyone who can write an entry can change its tags, so such a grant
needs its own rule first.

## 12. Migration guide

The step-by-step guide for an existing deployment is [docs/upgrading-to-0.3.md](../upgrading-to-0.3.md). This section
has a worked example of it. Both examples use the commands in §8. Set this once (the host path is where the server's
policy file lives):

```bash
export POLICY=/srv/mattstash/config/policy.json   # host path; the server sees it as MATTSTASH_POLICY_FILE
```

A server URL (`--server-url` or `MATTSTASH_SERVER_URL`) takes precedence over `--policy-file`, so run the local-mode
steps *before* exporting `MATTSTASH_SERVER_URL`.

Keep the policy file on its own volume, not the data volume, and mount its **directory** read-write: a read-only file
makes every admin change answer `409`. For example, mount `/srv/mattstash/config` at `/config` and set
`MATTSTASH_POLICY_FILE=/config/policy.json`.

The order matters, because 0.3 refuses to start with `MATTSTASH_API_KEY` set. Everything up to step 4 runs while the
0.2 server keeps serving the old key, so nothing changes for clients until the restart.

### (a) A deployment with one existing `MATTSTASH_API_KEY` (hermes)

Today the server runs with `MATTSTASH_API_KEY=<hermes key>`, and hermes sends it as `X-API-Key`. The key becomes a
token of a `hermes` principal, which keeps hermes working with no change to its key.

1. **Create the policy file and the first admin, in local mode.** This needs no running server:

   ```bash
   mattstash admin principal add matt-mac --kind human-device --admin --policy-file "$POLICY"
   mattstash admin token issue matt-mac --policy-file "$POLICY" --output-file "$HOME/.config/mattstash/admin.key"
   ```

   `--output-file` writes the token to a new file with mode 0600; an existing file is never overwritten.

2. **Create hermes with explicit grants.** An agent can't hold `*`, so list the prefixes hermes really reads (the
   names in its profile, or the `denied` lines from the access log once it runs on 0.3). Start with `list,read`:

   ```bash
   mattstash admin principal add hermes --kind agent --description "Hermes (MCP)" --policy-file "$POLICY"
   mattstash admin grant add hermes --key 'firefly.*' --actions list,read --policy-file "$POLICY"   # one line per prefix
   mattstash admin grant add hermes --key 'finance.*' --actions list,read --policy-file "$POLICY"   # example prefixes
   ```

   `mattstash admin check hermes read firefly.token --policy-file "$POLICY"` confirms a grant before the switch.

3. **Import hermes's existing key as a token.** The key is read from stdin, so it never appears in argv or in the
   shell history. Pipe it from wherever hermes keeps it, or type it at the prompt:

   ```bash
   mattstash admin --policy-file "$POLICY" token import hermes --description "hermes's old MATTSTASH_API_KEY" < /path/to/hermes.key
   ```

   It prints the new token id. Note it: you revoke it in step 6. Nothing changes for hermes.

4. **Switch the server.** Remove `MATTSTASH_API_KEY` (and `MATTSTASH_API_KEYS_FILE` and `MATTSTASH_REQUIRE_SCOPED_KEYS`,
   if set) from the server's environment, set `MATTSTASH_POLICY_FILE` and restart it. The policy's admin token is what
   the CLI uses from now on:

   ```bash
   export MATTSTASH_SERVER_URL=https://mattstash.example.com
   export MATTSTASH_API_KEY_FILE="$HOME/.config/mattstash/admin.key"
   ```

   A server that refuses to start names the setting that is still set. Keep the old configuration at hand until hermes
   is confirmed.

5. **Verify with the access log.** Hermes's requests are now logged under its principal, with the imported token id, and
   a request the grants do not cover is logged as `denied`:

   ```bash
   mattstash admin log --principal hermes --since 1h
   mattstash admin log --principal hermes --decision denied --since 1h   # each one needs another grant (grant add)
   ```

   Add grants for any prefix the denied lines name, then continue.

6. **Rotate hermes to an `mst_` token, then revoke the imported key.** The imported `sha256:` key is weaker (unsalted)
   and the server warns about it at each start until it is gone:

   ```bash
   mattstash admin token rotate hermes <imported token id> --grace 24h --output-file ./hermes.key
   #   ... put the new token in hermes's profile .env (its MATTSTASH_API_KEY), restart hermes, delete ./hermes.key ...
   mattstash admin log --principal hermes --since 10m       # the new token id is in use
   mattstash admin token revoke hermes <imported token id>  # only if you did not use --grace
   ```

   Revoke the imported token once the log shows only the new one. With `--grace` the old key stops on its own after
   the grace period, so the switch needs no revoke. Hermes's own `MATTSTASH_API_KEY` is its client setting; only the
   value changes.

### (b) Adding an agent with read-only access to `firefly.*`

```bash
mattstash admin principal add firefly-agent --kind agent --description "Firefly III (MCP)"
mattstash admin grant add firefly-agent --key 'firefly.*' --actions list,read --description "Firefly III tokens"
mattstash admin token issue firefly-agent --expires 90d --description "firefly MCP" --output-file ./firefly-agent.key
```

Check the grant before handing the token over. `admin check` exits 0 when allowed and 1 when denied:

```bash
mattstash admin check firefly-agent read firefly.token       # allowed (grant g_…), exit 0
mattstash admin check firefly-agent write firefly.token      # denied (no-grant), exit 1
mattstash admin check firefly-agent read cloudflare.token    # denied (no-grant), exit 1
```

Move `firefly-agent.key` to the agent's secret store and delete `./firefly-agent.key`. The agent uses the token exactly
like an old API key:

```bash
mattstash --server-url "$MATTSTASH_SERVER_URL" --api-key-file /run/secrets/firefly-agent.key list
mattstash --server-url "$MATTSTASH_SERVER_URL" --api-key-file /run/secrets/firefly-agent.key get firefly.token
mattstash --server-url "$MATTSTASH_SERVER_URL" --api-key-file /run/secrets/firefly-agent.key get cloudflare.token   # exit 2: as for a missing name
mattstash --server-url "$MATTSTASH_SERVER_URL" --api-key-file /run/secrets/firefly-agent.key delete firefly.token   # exit 1: no delete grant
```

`list` shows only `firefly.*` names. A denied read answers exactly like a missing name, so the agent cannot tell
them apart. To stop access later: `mattstash admin token revoke firefly-agent <token id>`, or
`mattstash admin principal disable firefly-agent` to reject all of its tokens and keep its grants.

### Converting a v1 JSON key policy

If `MATTSTASH_API_KEYS_FILE` held a v1 JSON policy, convert it with:

```bash
mattstash admin migrate-keys --from /srv/secrets/keys.json --policy-file "$POLICY"              # agents
mattstash admin migrate-keys --from /srv/secrets/keys.json --policy-file "$POLICY" --kind human-device   # a key without prefixes
```

This runs in local mode only and writes nothing if it fails. It stores each key's digest as an imported `sha256:` token,
so every existing caller keeps its key, and it prints the name of each new principal. Each key becomes a principal named
after its `id`, of the kind `--kind` gives (default `agent`). **The principals are never admins:** the v1 `admin` op only
reloaded the vault, and reloading now needs an admin. To promote a `human-device` principal yourself:
`mattstash admin principal update <id> --admin`. `ops: read` becomes `list,read`, `write` and `delete` stay as they
are, and each prefix `p` becomes the pattern `p*`. Then move each caller as in (a), steps 5 and 6: watch it by principal
name (`admin log --principal <id>`) and rotate it to an `mst_` token. Remove the v1 file once no caller uses it.
