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

Phase 1 adds named **principals** with tokens, default-deny **grants**, and a structured **access log**. It
keeps existing keys working.

## 2. Ideas taken from OpenBao/Vault, and what was left out

| Vault idea | Taken? | How it shows up here |
| --- | --- | --- |
| Default deny; access only through explicit policy | yes | No grant, no access. Legacy keys are the only implicit "allow all". |
| Path capabilities (`list`, `read`, `create`/`update`, `delete`) | yes, simplified | `list`, `read`, `write`, `delete`. `list` is separate from `read`, as in Vault. |
| Glob only at the end of a path (`secret/foo*`, `secret/foo/*`) | yes | `firefly.*` is a prefix match; `firefly` is an exact name; `*` alone is everything. No `+` segment wildcards. |
| Token *accessor*: a non-secret handle used to look up/revoke a token | yes | Every token has a public `token_id` embedded in it, used in logs, revocation and lookup. |
| Token TTLs | yes | Optional `expires` on tokens and on grants. No renewal/periodic tokens. |
| Audit device that never logs secrets | yes | One JSON line per request; values never logged. |
| Audit is fail-closed (no audit, no request) | yes | If the access-log file can't be written, the request is refused with 503. |
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
  principals that look alike). Names starting `legacy-` are reserved for §7.
- **kind**: `human-device` (a Mac), `agent` (an AI agent or MCP server), `runner` (the Ansible VM, CI). The kind
  limits what a principal may be given (below) and is in every log line.
- **admin**: may change principals, tokens and grants and read the access log. **Only `human-device`
  principals may be admins.** This is checked when the policy is loaded (an agent or runner with `admin: true`
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
later. One other scheme is accepted: `sha256:<hex>`, unsalted, only for keys migrated from v1 policies (§7).
The server logs a deprecation warning for those at startup.

**Verification** is constant time with respect to the secret:

1. Parse `mst_<id>_<secret>`. If the format doesn't match, go to the legacy path (§7).
2. Look up `id`. The id is public, so a dictionary lookup is fine. If it's unknown, still compute one HMAC
   against a fixed dummy record, so unknown and wrong-secret take the same time.
3. `hmac.compare_digest` on the digests.
4. Then check expiry (`now >= expires` means expired), `disabled`, and that the principal still exists. An
   unknown, wrong, expired or disabled token all answer the same `401 Authentication failed`. Only the access
   log records which one it was (`reason`).

**Rotation.** `token issue` adds a token. A principal can hold several at once, so you can issue the new one,
deploy it, then `token revoke <id>`. `token rotate <principal> --grace 24h` does both in one step. It issues a new
token and sets the old one's `expires` to now + grace (default 0, i.e. immediately).

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
KeePass. There is no Unicode or case normalisation, no trimming, and `.`, `/`, `-` get no special treatment.

| Pattern | Matches | Doesn't match |
| --- | --- | --- |
| `firefly` | `firefly` | `firefly-mcp`, `firefly.token`, `Firefly` |
| `firefly.*` | `firefly.token`, `firefly.db.password` | `firefly`, `firefly-mcp` |
| `firefly*` | `firefly`, `firefly-mcp`, `firefly.token` (you asked for it) | `Firefly` |
| `firefly/*` | `firefly/token`, `firefly/` | `firefly`, `firefly.token` |
| `*` | everything | |

Validation, applied when a grant is created or loaded:
- `*` may appear only once, as the last character. `a*b`, `**`, `*a` are errors.
- A pattern that ends in a separator but has no `*` (`firefly/`, `firefly.`) is an error ("did you mean
  `firefly/*`?"), because an exact-name grant on a name ending in a separator is almost always a mistake.
- Printable ASCII only, no whitespace, at most 255 characters (the server's name limit).
- Patterns are not checked against the server's URL name rules. A pattern may contain `/` (titles can, see
  PR #16), even though the HTTP API can't address such names yet (`docs/security-review.md`).

**Why not keep raw prefixes?** A raw prefix is what v1 did, and it's how `firefly` ends up granting
`firefly-mcp`. With an explicit `*` the reader of the grant can see exactly what it covers. v1 prefixes are
converted to `<prefix>*`, which keeps their old meaning exactly (§7).

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
| `/admin/*` | principal is admin (and `human-device` or legacy) | 403. |

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
- write a temporary file in the same directory with mode 0600, `fsync`, then `os.replace`,
- increment `revision`.

The server picks up changes from other writers by checking the file's mtime and size on each request (a
`stat`), plus the existing 300-second refresh. A broken edit keeps the previous policy and logs an error, which
is the existing behaviour. `POST /admin/invalidate-api-key-cache` reloads at once and reports failure. If the
file isn't writable (a Kubernetes ConfigMap or Secret), mutations answer `409 Policy file is read-only`. You
then edit the source and reload.

**Lockout protection.** A change that would leave no enabled admin principal with a valid token is refused,
unless a legacy admin key (§7) is configured. That covers removing or disabling the last admin, revoking or
expiring its last token, and clearing its admin flag.

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
 "client":"100.101.7.3","status":200}
```

- `decision` is `allowed` or `denied`. `reason` appears on denials: `no-grant`, `not-admin`, `unknown-token`,
  `bad-token`, `expired-token`, `disabled`, `no-token`.
- `key` is the credential name, or for list/search the `prefix`/`q`/`tag` filter. `count` is the number of
  entries returned. Health probes aren't logged.
- **Never logged:** the token or any part of its secret, secret values, usernames, URLs, notes, request bodies,
  query strings other than the filter fields above. For a malformed token, only the parsed `token_id` is
  logged, and only if it has the right shape. Every string is escaped to printable ASCII and capped at 256
  characters, so a client can't forge lines.
- `status` is the HTTP status. The security middleware writes the line at `http.response.start`, before any
  byte of the response is sent, from the decision the route dependency recorded. That ordering is what makes
  failing closed possible.

**Where it goes.**
- `MATTSTASH_ACCESS_LOG_FILE` unset (default): JSON lines on stdout via the `mattstash.access` logger, which
  is what `docker logs` and Kubernetes collect.
- Set: also written to that file, created with mode 0600. Put it on a volume that persists and is *not* the
  data volume, e.g. `/logs/access.jsonl`.

**Rotation:** stdlib `RotatingFileHandler`, `MATTSTASH_ACCESS_LOG_MAX_BYTES` (default 10 MiB) ×
`MATTSTASH_ACCESS_LOG_BACKUPS` (default 10 files). No logrotate or copytruncate coordination is needed, and it
works the same in a container. The admin API reads the current file and its backups.

**Fail closed.** If the file is configured and a line can't be written (disk full, permissions), the request is
refused with 503 and an error goes to the server log. As in Vault, an unlogged secret read is worse than an
outage. Writing to stdout can't fail in a way we can detect, so stdout-only mode doesn't fail closed.

Reading it: `mattstash admin log [--principal P] [--decision denied] [--since 24h] [--limit N]`, which uses
`GET /admin/access-log` or, in local mode, the file.

## 7. Backward compatibility

| Today | Phase 1 behaviour |
| --- | --- |
| `MATTSTASH_API_KEY` (hermes, cornyhorse-finance) | Keeps working. Becomes principal `legacy-env`, kind `legacy`, admin, implicit grant `*` with all four actions. |
| `MATTSTASH_API_KEYS_FILE`, plain list | Keeps working. Principals `legacy-1`, `legacy-2`, …, same as `legacy-env`. |
| `MATTSTASH_API_KEYS_FILE`, v1 JSON policy | Keeps working. Each key becomes a principal of kind `legacy` named after its `id`. `ops: read` becomes `list,read`, `write` and `delete` stay as they are, `admin` becomes the admin flag. Each prefix `p` becomes `p*` (exactly the old `startswith` meaning); no prefixes means `*`. |
| `MATTSTASH_REQUIRE_SCOPED_KEYS=true` | Still refuses to start if *unscoped* legacy keys are configured. |

- Legacy principals are built in memory on each load and never written to the policy file. Their names can't
  clash with file principals because `legacy-*` is reserved and a v1 `id` that clashes is a load error.
- Every legacy key is matched in constant time by comparing its SHA-256 digest with every legacy record (the
  existing code path). This only runs when the token isn't in `mst_` format.
- **Deprecation:** a startup warning per legacy source, a `Deprecation: true` response header on requests
  authenticated by a legacy key, and `"kind":"legacy"` in the access log. That way you can find every caller
  before switching legacy keys off. Nothing is removed in this release. A later major release will drop the
  plain sources (proposed: 0.4).
- `mattstash admin migrate-keys --from keys.json` converts a v1 JSON policy into v2 principals and grants. It
  keeps each digest as `sha256:<hex>`, so existing callers keep their keys. Re-issue tokens later to move to the
  salted scheme.
- `MATTSTASH_POLICY_FILE` and the legacy sources can be configured together while migrating.

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
mattstash admin principal remove NAME [--yes]

mattstash admin token issue PRINCIPAL [--expires 90d|2027-01-01] [--description TEXT] [--output-file PATH]
mattstash admin token list PRINCIPAL
mattstash admin token revoke PRINCIPAL TOKEN_ID
mattstash admin token rotate PRINCIPAL TOKEN_ID [--grace 24h] [--expires …] [--output-file PATH]

mattstash admin grant list [--principal NAME]
mattstash admin grant add PRINCIPAL (--key PATTERN | --tag TAG) [--actions list,read] [--expires …] [--description …]
mattstash admin grant remove GRANT_ID

mattstash admin check PRINCIPAL ACTION NAME [--tag T …]   # explains: allowed by g_…, or denied (reason)
mattstash admin log [--principal NAME] [--decision allowed|denied] [--since 24h] [--limit 100] [--json]
mattstash admin migrate-keys --from KEYS_JSON [--policy-file PATH]   # local mode only
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
   List and search filter per entry with the same evaluation function.
3. Middleware, at `http.response.start`: writes the access line with the status. If the file sink fails,
   the response is replaced by `503` before anything has been sent. A request that ends without a response (a
   crash) is logged from `finally` with status 500.

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

## 11. Decisions that need a call from you (also listed in the PR)

1. **Admin = `human-device` only.** The Ansible runner can't manage the policy. Should runners be allowed to be
   admins (for example, so Ansible can provision agent principals)?
2. **Tag grants are read-only in phase 1** (§4.3). Is that enough, or do you want tag-based writes with a rule
   that only admins may change tags?
3. **Fail closed** when the access-log file can't be written. Do you want an opt-out
   (`MATTSTASH_ACCESS_LOG_FAIL_OPEN`)?
4. **Legacy removal timeline**: drop the plain `MATTSTASH_API_KEY` / plain keys file as a server credential in 0.4?
5. **`*` grants for agents** are allowed, with a CLI warning. Forbid them outright?
6. **List-only fields**: entries visible through `list` without `read` return name and version only. Is
   showing `username`/`url` acceptable for your agents? It would make `mattstash list` more useful, but those
   fields can be sensitive.
7. **Names with `/` over HTTP.** They're allowed in titles and in grant patterns, but the server's URL rules
   still reject them. Making the server accept them (`{name:path}` plus care with `/versions`) is a separate change.

## 12. Migration guide

Both examples use the commands in §8. Set these once (the host path is where the server's policy file lives):

```bash
export MATTSTASH_SERVER_URL=https://mattstash.example.com
export POLICY=/srv/mattstash/config/policy.json   # host path; the server sees it as MATTSTASH_POLICY_FILE
```

Keep the policy file on its own volume, not the data volume, and mount it **read-write**: a read-only file makes
every admin change answer `409`. For example, mount `/srv/mattstash/config` at `/config` and set
`MATTSTASH_POLICY_FILE=/config/policy.json`. Each server restart picks up the new variables.

### (a) A deployment with one existing `MATTSTASH_API_KEY` (hermes)

Today the server runs with `MATTSTASH_API_KEY=<hermes key>` and hermes sends it as `X-API-Key`. Nothing in this
plan breaks it. Until you remove it, the key is principal `legacy-env` (kind `legacy`, admin, every action on every
name), and each request it makes is logged with `"kind":"legacy"` and answered with `Deprecation: true`.

1. **Create the policy file and the first admin, in local mode.** This needs no running server; it writes the
   file on the host:

   ```bash
   mattstash admin principal add matt-mac --kind human-device --admin --policy-file "$POLICY"
   mattstash admin token issue matt-mac --policy-file "$POLICY" --output-file "$HOME/.config/mattstash/admin.key"
   ```

   Without `--output-file` the token goes to stdout. With it, the token is written only to that file, mode 0600,
   and an existing file is never overwritten. Restart the server with `MATTSTASH_POLICY_FILE` set. Then point the
   CLI at the server with the admin token:

   ```bash
   export MATTSTASH_API_KEY_FILE="$HOME/.config/mattstash/admin.key"
   ```

2. **Watch the legacy caller before changing anything.** These commands run in server mode, with the admin token:

   ```bash
   mattstash admin log --principal legacy-env --since 7d            # what the legacy key does
   mattstash admin log --since 7d --limit 1000 --json | grep '"kind":"legacy"'   # every legacy caller
   ```

   The second command finds every legacy caller, whatever its name (`legacy-env`, or `legacy-1`, `legacy-2`, ... for
   the other legacy sources), so use it to check that nothing else still depends on a legacy key.

3. **Create hermes with the access it has today.** The legacy key can do everything, so start with the same grant
   and narrow it when the log shows what hermes really uses. The CLI warns when `*` is granted to an agent:

   ```bash
   mattstash admin principal add hermes --kind agent --description "Hermes (MCP)"
   mattstash admin grant add hermes --key '*' --actions list,read,write,delete --description "temporary: same as the old MATTSTASH_API_KEY"
   ```

4. **Issue hermes its token and swap the key.** `--output-file` creates a new 0600 file:

   ```bash
   mattstash admin token issue hermes --description "replaces MATTSTASH_API_KEY" --output-file ./hermes.key
   ```

   Move the file to hermes's secret store, point hermes at it with `MATTSTASH_API_KEY_FILE=<path>` instead of
   `MATTSTASH_API_KEY`, restart hermes, and delete `./hermes.key`. While both keys work there is no downtime. Confirm
   with `mattstash admin log --principal hermes --since 1h`: the records show `"kind":"agent"` and `allowed`.

5. **Narrow hermes's grant** to what the log shows, then remove the broad one:

   ```bash
   mattstash admin grant list --principal hermes
   mattstash admin grant add hermes --key 'firefly.*' --actions list,read     # example pattern
   mattstash admin grant remove <id of the * grant>
   ```

6. **Remove the legacy key.** When the `"kind":"legacy"` query in step 2 has stayed empty for long enough, remove
   `MATTSTASH_API_KEY` (and `MATTSTASH_API_KEYS_FILE`, if used) from the server's environment and restart the server.
   Removing it can't lock you out: `matt-mac` is an enabled admin with a valid token, and the policy rules refuse any
   change that would leave no such admin.

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

If `MATTSTASH_API_KEYS_FILE` holds a v1 JSON policy, convert it with:

```bash
mattstash admin migrate-keys --from /srv/secrets/keys.json --policy-file "$POLICY"
```

This runs in local mode only. It prints the name of each new principal and stores each key's digest as `sha256:<hex>`,
so every existing caller keeps its key. Each key becomes a principal named after its `id`: a key with `admin` in its
`ops` becomes a `human-device` admin, any other key an `agent`. `ops: read` becomes `list,read`, `write` and `delete`
stay as they are, and each prefix `p` becomes the pattern `p*`. A migrated principal is not of kind `legacy`, so its
calls do not show as `"kind":"legacy"` in the access log: watch them by principal name (`admin log --principal <id>`)
instead. Issue the principal a new token with `token issue` and move its callers to it; new tokens use the salted
`mst_` format. Remove the v1 file once no caller uses it.
