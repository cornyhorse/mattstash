# Upgrading from 0.2 to 0.3

0.3 replaces the API-key settings of the server with principals, tokens and grants
([design](design/principals-and-grants.md)). **The old key settings are removed, not deprecated**, and the server
refuses to start while one of them is set, so an upgrade needs a policy file. This page explains how to make that
change without downtime: every client keeps the key it has today until you switch it to a token at your own pace.

The client side does not change. The CLI and your applications still send their token with `--api-key`,
`--api-key-file`, `MATTSTASH_API_KEY` or `MATTSTASH_API_KEY_FILE` (these are the *client's* names and keep working,
and an old key keeps working as a token until you retire it).

## What was removed

| Removed from the server | Replacement |
|---|---|
| `MATTSTASH_API_KEY` (one full-access key) | A principal with a token in the policy file. |
| `MATTSTASH_API_KEYS_FILE` (a list of keys, or a v1 JSON key policy) | The same, one principal per key. `mattstash admin migrate-keys` converts a v1 JSON file. |
| `MATTSTASH_REQUIRE_SCOPED_KEYS` | Gone with the keys it policed. Every credential is now scoped by grants. |
| `python -m app.keytool` | `mattstash admin token issue` (new tokens) and `mattstash admin token import` (existing keys). |
| The `Deprecation: true` response header, the `legacy` principal kind (`kind: "legacy"` in the access log), the `legacy` fields in the admin API's principal and grant objects, the `legacy-env` / `legacy-N` principals and the `legacy:...` grants | Nothing to replace: they only existed to flag the removed keys. |
| The v1 rule that an `admin` key may only reload | An admin (a `human-device` principal with the admin flag) manages the whole policy. `/admin/reload` and `/admin/invalidate-api-key-cache` need an admin. |

What the server needs now:

- `MATTSTASH_POLICY_FILE` is **required**. The server refuses to start without it, or when the file holds no usable
  credential (an enabled principal with a token that has not expired).
- If `MATTSTASH_API_KEY`, `MATTSTASH_API_KEYS_FILE` or `MATTSTASH_REQUIRE_SCOPED_KEYS` is set in the server's
  environment (even to `false`), startup fails with a message that names the variable
  (never its value) and points here. They are not ignored, because ignoring `MATTSTASH_API_KEY` would turn a
  deployment that used to be protected into one that rejects every client, or worse, one that you believe is configured.
  An *empty* variable (`MATTSTASH_API_KEY=` from a Compose `${KEY:-}`) counts as not set.
- `MATTSTASH_MIN_KEY_LENGTH` (default 32, at least 8) now only matters for `token import` through the admin API: it is
  the shortest existing key the server will import (never below 16).

## Moving over without downtime

You can do all of this on the machine you administer from, while the old server keeps running. Nothing changes for
the clients until you restart the server with the policy file, and then they keep working with the keys they have.

### 1. Create the policy file and an admin

Install the 0.3 CLI first (`pip install -U mattstash`). Then, in a directory outside the repository:

```bash
mattstash admin --policy-file policy.json principal add admin --kind human-device --admin --description "me"
mattstash admin --policy-file policy.json token issue admin --output-file admin.token --expires 365d
```

The first command creates the file (mode `0600`). The admin can manage principals, tokens and grants and read the
access log, but it reads no secret: admin does not imply data access.

### 2. One principal per client, with explicit grants

For every client that uses the server today, add a principal and say what it may touch:

```bash
mattstash admin --policy-file policy.json principal add billing --kind agent --description "billing service"
mattstash admin --policy-file policy.json grant add billing --key 'billing.*' --actions list,read
```

Choose the kind by what the client is: `agent` (an application, an AI agent, an MCP server), `runner` (CI, an Ansible
VM) or `human-device` (a person's own machine). Decide the grants from what the client actually reads: patterns are
exact names or a prefix ending in `*` (`billing.*`, `billing-*`), and `list` and `read` are separate actions, `write`
and `delete` too. If you kept the 0.2 access lines or the application's own configuration, use them; otherwise start
narrow and widen when `mattstash admin log --decision denied` shows what the client asked for.

> **`*` is no longer allowed for agents and runners.** A grant of `*` (every secret) is refused for `agent` and
> `runner` principals, in the policy file and in `grant add`; only `human-device` principals may hold it. A client
> that used to have a full-access key (`MATTSTASH_API_KEY`, or a plain line in the keys file) therefore needs one
> of these: the explicit prefixes it really uses; or, when it is a person's own machine, a `human-device` principal
> with `*`. A prefix such as `a*` is still fine for any kind, but it is a prefix, not "everything": prefer
> `service.*` over `s*`.

### 3. Import each client's existing key

`token import` stores a key the client already has as a token of its principal, so the client keeps working
untouched. The key is read from **standard input only** (never from an argument, where it would sit in the process
list and your shell history). Pipe it from wherever the client keeps it, or type it at the prompt (no echo):

```bash
mattstash admin --policy-file policy.json token import billing \
  --description "billing's old MATTSTASH_API_KEY" < /path/to/billing.key
# or
printf '%s' "$BILLING_KEY" | mattstash admin --policy-file policy.json token import billing
```

It prints the new token's id (note it down: you will revoke it in step 6). The key must be printable ASCII with no
surrounding whitespace (one trailing newline is fine) and at least 32 characters; `--min-length N` lowers that, down
to 16. A key already in `mst_` format is refused (issue or rotate those instead), and so is a key that another token
already holds. The key is stored as an unsalted `sha256:<hex>` hash, which is exactly how the server verified it
before, and the policy file never contains the key itself.

Importing works through a running 0.3 server as well (`mattstash --server-url ... --api-key-file admin.token admin token
import ...`, with an admin token); the key then travels in the request body, so use https or a private network.

**Several keys, one client?** Import each one onto the same principal. **One key shared by several clients?** Import
it once, then issue each client its own token (step 6) and revoke the shared one.

### 4. Switch the server

Remove the three old variables from the server's environment, set the policy file, and restart:

| Setup | Change |
|---|---|
| Docker Compose | Delete `MATTSTASH_API_KEYS_FILE` / `MATTSTASH_API_KEY`. Mount the policy file's **directory** (for example `./policy:/policy:ro`) and set `MATTSTASH_POLICY_FILE: /policy/policy.json`. Mount the directory, not the single file: the CLI replaces the file atomically, and a single-file bind mount keeps showing the old content. See `server/docker-compose.yml` and `docker-compose.prod.yml`. |
| Kubernetes | Put `policy.json` in the `mattstash-secrets` Secret (instead of `api-keys`) and set `MATTSTASH_POLICY_FILE: /secrets/policy.json` in the ConfigMap. See `server/k8s/`. |
| Anything else | Unset the three variables and set `MATTSTASH_POLICY_FILE` to the file. |

On start the server logs one warning per imported key, naming the token and the command that retires it:

```
Token wfq2... of principal billing uses the unsalted 'sha256:' scheme (an imported or migrated key). Rotate it to an mst_ token: mattstash admin token rotate billing wfq2...
```

That is expected until step 6. If the server refuses to start, the message says why (a variable still set, no policy
file, no usable credential, a policy that does not load). A server that does not start serves nobody, so keep the old
configuration at hand and restore it if you need to go back.

Set `MATTSTASH_ACCESS_LOG_FILE` too, if you have not, so you can do the next step. A rolling update (Kubernetes) or a
`docker compose up -d` restart is the only interruption.

### 5. Verify with the access log

```bash
mattstash admin log --log-file /path/to/access.jsonl --principal billing --since 1h      # the file, on the server's host
mattstash --server-url https://... --api-key-file admin.token admin log --principal billing --since 1h
```

Each line names the principal, the token id (the imported one), the name asked for and the decision. Look for
`denied` lines (`--decision denied`): a client that gets `404`/`403` where it used to succeed needs another grant
(`grant add`), and the change is live at once.

### 6. Rotate each client to an `mst_` token

When a client is verified, give it a real token and retire the imported key. The commands below work against the
server (put `--server-url URL --api-key-file admin.token` before `admin`) or against the policy file
(`admin --policy-file policy.json ...`); the running server notices a changed policy file by itself.

```bash
mattstash admin token issue billing --output-file billing.token           # a new mst_ token for the client
#   ... deploy billing.token to the client (MATTSTASH_API_KEY_FILE or --api-key-file) ...
mattstash admin log --principal billing --since 10m                        # the new token id is in use
mattstash admin token revoke billing <imported-token-id>
```

or in one step, `mattstash admin token rotate billing <imported-token-id> --grace 24h --output-file billing.token`,
which issues the new token and lets the imported key work for another 24 hours.

When the last imported key is gone, the `sha256:` warning disappears at the next start. Tokens look like
`mst_<id>_<secret>`, hold 256 random bits and are stored salted; a client sends them exactly like the old key.

## Migrating a v1 JSON key policy

If `MATTSTASH_API_KEYS_FILE` pointed at a JSON key policy (`ops` and `prefixes` per key), convert it in one go instead
of steps 2 and 3:

```bash
mattstash admin --policy-file policy.json migrate-keys --from keys.json [--kind agent] [--min-length N]
```

Each v1 entry becomes a principal named after its `id`, with grants converted from its `ops` and `prefixes` (a
`prefixes` entry `billing-` becomes the grant `billing-*`, exactly the old `startswith` meaning; v1 `read` becomes
`list` and `read`), and the old key keeps working (stored as an imported `sha256:` token). What to know:

- The principals are **never admins**. The v1 `admin` op only allowed reloading the vault; a v2 admin manages the
  whole policy, so the op is not carried over (the command names the keys that had it). Reloading now needs an admin,
  and the server polls the vault file every 5 seconds anyway, so a manual reload is rarely needed. Promote a
  principal yourself if you mean to (`principal update NAME --admin`, `human-device` principals only).
- `--kind` (default `agent`) sets the kind of all the new principals. A v1 key **without prefixes** can read every
  name, so it would need the `*` grant, which only `human-device` principals may hold: the command fails with a
  message naming the key and asking you to re-run with `--kind human-device` or to narrow the key (give it prefixes
  in the file, or migrate it by hand). Nothing is written when it fails.
- It refuses a key that is already in the policy, ids that are not valid principal names, and ids that differ only in
  case. It edits a local policy file only (`--policy-file` or `MATTSTASH_POLICY_FILE`), not a server.
- A **plain list** (one key per line) has no names to migrate. Create the principals yourself (step 2) and import each
  key (step 3).

Then continue with step 4.

## Other changes

- **Early warning for admin tokens.** The policy-change lockout protection looks one hour ahead; on top of it,
  when every admin token expires within 14 days the server logs a warning at startup and after each policy load, and
  the CLI prints it on stderr after admin commands in local mode and after `admin principal list` in both modes.
  Issue a new admin token before then.
- **Admin changes are checked before they are saved.** The admin API builds the full server state from the edited
  policy first; if the server could not load the result, the answer is `409` (`The change would leave a policy the
  server cannot load: ...`) and nothing is written. A reload that fails after a successful save, because of a race or an
  I/O error, is handled as before: `409` for changes that take access away, otherwise success with a `warning` and
  `X-Policy-Active: false`.
- **New admin endpoint** `POST /api/v1/admin/principals/{name}/tokens/import` with `{"key": "...", "description"?,
  "expires"?, "min_length"?}`; the answer is `201 {"id", "expires"}` and never contains the key, which is also never
  logged.
- **Admin API shapes.** The `legacy` field is gone from principals and grants. Clients that read it as optional are
  unaffected.
- **`/` in names is now opt-in.** Creating or writing a credential whose name contains `/` is refused by default (the
  library, the CLI and the server), with an error that suggests `.` (`myapp.db-password`). Reading, listing and deleting
  existing entries with `/` keeps working locally. To keep writing such names set `MATTSTASH_ALLOW_SLASH_NAMES=true`
  (the library and CLI environment, and the server's). With it enabled on the server, names with `/` are addressable
  over HTTP (`/api/v1/credentials/{name:path}`, `/api/v1/db-url/{name:path}` and the new
  `/api/v1/versions/{name:path}`; a name may not start or end with `/`, contain `//`, or have `.` or `..` segments).
  Renaming to `.` is the long-term answer.

## Checklist

1. Install the 0.3 CLI; create `policy.json` with an admin (step 1).
2. A principal per client with explicit grants; no `*` for agents or runners (step 2).
3. Import each client's key from stdin (step 3), or `migrate-keys` for a v1 JSON file.
4. Remove `MATTSTASH_API_KEY`, `MATTSTASH_API_KEYS_FILE` and `MATTSTASH_REQUIRE_SCOPED_KEYS`; set
   `MATTSTASH_POLICY_FILE` and mount its directory; restart (step 4).
5. Check `admin log` for `denied` lines (step 5).
6. Move each client to an `mst_` token and revoke the imported key (step 6).
7. Replace `python -m app.keytool` in scripts with `mattstash admin token issue`.
