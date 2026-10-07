# Upgrading from 0.1.x to 0.2

0.2 is a security and correctness release (see [security-review.md](security-review.md) for the findings behind
each change). Several behaviours changed on purpose; this page lists what to do about each.

For the API server see also [server/docs/configuration.md](../server/docs/configuration.md#upgrading-from-01x).

## Checklist

0. **Python 3.11 or newer is required** (tested on 3.11, 3.12, 3.13 and 3.14; the Docker image runs 3.14).
   Python 3.9 and 3.10 are no longer supported (3.10 reaches end of life on 2026-10-31); pin `mattstash<0.2` if you
   cannot upgrade yet.
1. **Create databases explicitly.** Nothing creates a database implicitly any more.
   ```bash
   mattstash setup                    # prompts for a master password
   mattstash setup --sidecar          # old behaviour: random password in <db dir>/.mattstash.txt
   ```
   Existing databases and sidecar files keep working unchanged.
2. **Handle database errors in Python code** (`DatabaseNotFoundError`, `DatabaseAccessError`, `DatabaseLockError`).
3. **Check scripts that rely on exit codes or on `delete`/`list`/`s3_client` behaviour** (tables below).
   Scripts that pass a secret on the command line (`put --value SECRET`) keep working, but see the new ways to keep
   secrets out of `ps` and shell history under *Command line*.
4. **Server:** read-only by default, keys of at least 32 characters, health at `/health`, start with
   `python -m app` (details in the server docs).

## Library (Python API)

| 0.1.x | 0.2 | Why |
|-------|-----|-----|
| `MattStash(path)` created the database and a sidecar when both were missing. | Never creates anything. A missing database raises `DatabaseNotFoundError` (message names the path and suggests `mattstash setup`). Use `MattStash.create(path, password=..., sidecar=False, force=False)` to create one. | A mistyped path or an unmounted volume silently produced an empty database that then looked like "secret not found". |
| `get()` returned `None`, `delete()` returned `False`, `list()` returned `[]` when the database could not be opened (wrong password, corrupt file, missing password). | These raise `DatabaseAccessError` / `DatabaseNotFoundError`. `None`/`False` now only mean "no such secret". | Authentication failures were indistinguishable from missing secrets. |
| Password order: explicit, **sidecar**, `KDBX_PASSWORD`. | Explicit, `KDBX_PASSWORD`, **`KDBX_PASSWORD_FILE`**, sidecar. Empty values are ignored; a configured but unreadable `KDBX_PASSWORD_FILE` is an error. | A stale sidecar silently beat an operator-supplied password. |
| `delete(title)` removed only the unversioned entry if one existed, leaving versions readable. | Removes the unversioned entry **and every version**. `delete(title, version=N)` removes one version; `prune(title, keep=N)` keeps the newest N. | A "deleted" secret could still be read. |
| `put(..., version=-1)` stored a malformed title. | `InvalidCredentialError` unless `version` is a non-negative `int`. | |
| `list()` returned one row per stored entry (`name@0000000001` ...). | Unchanged by default; `list(latest_only=True)` returns one row per name with its latest `version`. | |
| `Credential` had no version. | `Credential.version` (`None` unless known; included in `as_dict()` only when set). `put()` and `get()` of full credentials fill it. | The server always reported `0000000001`. |
| `hydrate_env()` ignored versioned entries (the default output of `put`). | Uses the latest version. | |
| `get_db_url()` did not escape credentials. | User, password and database are percent-encoded; the host must be a plain host name or IP; `sslmode` must be a known value. | A password containing `@` or `/` produced a URL pointing at the wrong host. |
| `get_s3_client(verbose=True)` printed to stdout. | `verbose=False` by default; output goes to stderr. | Library code should not write to stdout. |
| Not thread/process safe. | One `MattStash` is thread-safe; writes take a cross-process lock (`<db>.lock`), re-read the file when another writer changed it, and discard in-memory state if saving fails. | Lost updates and "phantom" entries. |
| `mattstash.core` module and package both existed. | Only the package. | Dead code. |
| `requires-python >=3.9`. | `>=3.11`. | 3.9 is end of life and 3.10 follows on 2026-10-31. |
| Titles were looked up through an XPath built from the title. | Exact string comparison in Python. | **Security:** a title such as `x" or "a"="a` could match or delete unrelated entries. |
| Entries moved to the KeePass Recycle Bin by another client were still served. | They are ignored (`get`, `list`, versions); their version numbers are never reused. | A trashed secret is a deleted secret. |
| A database that vanished (deleted, unmounted) kept being served from memory. | `DatabaseNotFoundError`; the instance works again when the file returns. | |
| A symlinked database was replaced by a regular file on save. | The link is kept and the target is updated; one lock per real file. | |
| `get_db_url(...)` was PostgreSQL only; `driver` defaulted to `"psycopg"`. | `dialect=` `postgresql`, `mysql` or `mariadb` (or the entry's `dialect` property); `driver="auto"` is the default (psycopg for PostgreSQL, none otherwise). Hosts are validated (IPv6 is bracketed, ports 1-65535), unknown dialects/drivers raise `ValueError`. | |
| Not available. | `MattStash.backup(dest=None, force=False)`, `rotate_password(new, backup=False)` (may raise `SidecarUpdateError` after re-keying), `resolve_env(...)`, `get_entry_with_properties`. | |
| `create(..., password=" pw ", sidecar=True)` stored a password the sidecar could not return. | Refused when the password has leading/trailing whitespace; without a sidecar it works and `CreatedDatabase.warnings` says why file sources cannot supply it. | Password files are read with whitespace stripped. |

Files are created with mode `0600` (and keep their mode across saves). A warning is logged when the database or
sidecar is group/world readable.

## Command line

| Change | Detail |
|--------|--------|
| `setup` | Prompts for the master password (twice) unless you pass `--sidecar`, `--generate`, `--password-file`, `--password-stdin` or set `KDBX_PASSWORD(_FILE)`. `--force` now asks for confirmation (`--yes` for scripts) and first backs up the existing files to `<name>.bak-<timestamp>`; if creation fails the old files are untouched. |
| Exit codes | New: `6` database not found, `7` database cannot be opened (wrong/missing password, corrupt, lock timeout), `8` `setup` refused to overwrite. Previously 6/7 situations exited `2` ("not found"). |
| `delete` | Removes all versions (see above); `delete TITLE --version N` removes one. `prune TITLE --keep N` keeps the newest N (local database only). |
| `get`, `list`, `put`, ... on a missing database | Exit `6` with a message; nothing is created. |
| Secrets without argv | `put --value -` (stdin) and `--value-file FILE`; `--entry-password`, `--entry-password-file`, `--entry-password-stdin` for full entries; global `--db-password-file`, `--api-key-file` (`MATTSTASH_API_KEY_FILE`). A bare `--password` on `put --fields` still sets the entry password but is deprecated (use `--entry-password*`; `--db-password` is the unambiguous spelling of the database password). |
| `put --value` with `--username`/`--url`, or an empty value | Now an error (the extra fields used to be dropped silently). |
| `get --raw [--field F]` | Prints only the value (exit 2 when missing or empty); mutually exclusive with `--json`. |
| New commands | `env` and `exec` (secrets as environment variables; `exec` removes `KDBX_PASSWORD` and `MATTSTASH_API_KEY` from the command's environment unless `--keep-vault-env`; exit 126/127 when the command cannot be run), `backup`, `rotate-password`. See [cli-reference.md](cli-reference.md). |
| `db-url` | `--dialect`; `--driver` defaults to `auto`. |
| `--password` / `--api-key` on the command line | Still work; help text and docs steer to the file/stdin/env forms because argv is visible to other users. |

## Changes from the second review (library, CLI, server)

| Area | Change |
|------|--------|
| Paths | `MattStash.path` is absolute. Symlinks are followed on **every** access (a retargeted link or a swapped Kubernetes Secret volume is picked up); saves go to the resolved file so a symlinked database stays a symlink; two paths to one file share one lock. |
| Locking | `lock_timeout` bounds the *whole* wait for a write (queued threads included, they no longer wait one timeout each). A busy writer can no longer starve other processes. A lock file deleted while held makes the write fail with `DatabaseLockError` instead of silently losing exclusion. |
| Saving | The database is written to a uniquely named staged file and renamed (it keeps owner, group and mode; `0600` for new files). Failures raise `DatabaseAccessError` ("Could not save the database: ...") instead of a raw `OSError`. Single-file bind mounts cannot be renamed over and now fail loudly instead of truncating the database. |
| `rotate-password` | The new password is never lost: the sidecar is replaced right after the re-key; if something fails afterwards (`RotationIncompleteError`: `SidecarUpdateError`, `RekeyVerifyError`) the CLI still prints a generated password and names the backup. A sidecar is only rewritten when it holds the password the database was opened with (one `.mattstash.txt` per directory can belong to another database); symlinked sidecars are updated through the link. |
| `backup` | Default names are `<db>.bak-<UTC timestamp with microseconds>` (with a counter on collision). A truncated or non-KDBX file is refused. |
| `setup` | `--force` on a symlinked database replaces the target under the writers' lock. A lock timeout exits `7`. Failed runs name the backups they kept. An interrupt (Ctrl-C, `SIGTERM`, `SIGHUP`) cleans up and exits `130`. |
| `env` / `exec` | Names derived from `--prefix` may not be loader/shell control variables (`LD_PRELOAD`, `PATH`, `BASH_ENV`, ...): use `--map NAME=TITLE`, `--allow-env-name NAME` (one name) or `--allow-reserved` (all). New `--format docker-env` for `docker run --env-file`. `exec` leaves SIGPIPE at its default, injects a secret mapped to a vault variable without `--override`, removes the `_FILE` vault variables as well, and exits 126 for a non-executable command on `PATH`. The documented prefix separator is `.` (`put` and the server reject `/`). |
| API key / passwords | Keys are stripped and must be printable ASCII (inner spaces are fine); empty `--password`, `--db-password`, `--db-password-file`, `--password-file`, `--new-password-file`, `--api-key`, `--api-key-file` and `--server-url` are errors (an empty *environment variable* still means "not set") (no silent fallback to another source); a UTF-8 BOM in a password/key file is ignored; password files are capped at 1 MiB; a terminal is read without echo. |
| Server mode (CLI) | Only the server's own "Credential not found" 404 means "no such secret" (a wrong URL is an error, so `delete` cannot report "already gone"). Responses are bounded in size and time; rate-limited `GET`s are retried honouring `Retry-After`. |
| Server | Rate limits per route, `Retry-After` on `429`, `MATTSTASH_MAX_CONCURRENT_WRITES`, `POST /admin/reload` fails with `503`. See [server/docs/configuration.md](../server/docs/configuration.md). |

## Server mode (CLI client)

- Failures raise `mattstash.utils.exceptions.ServerError` (HTTP status and request path only; never the API key, query
  string or response body) instead of `httpx.HTTPStatusError`. Code that caught the httpx exception must catch this.
- Secret names are percent-encoded in request paths, so names such as `db#prod` address the right secret.
- A plain `http://` server URL to a non-loopback host logs a warning (silence with `MATTSTASH_ALLOW_INSECURE_HTTP=1`).
- `delete --version N` sends `DELETE ?version=N`. **An old server ignores the parameter and deletes every version**:
  upgrade the server first. `prune` is not available in server mode.
- The server's `db-url` endpoint accepts `dialect` and an optional `driver`.

## What did not change

- The `.kdbx` format: databases are fully compatible in both directions, and any KeePass client can open them.
- Sidecar files created by 0.1.x are still honoured (as the last fallback).
- The Python module-level functions (`mattstash.get`, `put`, ...) and the CLI command names.

## Release note

These are breaking changes, so release as a **minor** version: put `[minor]` in the merge commit message
(the release workflow bumps the patch version unless told otherwise).
