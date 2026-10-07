# Upgrading from 0.1.x to 0.2

0.2 is a security and correctness release (see [security-review.md](security-review.md) for the findings behind
each change). Several behaviours changed on purpose; this page lists what to do about each.

For the API server see also [server/docs/configuration.md](../server/docs/configuration.md#upgrading-from-01x).

## Checklist

1. **Create databases explicitly.** Nothing creates a database implicitly any more.
   ```bash
   mattstash setup                    # prompts for a master password
   mattstash setup --sidecar          # old behaviour: random password in <db dir>/.mattstash.txt
   ```
   Existing databases and sidecar files keep working unchanged.
2. **Handle database errors in Python code** (`DatabaseNotFoundError`, `DatabaseAccessError`, `DatabaseLockError`).
3. **Check scripts that rely on exit codes or on `delete`/`list`/`s3_client` behaviour** (tables below).
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
| Titles were looked up through an XPath built from the title. | Exact string comparison in Python. | **Security:** a title such as `x" or "a"="a` could match or delete unrelated entries. |

Files are created with mode `0600` (and keep their mode across saves). A warning is logged when the database or
sidecar is group/world readable.

## Command line

| Change | Detail |
|--------|--------|
| `setup` | Prompts for the master password (twice) unless you pass `--sidecar`, `--generate`, `--password-file`, `--password-stdin` or set `KDBX_PASSWORD(_FILE)`. `--force` now asks for confirmation (`--yes` for scripts) and first backs up the existing files to `<name>.bak-<timestamp>`; if creation fails the old files are untouched. |
| Exit codes | New: `6` database not found, `7` database cannot be opened (wrong/missing password, corrupt, lock timeout), `8` `setup` refused to overwrite. Previously 6/7 situations exited `2` ("not found"). |
| `delete` | Removes all versions (see above). |
| `get`, `list`, `put`, ... on a missing database | Exit `6` with a message; nothing is created. |

## What did not change

- The `.kdbx` format: databases are fully compatible in both directions, and any KeePass client can open them.
- Sidecar files created by 0.1.x are still honoured (as the last fallback).
- The Python module-level functions (`mattstash.get`, `put`, ...) and the CLI command names.

## Release note

These are breaking changes, so release as a **minor** version: put `[minor]` in the merge commit message
(the release workflow bumps the patch version unless told otherwise).
