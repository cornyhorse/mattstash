# Python API Reference

Complete Python interface documentation for MattStash.

## Note on Server Mode

The Python API (`MattStash` class) operates on local KeePass databases only. For network-accessible credential storage, use the MattStash API server.

**Local Python API**: Direct KeePass file access (this document)
- Use `MattStash` class for local database operations
- Suitable for local development, scripts, and applications

**Server API**: REST API for network access
- Deploy the FastAPI server component
- Access via HTTP/HTTPS from any network location
- See [Server API Documentation](../server/README.md#api-documentation)
- CLI supports server mode via `--server-url` flag (see [CLI Reference](cli-reference.md))

## Quick Start

```python
from mattstash import MattStash

# Initialize with defaults
stash = MattStash()

# Custom database path
stash = MattStash(path="/path/to/custom.kdbx", password="mypassword")
```

## MattStash Class

### Constructor

```python
MattStash(path=None, password=None, *, lock_timeout=30.0)
MattStash.create(path=None, password=None, *, sidecar=False, force=False, backup=True)  # classmethod
```

**Parameters:**
- `path` (str, optional) - Path to KeePass database. Default: `~/.config/mattstash/mattstash.kdbx`
- `password` (str, optional) - Database password. If None, resolved from `KDBX_PASSWORD`, `KDBX_PASSWORD_FILE`, then the sidecar file
- `lock_timeout` (float) - the longest a write waits for the database lock (other threads of this process *and* other
  processes together) before raising `DatabaseLockError`

`MattStash.path` is made absolute. Symlinks in it are followed on every access, so a link that is retargeted (or a
Kubernetes Secret volume that is swapped) is picked up; saves go to the file the path currently resolves to. A
`MattStash` object is not meant to be used across `fork()` by threads that were mid-operation, but a forked child gets
fresh locks and never owns the parent's file lock.

The constructor never creates a database. Use `MattStash.create(...)` (what `mattstash setup` calls) to create one;
it returns a ready-to-use instance and `create_with_info(...)` also returns the generated password and any backups.

**Errors.** A missing *secret* is `None`/`False`. Problems with the *database* raise typed exceptions from
`mattstash.utils.exceptions`: `DatabaseNotFoundError`, `DatabaseAccessError` (wrong/missing password, corrupt file) and
`DatabaseLockError`. They are never reported as "not found".

**Thread/process safety.** One `MattStash` object may be shared between threads. Writes hold a cross-process lock,
re-read the file if another writer changed it, and discard in-memory state if saving fails.

### Core Methods

#### `get(title, show_password=False, version=None)`

Retrieve a credential by title.

**Parameters:**
- `title` (str) - Credential name
- `show_password` (bool) - Whether to include actual passwords
- `version` (int, optional) - Specific version to retrieve

**Returns:**
- `dict` for simple secrets: `{"name": str, "value": str, "notes": str}`
- `Credential` object for full credentials
- `None` if not found

**Examples:**
```python
# Simple secret
token = stash.get("api-token", show_password=True)
# Returns: {"name": "api-token", "value": "sk-123456", "notes": None}

# Full credential
db_creds = stash.get("database")
# Returns: Credential object with username, password, url, etc.

# Specific version
old_token = stash.get("api-token", version=1)
```

#### `put(title, **kwargs)`

Store or update a credential.

**Parameters:**
- `title` (str) - Credential name
- `value` (str, optional) - Simple secret value
- `username` (str, optional) - Username field
- `password` (str, optional) - Password field
- `url` (str, optional) - URL field
- `notes` (str, optional) - Notes/comments
- `tags` (list, optional) - List of tags
- `version` (int, optional) - Explicit version number
- `autoincrement` (bool) - Auto-increment version (default: True)

**Returns:**
- `dict` for simple secrets
- `Credential` object for full credentials

**Examples:**
```python
# Simple secret
result = stash.put("api-token", value="sk-123456")

# Full credential
result = stash.put("database",
                   username="dbuser",
                   password="secret123",
                   url="localhost:5432",
                   notes="Production DB",
                   tags=["production", "postgresql"])

# Explicit versioning
result = stash.put("api-token", value="new-token", version=5)
```

#### `delete(title, version=None)`

Delete a credential: the unversioned entry and **all** of its versions, or only one version.

**Parameters:**
- `title` (str) - Credential name
- `version` (int, optional) - delete only this version and keep the others

**Returns:**
- `bool` - True if anything was deleted, False if nothing matched

**Example:**
```python
stash.delete("old-api-key")              # every version
stash.delete("api-token", version=1)     # just api-token@0000000001
```

#### `prune(title, keep)`

Delete all but the newest `keep` versions (`keep >= 1`) of a credential.

**Returns:**
- `list[str]` - the version strings that were deleted (empty if there was nothing to prune)

```python
removed = stash.prune("api-token", keep=3)   # e.g. ["0000000001", "0000000002"]
```

Versions are a history of values, not an audit log: they do not record who changed a secret or when.

#### `list(show_password=False, latest_only=False)`

List credentials.

**Parameters:**
- `show_password` (bool) - Whether to include passwords
- `latest_only` (bool) - collapse versions: each base name appears once, as its latest version, with
  `credential_name` set to the base name and `version` filled in (default: every stored entry, so versions show up
  as `name@0000000001` rows)

**Returns:**
- `list[Credential]` - List of credentials

**Example:**
```python
all_creds = stash.list(show_password=True)
for cred in all_creds:
    print(f"{cred.credential_name}: {cred.username}")
```

### S3 Integration

#### `get_s3_client(title, **kwargs)`

Create a configured boto3 S3 client from stored credentials.

**Parameters:**
- `title` (str) - Credential containing S3 access info
- `region` (str) - AWS region (default: "us-east-1")
- `addressing` (str) - "path" or "virtual" (default: "path")
- `signature_version` (str) - Signature version (default: "s3v4")
- `retries_max_attempts` (int) - Max retries (default: 10)
- `verbose` (bool) - Print the endpoint line to stderr (default: False; library calls are silent, the `s3-test` CLI enables it)

**Returns:**
- `boto3.client` - Configured S3 client

**Example:**
```python
# Get S3 client
s3 = stash.get_s3_client("s3-backup")

# Use the client
s3.upload_file('local.txt', 'my-bucket', 'remote.txt')

# List buckets
buckets = s3.list_buckets()
```

**Required credential format:**
- `username` - AWS Access Key ID
- `password` - AWS Secret Access Key  
- `url` - S3 endpoint URL

### Database Integration

#### `get_db_url(title, **kwargs)`

Generate SQLAlchemy database URL from stored credentials.

**Parameters:**
- `title` (str) - Credential containing database info
- `dialect` (str, optional) - `"postgresql"` (default), `"mysql"` or `"mariadb"`; overrides the credential's
  `dialect` custom property
- `driver` (str, optional) - driver suffix (default: None, i.e. none). Checked against an allow-list per dialect:
  `postgresql`: `psycopg`, `psycopg2`, `asyncpg`, `pg8000`; `mysql`: `pymysql`, `mysqlconnector`, `asyncmy`,
  `aiomysql`; `mariadb`: `mariadbconnector`, `pymysql`. `"auto"` means `psycopg` for PostgreSQL and no suffix for the others
- `mask_password` (bool) - Mask password in URL (default: True)
- `mask_style` (str) - "stars" or "omit" (default: "stars")
- `database` (str, optional) - Database name
- `sslmode_override` (str, optional) - SSL mode override (PostgreSQL only)

**Returns:**
- `str` - SQLAlchemy-compatible database URL

An unknown dialect, a driver that does not belong to the dialect, a missing database name, a bad `host:port`, or
`sslmode` on a non-PostgreSQL dialect raises `ValueError` (the last one is an error rather than silently
dropping a TLS setting). User, password and database name are percent-encoded.

**Example:**
```python
# Generate database URL
db_url = stash.get_db_url("production-db",
                          database="myapp_prod",
                          driver="psycopg")
# Returns: "postgresql+psycopg://user:*****@host:5432/myapp_prod"

# Unmasked URL
db_url = stash.get_db_url("dev-db",
                          database="myapp_dev",
                          mask_password=False)
# Returns: "postgresql://user:realpass@host:5432/myapp_dev"

# MySQL (or put the custom property dialect=mysql on the credential)
db_url = stash.get_db_url("shop-db", dialect="mysql", driver="pymysql", database="shop")
# Returns: "mysql+pymysql://user:*****@host:3306/shop"
```

**Required credential format:**
- `username` - Database username
- `password` - Database password
- `url` - Host and port (e.g., "localhost:5432")
- Custom property `database` or `dbname` (optional if passed as parameter)
- Custom properties `dialect` and `sslmode` (optional; `sslmode` is PostgreSQL only)

### Versioning Methods

#### `list_versions(title)`

Get version history for a credential.

**Parameters:**
- `title` (str) - Base credential name

**Returns:**
- `list[str]` - List of version strings

**Example:**
```python
versions = stash.list_versions("api-token")
# Returns: ["0000000001", "0000000002", "0000000003"]
```

### Utility Methods

#### `hydrate_env(mapping)`

Set `os.environ` variables from stored credentials (only for variables that are not already set).

**Parameters:**
- `mapping` (dict) - Map of `"Title:FIELD"` to the environment variable name. `FIELD` is `AWS_ACCESS_KEY_ID`
  (the username), `AWS_SECRET_ACCESS_KEY` (the password) or a custom property name. The latest version is used.

**Example:**
```python
stash.hydrate_env({
    "s3-backup:AWS_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
    "s3-backup:AWS_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
})
```

#### `resolve_env(prefix=None, mappings=None, *, strip_prefix=True, upper=False)`

Compute environment variables for a set of secrets *without* touching `os.environ`; this is the engine behind
`mattstash env` and `mattstash exec`.

**Parameters:**
- `prefix` (str, optional) - every secret whose base title starts with it becomes a variable. The name is the title
  without the prefix (kept with `strip_prefix=False`), characters outside `[A-Za-z0-9_]` replaced by `_`, upper-cased
  with `upper=True`. `""` selects every secret.
- `mappings` (dict or iterable, optional) - `{"ENVVAR": "TITLE[:FIELD]"}` or an iterable of `"ENVVAR=TITLE[:FIELD]"`
  strings. `FIELD` is `password` (default), `username`, `url`, `notes` or a custom property name; the field is taken
  after the last `:`, so a title containing `:` needs an explicit field.

**Returns:**
- `dict[str, str]` - `{ENVVAR: value}`, from the latest version of each secret, read from one consistent snapshot.
  Nothing is logged or written.

**Raises:** `ValueError` (nothing selected, invalid variable name, a name produced twice, NUL in a value),
`CredentialNotFoundError` (a mapped secret/field value is missing, or the prefix matches nothing) and the usual
database errors.

```python
env = stash.resolve_env("myapp.", upper=True)          # {"DB_PASSWORD": "...", "API_KEY": "..."}
env = stash.resolve_env(mappings={"PGPASSWORD": "production-db", "PGUSER": "production-db:username"})

import os, subprocess
subprocess.run(["./server"], env={**os.environ, **env}, check=True)
```

`mattstash.core.env_vars` also provides `format_shell`, `format_dotenv` and `format_json` (the renderers of
`mattstash env`; shell output is `shlex`-quoted and safe to `eval`).

### Operations

#### `backup(dest=None, *, force=False)`

Write a consistent copy of the database file and return its path. The copy is taken while holding the write lock
(it cannot interleave with a writer), written to a temp file with mode `0600` and renamed into place.

**Parameters:**
- `dest` (str, optional) - a file, or an existing directory (the default name is used inside it). Default:
  `<db>.bak-<UTC timestamp with microseconds>` next to the database (a counter is appended on collision)
- `force` (bool) - replace `dest` if it exists (otherwise `DatabaseExistsError`)

The backup is the encrypted file as it is (it needs no password; the sidecar is not copied). A file that is empty or
lacks the KeePass signature is refused (`DatabaseAccessError`), so `force=True` can never replace the last good backup
with a truncated one. Raises `DatabaseNotFoundError`, `DatabaseLockError`, `DatabaseExistsError` or `MattStashError`
(bad destination, for example a directory that does not exist).

```python
path = stash.backup()                       # /data/mattstash.kdbx.bak-20261007T120000123456Z
stash.backup("/backups/", force=False)
```

#### `rotate_password(new_password, *, backup=False)`

Change the master password. Under the write lock it verifies the current password, optionally copies the file first
(`backup=True`; the copy keeps the *old* password and its path is returned), re-keys and saves, replaces the sidecar
file (atomically, mode 0600, symlinks followed) **right after the re-key**, and then re-opens the file with the new
password to prove it works. The sidecar is only rewritten if it holds the password this database was opened with: one
`.mattstash.txt` serves a whole directory and may belong to another database (a warning says it was left alone).
`self.password` is updated.

**Returns:** the backup path if `backup=True`, otherwise `None`.

**Raises:** `DatabaseAccessError` (wrong current password; nothing changed), `DatabaseLockError`,
`InvalidCredentialError` (empty new password, or edge whitespace while a sidecar will be updated), and
`RotationIncompleteError` if the database *was* re-keyed but something afterwards failed: `SidecarUpdateError` (the
sidecar could not be replaced; the new password is kept in the file named by `staged_path`) or `RekeyVerifyError`
(re-reading failed, for example an I/O error; the database and the sidecar already use the new password). Whenever you
catch `RotationIncompleteError` the new password **is in effect**: make sure it reaches the user. On any exception
`backup_path` (when set) names the pre-rotation backup. An interruption (Ctrl-C) right after the re-key rolls the sidecar
forward instead of discarding the only record of the new password.

```python
stash = MattStash("/data/mattstash.kdbx", password=old_password)
backup_path = stash.rotate_password(new_password, backup=True)
```

Other processes holding the old password (for example a server started with `KDBX_PASSWORD`) can no longer open
the database until they receive the new one.

## Module-Level Functions

For convenience, MattStash provides module-level functions that use a shared instance:

```python
from mattstash import get, put, delete, prune, list_creds, get_s3_client, get_db_url
```

### `get(title, path=None, password=None, show_password=False, version=None)`

Module-level credential retrieval.

```python
from mattstash import get

# Simple usage
cred = get("api-token", show_password=True)

# Custom database
cred = get("api-token", path="/path/to/db.kdbx")
```

### `put(title, path=None, db_password=None, **kwargs)`

Module-level credential storage.

```python
from mattstash import put

# Store simple secret
put("api-token", value="sk-123456")

# Store full credential
put("database", 
    username="user", 
    password="pass", 
    url="localhost:5432")
```

### `delete(title, path=None, password=None, version=None)`

Module-level credential deletion (all versions, or only `version`).

```python
from mattstash import delete

success = delete("old-token")
delete("api-token", version=1)
```

### `prune(title, keep, path=None, password=None)`

Module-level version pruning; returns the deleted version strings.

### `list_creds(path=None, password=None, show_password=False)`

Module-level credential listing.

```python
from mattstash import list_creds

all_creds = list_creds(show_password=True)
```

### `get_s3_client(title, path=None, password=None, **kwargs)`

Module-level S3 client creation.

```python
from mattstash import get_s3_client

s3 = get_s3_client("s3-backup", region="us-west-2")
```

### `get_db_url(title, path=None, password=None, **kwargs)`

Module-level database URL generation (accepts `dialect=` like `MattStash.get_db_url`).

```python
from mattstash import get_db_url

url = get_db_url("prod-db", database="myapp")
```

## Credential Object

The `Credential` class represents a full credential entry:

```python
class Credential:
    credential_name: str
    username: str
    password: str
    url: str
    notes: str
    tags: list[str]
    show_password: bool
    version: str | None
```

### Properties

- `credential_name` - The credential's title/name
- `username` - Username field
- `password` - Password field (masked unless show_password=True)
- `url` - URL field
- `notes` - Notes/comments
- `tags` - List of tags
- `show_password` - Whether passwords are visible

`Credential` also carries `version` (the zero-padded version string, or `None`).

## Error Handling

A missing *secret* is `None` (`get`) or `False` (`delete`). Problems with the database or the call raise
exceptions from `mattstash.utils.exceptions` (all subclasses of `MattStashError`):

```python
from mattstash.utils.exceptions import (
    DatabaseAccessError, DatabaseLockError, DatabaseNotFoundError, MattStashError,
)

try:
    cred = stash.get("nonexistent")
except DatabaseNotFoundError:
    print("No database at that path: run `mattstash setup`")
except DatabaseAccessError:
    print("Wrong/missing password or corrupt database")
except DatabaseLockError:
    print("Another process held the write lock too long")
if cred is None:
    print("No such secret")
```

`db-url` problems (`get_db_url`) and `resolve_env` input problems are `ValueError`; invalid titles/fields are
`InvalidCredentialError`.

## Configuration

### Default Paths

```python
from mattstash import config

print(config.default_db_path)      # ~/.config/mattstash/mattstash.kdbx
print(config.sidecar_basename)     # .mattstash.txt
print(config.version_pad_width)    # 10
```

### Environment Variables

- `KDBX_PASSWORD` - Database password
- `KDBX_PASSWORD_FILE` - File holding the database password
- `MATTSTASH_DB_PATH` - Default database path

Password precedence: explicit `password=` argument > `KDBX_PASSWORD` > `KDBX_PASSWORD_FILE` > sidecar file.

## Best Practices

### Security
```python
# Always use show_password=False for logging
cred = stash.get("sensitive", show_password=False)
print(f"Retrieved {cred.credential_name}")  # Safe to log

# Only show passwords when necessary
actual_cred = stash.get("sensitive", show_password=True)
```

### Error Handling
```python
def safe_get_credential(name):
    try:
        return stash.get(name, show_password=True)
    except Exception as e:
        print(f"Failed to get {name}: {e}")
        return None
```

### Resource Management
```python
# For one-off operations, use module functions
from mattstash import get
cred = get("api-token")

# For multiple operations, use instance
stash = MattStash()
cred1 = stash.get("token1")
cred2 = stash.get("token2")
```
