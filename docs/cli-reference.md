# CLI Reference

Complete command-line interface documentation for MattStash.

## Global Options

Available for all commands:

### Local Mode Options

```bash
--db PATH                    # Path to KeePass database (default: ~/.config/mattstash/mattstash.kdbx)
--password PASSWORD          # Database password (overrides KDBX_PASSWORD, KDBX_PASSWORD_FILE, sidecar)
```

### Server Mode Options

```bash
--server-url URL            # MattStash server URL (enables server mode)
--api-key KEY               # API key for server authentication
```

### Other Options

```bash
--verbose                   # Enable verbose output
```

## Environment Variables

- `MATTSTASH_SERVER_URL` - Server URL (enables server mode)
- `MATTSTASH_API_KEY` - Server API key
- `KDBX_PASSWORD` - Database password (local mode)
- `MATTSTASH_ENABLE_CACHE` - Enable connection caching (true/false)
- `MATTSTASH_CACHE_TTL` - Cache TTL in seconds

## Mode Selection

MattStash CLI operates in one of two modes:

**Local Mode** (default): Direct access to local KeePass database files
- Uses `--db` and `--password` options
- Reads credentials from filesystem
- Default when no `--server-url` is specified

**Server Mode**: HTTP requests to MattStash API server
- Uses `--server-url` and `--api-key` options
- Network-based credential access
- Enabled when `--server-url` is provided or `MATTSTASH_SERVER_URL` environment variable is set
- Local database options (`--db`, `--password`) are ignored in server mode

## Commands

### `setup` - Create a Database

Creates a new KeePass database. This is the **only** command that creates one.

```bash
mattstash setup [--sidecar | --generate | --password-file FILE | --password-stdin]
                [--force [--yes] [--no-backup]]
```

**Master password source** (first match wins): `--password-stdin`, `--password-file`, `--password`,
`KDBX_PASSWORD` / `KDBX_PASSWORD_FILE`, `--sidecar` (random, stored next to the database), `--generate` (random,
printed once), otherwise an interactive prompt (asked twice). Non-interactive runs without any source fail.

**Options:**
- `--sidecar` - generate a password and store it in `<db dir>/.mattstash.txt` (0600). The key then sits beside the database.
- `--generate` - generate a password and print it once; nothing is stored.
- `--password-file FILE` / `--password-stdin` - read the password from a file / stdin.
- `--force` - replace existing files. Asks for confirmation (non-interactive runs need `--yes`) and backs up the
  existing database/sidecar to `<name>.bak-<timestamp>` first.
- `--no-backup` - with `--force`, skip the backup.

**Examples:**
```bash
mattstash setup                                   # prompt
mattstash setup --sidecar                         # convenient single-user setup
mattstash --db /srv/data/mattstash.kdbx setup --password-file /run/secrets/kdbx_password
mattstash setup --force --yes --sidecar           # replace (with backup)
```

**Exit codes:** `0` success, `1` failure, `8` refused to overwrite existing files.

### Exit codes (all commands)

| Code | Meaning |
|------|---------|
| 0 | success |
| 1 | generic failure / invalid input |
| 2 | the requested secret does not exist |
| 3 / 4 | `s3-test`: client creation / `HeadBucket` failed |
| 5 | `db-url`: URL could not be built |
| 6 | database file not found (run `mattstash setup`) |
| 7 | database cannot be opened: wrong/missing password, corrupt file, lock timeout |
| 8 | `setup` refused to overwrite existing files |

### `list` - Show All Credentials

Display all stored credentials.

```bash
mattstash list [--show-password] [--json]
```

**Options:**
- `--show-password` - Include passwords in output
- `--json` - Output in JSON format

**Examples:**
```bash
# Basic list
mattstash list

# Show passwords
mattstash list --show-password

# JSON output for scripting
mattstash list --json
```

**Output (normal):**
```
api-token
production-db    user: dbuser, url: localhost:5432
s3-backup        user: ACCESS_KEY, url: https://s3.amazonaws.com
```

**Output (JSON):**
```json
[
  {
    "name": "api-token",
    "value": "*****",
    "notes": null
  },
  {
    "credential_name": "production-db",
    "username": "dbuser",
    "password": "*****",
    "url": "localhost:5432",
    "notes": "Production database",
    "tags": ["production"]
  }
]
```

### `keys` - List Credential Names

Show only the names/titles of stored credentials.

```bash
mattstash keys [--json]
```

**Options:**
- `--json` - Output in JSON format

**Examples:**
```bash
mattstash keys
```

**Output:**
```
api-token
production-db
s3-backup
```

### `get` - Retrieve Credential

Get a specific credential by name.

```bash
mattstash get <title> [--show-password] [--json]
```

**Arguments:**
- `title` - Name of the credential to retrieve

**Options:**
- `--show-password` - Show actual password values
- `--json` - Output in JSON format

**Examples:**
```bash
# Get simple secret
mattstash get "api-token"

# Get with password visible
mattstash get "production-db" --show-password

# JSON output
mattstash get "s3-backup" --json
```

**Output (simple secret):**
```
api-token: *****
```

**Output (full credential):**
```
production-db
  username: dbuser
  password: *****
  url: localhost:5432
  notes: Production database
  tags: production
```

**Exit codes:**
- `0` - Success
- `2` - Credential not found

### `put` - Store/Update Credential

Create or update a credential. Supports two modes:

#### Simple Secret Mode
```bash
mattstash put <title> --value <secret>
```

#### Full Credential Mode
```bash
mattstash put <title> --fields [--username <user>] [--password <pass>] [--url <url>] [--notes <notes>] [--tag <tag>]
```

**Arguments:**
- `title` - Name for the credential

**Options:**
- `--value` - Store as simple secret (mutually exclusive with --fields)
- `--fields` - Store as full credential (mutually exclusive with --value)
- `--username` - Username field
- `--password` - Password field  
- `--url` - URL field
- `--notes` - Notes/comments
- `--comment` - Alias for --notes
- `--tag` - Add tag (repeatable)
- `--json` - Output result in JSON

**Examples:**
```bash
# Simple secret
mattstash put "api-token" --value "sk-123456789"

# Full credential
mattstash put "database" --fields --username dbuser --password secret123 \
  --url localhost:5432 --notes "Production DB" --tag production

# Update existing (automatically versioned)
mattstash put "api-token" --value "sk-987654321"
```

**Output:**
```
api-token: stored
```

### `delete` - Remove Credential

Delete a credential permanently.

```bash
mattstash delete <title>
```

**Arguments:**
- `title` - Name of credential to delete

**Examples:**
```bash
mattstash delete "old-api-key"
```

**Output:**
```
old-api-key: deleted
```

**Exit codes:**
- `0` - Success
- `2` - Credential not found

### `versions` - Show Version History

Display version history for a credential.

```bash
mattstash versions <title> [--json]
```

**Arguments:**
- `title` - Base name of the credential

**Options:**
- `--json` - Output in JSON format

**Examples:**
```bash
mattstash versions "api-token"
```

**Output:**
```
api-token versions:
  0000000001
  0000000002
  0000000003 (latest)
```

### `s3-test` - Test S3 Connectivity

Create S3 client and optionally test bucket access.

```bash
mattstash s3-test <title> [options]
```

**Arguments:**
- `title` - Name of credential containing S3 access info

**Options:**
- `--region <region>` - AWS region (default: us-east-1)
- `--addressing <style>` - Addressing style: path or virtual (default: path)
- `--signature-version <version>` - Signature version (default: s3v4)
- `--retries-max-attempts <n>` - Max retry attempts (default: 10)
- `--bucket <name>` - Test bucket access with HeadBucket
- `--quiet` - No output, exit code only

**Examples:**
```bash
# Test client creation
mattstash s3-test "s3-backup"

# Test bucket access
mattstash s3-test "s3-backup" --bucket my-bucket

# Custom configuration
mattstash s3-test "minio-server" --region us-west-1 --addressing virtual
```

**Output:**
```
S3 client created successfully
Endpoint: https://s3.amazonaws.com
Region: us-east-1
```

**Exit codes:**
- `0` - Success
- `3` - S3 client creation failed
- `4` - Bucket access failed

### `db-url` - Generate Database URL

Build SQLAlchemy-compatible database connection URL.

```bash
mattstash db-url <title> [options]
```

**Arguments:**
- `title` - Name of credential containing database info

**Options:**
- `--driver <name>` - Database driver (default: psycopg)
- `--database <name>` - Database name (required if not in credential)
- `--mask-password <bool>` - Mask password in output (default: true)

**Examples:**
```bash
# Basic URL generation
mattstash db-url "production-db" --database myapp_prod

# With custom driver
mattstash db-url "mysql-db" --driver mysql --database webapp

# Show actual password
mattstash db-url "dev-db" --database myapp_dev --mask-password false
```

**Output:**
```
postgresql+psycopg://dbuser:*****@localhost:5432/myapp_prod
```

## Environment Variables

- `KDBX_PASSWORD` - Database password (lowest priority)

## Configuration Files

- `~/.credentials/mattstash.kdbx` - Default KeePass database
- `~/.credentials/.mattstash.txt` - Auto-generated password file (0600 permissions)

## Exit Codes Summary

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error (invalid arguments, file permissions, etc.) |
| 2 | Entry not found (get, delete commands) |
| 3 | S3 client creation failed |
| 4 | S3 bucket access failed |
