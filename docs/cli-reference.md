# CLI Reference

Complete command-line interface documentation for MattStash.

## Global Options

Available for all commands:

```bash
--db PATH                    # Path to KeePass database (default: ~/.credentials/mattstash.kdbx)
--password PASSWORD          # Database password (overrides sidecar/env)
--verbose                   # Enable verbose output
```

## Commands

### `setup` - Initialize Database

Creates the KeePass database and password sidecar file.

```bash
mattstash setup [--force]
```

**Options:**
- `--force` - Overwrite existing files

**Examples:**
```bash
# Initialize with defaults
mattstash setup

# Force re-initialization
mattstash setup --force

# Custom database location
mattstash --db /path/to/custom.kdbx setup
```

**Output:**
```
Database and sidecar created at ~/.credentials/
```

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
