# Configuration Guide

MattStash configuration options and setup guide.

## Default Configuration

MattStash uses sensible defaults that work out of the box:

```python
# Defaults
Database: ~/.config/mattstash/mattstash.kdbx      # MATTSTASH_DB_PATH or --db to change
Password: none stored by default                  # KDBX_PASSWORD / KDBX_PASSWORD_FILE, or an optional sidecar
                                                  # (~/.config/mattstash/.mattstash.txt, created by `setup --sidecar`)
Version padding: 10 digits (0000000001)
```

## Database Location

### CLI Override
```bash
# Use custom database for all commands
mattstash --db /path/to/custom.kdbx list
mattstash --db /path/to/custom.kdbx get "api-token"
```

### Python API Override
```python
from mattstash import MattStash

# Custom database path
stash = MattStash(path="/path/to/custom.kdbx")

# Module functions with custom path
from mattstash import get
cred = get("api-token", path="/path/to/custom.kdbx")
```

### Environment Variables

Set these to change default behavior:

```bash
export MATTSTASH_DB_PATH=/srv/data/mattstash.kdbx          # default database path
export KDBX_PASSWORD_FILE=/run/secrets/kdbx_password       # database password from a file (preferred)
export KDBX_PASSWORD="your-db-password"                    # database password (visible to child processes)

# Server mode
export MATTSTASH_SERVER_URL=https://mattstash.example.com
export MATTSTASH_API_KEY_FILE=/run/secrets/mattstash_api_key   # or MATTSTASH_API_KEY
export MATTSTASH_ALLOW_INSECURE_HTTP=1    # silence the plain-http warning on a trusted network
```

## Password Management

MattStash resolves the database password from these sources, highest priority first:

1. **Explicit option**: `--db-password-file FILE` (preferred), or `--password PW` / `--db-password PW`
   ```bash
   mattstash --db-password-file ./master-password list
   mattstash --password "explicit-pass" list     # visible in `ps`/shell history: prefer the options below
   ```
   `--db-password` is an alias of `--password`; giving `--password`/`--db-password` together with
   `--db-password-file` is an error. (For `put --fields`, a bare `--password` is the deprecated spelling of
   `--entry-password`; `--db-password*` always means the database password.)

2. **`KDBX_PASSWORD` environment variable**
   ```bash
   export KDBX_PASSWORD="your-db-password"
   ```

3. **`KDBX_PASSWORD_FILE`** - path to a file containing the password (Docker/Kubernetes secrets).
   If it is set but cannot be read, that is an error (no silent fallback).
   ```bash
   export KDBX_PASSWORD_FILE=/run/secrets/kdbx_password
   ```

4. **Sidecar file** `.mattstash.txt` next to the database - only exists if you ran `mattstash setup --sidecar`
   (or have an older install). It is consulted last, so an operator-supplied password can never be
   silently overridden by a stale sidecar.

Empty values are ignored. A warning is logged if the sidecar or the database file is group/world readable.

## Creating a Database

`mattstash setup` is the only way to create a database; no other command, the Python API or the server creates
one implicitly.

```bash
mattstash setup                                     # prompt for a master password
mattstash --db /custom/path.kdbx setup --sidecar    # random password in <db dir>/.mattstash.txt
mattstash setup --password-file F | --password-stdin | --generate
```

If `KDBX_PASSWORD`/`KDBX_PASSWORD_FILE` are set they are used as the master password (nothing random is
generated and no sidecar is written).

### Replacing an existing database

```bash
mattstash setup --force            # asks for confirmation; add --yes for scripts
mattstash setup --force --yes --no-backup
```

`--force` first copies the existing database (and sidecar) to `<name>.bak-<UTC timestamp>` (mode 0600), builds the
new files beside the old ones, and only swaps them in on success. If creation fails the old files are untouched.

## File Permissions

MattStash creates and keeps files private:

```bash
-rw------- (0600) mattstash.kdbx        # also re-applied after every save
-rw------- (0600) .mattstash.txt        # only with --sidecar; created 0600, never briefly world-readable
-rw------- (0600) mattstash.kdbx.lock   # advisory lock file used while writing
drwx------ (0700) <directory>           # only if setup had to create it
```

An existing, looser mode on the database is preserved (never widened) and triggers a warning.

## Concurrency

Writes take an advisory lock (`<db>.lock`), re-read the database if another process changed it, apply the change
and save atomically. Two writers (for example the CLI and the server, or several processes) can therefore not
overwrite each other's changes, and a failed write never leaves phantom state behind. Reads never block on the lock
and pick up external changes automatically. On network filesystems (NFS/SMB) locking is best effort; run a single
writer there.

## Server Mode Configuration

MattStash CLI can connect to a MattStash API server instead of local databases for network-accessible credential storage.

### Enabling Server Mode

```bash
# Via environment variables (recommended)
export MATTSTASH_SERVER_URL="http://mattstash:8000"
export MATTSTASH_API_KEY="your-api-key-here"

# The key from a file instead (not visible in the environment or shell history)
export MATTSTASH_API_KEY_FILE=/run/secrets/mattstash_api_key

# Via command-line flags
mattstash --server-url http://mattstash:8000 --api-key-file ./api-key list
mattstash --server-url http://mattstash:8000 --api-key "key" list       # visible in ps/shell history
```

The API key comes from, first match wins: `--api-key`, `--api-key-file`, `MATTSTASH_API_KEY`,
`MATTSTASH_API_KEY_FILE`. The client verifies TLS certificates and warns once when an `http://` URL points at a host
other than `localhost`/a loopback address, or at any host when an `HTTP_PROXY` applies (the key then travels in clear text); plain HTTP is never refused, and
`MATTSTASH_ALLOW_INSECURE_HTTP=1` silences the warning for a trusted network.

### Mode Detection

Server mode is enabled when `--server-url` is provided or `MATTSTASH_SERVER_URL` environment variable is set. When in server mode:

- Local database options (`--db`, `--password`, `--db-password-file`) are ignored
- All operations are HTTP requests to the server
- Authentication via API key is required
- Credentials are stored/retrieved from the server's backend database

### Server Mode Examples

```bash
# Set up environment
export MATTSTASH_SERVER_URL="http://localhost:8000"
export MATTSTASH_API_KEY="my-secure-api-key"

# All commands now use the server
mattstash get "api-token"
mattstash put "new-secret" --value "secret-value"
mattstash list --show-password

# Override server URL for specific command
mattstash --server-url http://staging-server:8000 get "staging-token"
```

### Switching Between Modes

```bash
# Use local database (unset server variables)
unset MATTSTASH_SERVER_URL
unset MATTSTASH_API_KEY
mattstash list  # Uses local database

# Use server (set server variables)
export MATTSTASH_SERVER_URL="http://server:8000"
export MATTSTASH_API_KEY="key"
mattstash list  # Uses server

# Inline mode selection
mattstash --db ~/.config/mattstash/mattstash.kdbx list  # Local
mattstash --server-url http://server:8000 --api-key key list  # Server
```

### Server Setup

For information about deploying and configuring the MattStash server, see:
- [Server README](../server/README.md) - Deployment and API documentation
- [Server Quick Start](../server/QUICKSTART.md) - Getting started guide

## Versioning Configuration

### Version Padding

All versions are zero-padded to 10 digits by default:

```
0000000001  # Version 1
0000000002  # Version 2
0000000123  # Version 123
```

This ensures proper sorting and consistent naming.

### Auto-increment Behavior

By default, `put` operations auto-increment versions:

```bash
# First time
mattstash put "api-key" --value "v1"    # Creates version 1

# Second time  
mattstash put "api-key" --value "v2"    # Creates version 2

```

An explicit version number is only available from the Python API (`put("api-key", value="v5", version=5)`);
the command line always appends the next version.

## Multi-Database Setup

Use different databases for different environments:

```bash
# Development database
export DEV_DB="/path/to/dev.kdbx"
mattstash --db "$DEV_DB" put "dev-token" --value "dev-123"

# Production database  
export PROD_DB="/path/to/prod.kdbx"
mattstash --db "$PROD_DB" put "prod-token" --value "prod-456"
```

### Python Multi-Database

```python
from mattstash import MattStash

# Separate instances for different environments
dev_stash = MattStash(path="/path/to/dev.kdbx")
prod_stash = MattStash(path="/path/to/prod.kdbx")

dev_token = dev_stash.get("api-token")
prod_token = prod_stash.get("api-token")
```

## Security Considerations

### File System Security

```bash
# Secure the credentials directory
chmod 700 ~/.config/mattstash/

# Verify permissions
ls -la ~/.config/mattstash/
# drwx------ ~/.config/mattstash/
# -rw------- .mattstash.txt
# -rw-r--r-- mattstash.kdbx
```

### Network Storage

**Safe for network storage:**
- KeePass database files (`.kdbx`) - encrypted
- Can be synced via Dropbox, Git, etc.

**NOT safe for network storage:**
- Password sidecar files (`.mattstash.txt`) - plaintext
- Keep local only

### Backup Strategy

```bash
# Backup database (encrypted, safe)
cp ~/.config/mattstash/mattstash.kdbx backup/mattstash-$(date +%Y%m%d).kdbx

# Backup password file (plaintext, secure storage only)
cp ~/.config/mattstash/.mattstash.txt secure-backup/
```

## Custom Properties

Store additional metadata using custom properties:

```bash
# Database credentials with custom properties
mattstash put "prod-db" --fields \
  --username dbuser \
  --entry-password-file ./dbpass.txt \
  --url localhost:5432 \
  --notes "Production database"
  
# Custom properties must be set via Python API
```

```python
# Access custom properties
cred = stash.get("prod-db")
ssl_mode = cred.get_custom_property("sslmode")
```

## Troubleshooting

### Permission Errors

```bash
# Fix directory permissions
chmod 700 ~/.config/mattstash/

# Fix password file permissions  
chmod 600 ~/.config/mattstash/.mattstash.txt
```

### Database Corruption

```bash
# Verify database integrity
mattstash list  # Should work if database is OK

# Restore from the latest backup (made by `mattstash backup`, `rotate-password` or `setup --force`)
ls ~/.config/mattstash/mattstash.kdbx.bak-*
cp ~/.config/mattstash/mattstash.kdbx.bak-<timestamp> ~/.config/mattstash/mattstash.kdbx
```

Do not run `mattstash setup --force` to "repair" a database: it replaces it with an empty one (after taking a
backup).

### Password Issues

```bash
# A stale KDBX_PASSWORD / KDBX_PASSWORD_FILE in the environment beats the sidecar file
unset KDBX_PASSWORD KDBX_PASSWORD_FILE

# Change the master password (re-keys the database and updates the sidecar, if there is one)
mattstash rotate-password            # prompts for the new password; --generate / --new-password-file also work
```

### Path Issues

```bash
# Verify paths
echo $HOME/.config/mattstash/

# Create directory if missing
mkdir -p ~/.config/mattstash/
chmod 700 ~/.config/mattstash/
```

## Integration Examples

### Docker

```dockerfile
# The database may be baked into an image or mounted; the password must NOT be: mount it as a secret at run time
COPY credentials/mattstash.kdbx /app/credentials/
ENV MATTSTASH_DB_PATH=/app/credentials/mattstash.kdbx
ENV KDBX_PASSWORD_FILE=/run/secrets/mattstash_password
```

For services, prefer running the MattStash API server (see `server/README.md`) and reading secrets over HTTP, or
`mattstash exec -- COMMAND` to start the application with its secrets in the environment.

### CI/CD

```yaml
# GitHub Actions example
- name: Setup credentials
  run: |
    umask 077
    printf '%s' "${{ secrets.KDBX_PASSWORD }}" > "$RUNNER_TEMP/mattstash.pw"

- name: Deploy
  env:
    KDBX_PASSWORD_FILE: ${{ runner.temp }}/mattstash.pw
  run: |
    mattstash get "deploy-key" --raw
```

### Systemd Service

```ini
[Unit]
Description=My App
After=network.target

[Service]
Type=simple
User=myapp
ExecStart=/usr/local/bin/myapp
Environment=MATTSTASH_DB_PATH=/etc/myapp/credentials.kdbx
Environment=KDBX_PASSWORD_FILE=/etc/myapp/.password

[Install]
WantedBy=multi-user.target
```

---

## YAML Configuration File Support

**New in v0.2.0** - MattStash now supports YAML configuration files for persistent settings.

### Installation

Configuration file support requires PyYAML:

```bash
pip install 'mattstash[config]'
```

Or install all optional dependencies:

```bash
pip install 'mattstash[all]'
```

### Configuration Priority

Settings are applied in the following order (highest to lowest priority):

1. **CLI Arguments** - Explicit parameters passed to commands
2. **Environment Variables** - `MATTSTASH_*` environment variables  
3. **Configuration File** - YAML config file
4. **Default Values** - Built-in defaults

### Configuration File Locations

MattStash searches for configuration in this order:

1. `~/.config/mattstash/config.yml`
2. `~/.mattstash.yml`
3. `.mattstash.yml` (current directory)

The first file found is used.

### Generating an Example Config

Use the CLI to generate an example configuration file:

```bash
# Generate at default location (~/.config/mattstash/config.yml)
mattstash config

# Generate at custom location
mattstash config --output ~/my-config.yml
```

### Available Configuration Options

```yaml
# MattStash Configuration
# Priority: CLI args > Env vars > Config file > Defaults

database:
  path: ~/.config/mattstash/mattstash.kdbx
  sidecar_basename: .password.txt

versioning:
  pad_width: 10

logging:
  level: INFO
  verbose: false

s3:
  region: us-east-1
  addressing: path
  signature_version: s3v4
  retries: 10

cache:
  enabled: false
  ttl: 300
```

### Team Configuration Example

Create a `.mattstash.yml` in your project repository:

```yaml
database:
  path: ./team-secrets.kdbx
  
s3:
  region: us-west-2
  addressing: virtual

logging:
  level: DEBUG
  verbose: true
```

Team members will automatically use these settings when working in the project directory.

### Environment Variable Mapping

All config options can be set via environment variables:

- `MATTSTASH_DB_PATH` → `database.path`
- `MATTSTASH_SIDECAR_BASENAME` → `database.sidecar_basename`
- `MATTSTASH_VERSION_PAD_WIDTH` → `versioning.pad_width`
- `MATTSTASH_LOG_LEVEL` → `logging.level`
- `MATTSTASH_S3_REGION` → `s3.region`
- `MATTSTASH_S3_ADDRESSING` → `s3.addressing`
- `MATTSTASH_S3_SIGNATURE_VERSION` → `s3.signature_version`
- `MATTSTASH_S3_RETRIES` → `s3.retries`
- `MATTSTASH_ENABLE_CACHE` → `cache.enabled`
- `MATTSTASH_CACHE_TTL` → `cache.ttl`

