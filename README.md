# MattStash

A simple, CredStash-like interface to KeePass databases for credential management.

## Overview

MattStash provides both CLI and Python API access to KeePass databases, supporting:

- **Simple secrets** (CredStash-style key/value pairs)
- **Full credentials** (username, password, URL, notes, tags)
- **Versioning** with automatic incrementing (a history of values, not an audit log)
- **Secrets without argv**: values and passwords from stdin, files or the environment
- **Scripting and containers**: `get --raw`, `env` and `exec` hand secrets to scripts, pods and containers
- **S3 client helpers** for boto3 integration
- **Database URL builders** for SQLAlchemy connections (PostgreSQL, MySQL, MariaDB)
- **Explicit, safe database creation** (`mattstash setup`) with private file modes and backups
- **Operations**: consistent `backup`, master-password `rotate-password`, version `prune`

## Quick Start

### Installation

```bash
# Core functionality
pip install mattstash

# With S3 support
pip install "mattstash[s3]"

# With YAML configuration file support
pip install "mattstash[config]"

# With all optional features
pip install "mattstash[all]"
```

### First Use

Create a database once, explicitly. `mattstash setup` is the only command that ever creates one, so a
mistyped `--db` path or an unmounted volume can never silently produce a fresh, empty database.

```bash
# Prompts for a master password (twice) and creates ~/.config/mattstash/mattstash.kdbx
mattstash setup

# Non-interactive alternatives
mattstash setup --sidecar                    # random password stored in <db dir>/.mattstash.txt (0600)
mattstash setup --password-file /run/secrets/kdbx_password
echo "$PW" | mattstash setup --password-stdin
KDBX_PASSWORD=... mattstash setup            # or KDBX_PASSWORD_FILE=...
mattstash setup --generate                   # random password, printed once
```

Every other command opens the database with, in order: `--password`/`--db-password`/`--db-password-file`,
`KDBX_PASSWORD`, `KDBX_PASSWORD_FILE`, then the sidecar file (if you chose `--sidecar`). A missing database or a wrong
password is reported as such (exit codes 6 and 7), never as "secret not found" (exit code 2).

> **Security note:** with `--sidecar` the key sits next to the database. That protects against copying the
> `.kdbx` alone (for example in a backup or cloud sync) but not against anyone who can read the directory.
> For services prefer `KDBX_PASSWORD_FILE` pointing at a file in a *different* mount.

### Basic Examples

```bash
# Store a simple secret: the value from stdin (or --value-file FILE), not from the command line
printf '%s' "$TOKEN" | mattstash put "api-token" --value -

# Store a full credential: the password from a file (or --entry-password-stdin)
mattstash put "production-db" --username dbuser --entry-password-file ./db-password \
  --url localhost:5432 --notes "Production PostgreSQL"

# Retrieve credentials
mattstash get "api-token"                        # masked
mattstash get "production-db" --show-password --json
mattstash get "api-token" --raw                  # only the value, for scripts

# List all credentials
mattstash list

# Delete credentials
mattstash delete "old-token"
```

### Keep secrets off the command line

Arguments are visible to every local user (`ps`, `/proc`) and end up in your shell history, so MattStash accepts
secrets from stdin, files and the environment as well:

| Instead of | Use |
|------------|-----|
| `put NAME --value SECRET` | `put NAME --value -` (stdin) or `put NAME --value-file FILE` |
| `put NAME --fields --password PW` (deprecated) | `--entry-password-file FILE` or `--entry-password-stdin` |
| `--password PW` (database) | `--db-password-file FILE`, `KDBX_PASSWORD_FILE` or `KDBX_PASSWORD` |
| `--api-key KEY` (server) | `--api-key-file FILE`, `MATTSTASH_API_KEY_FILE` or `MATTSTASH_API_KEY` |

One trailing newline is removed from stdin/file input, and empty input is rejected. `--password`/`--db-password` is the
*database* password; `--entry-password*` is the password stored *in an entry*.

### Scripts, containers and Kubernetes

```bash
# One value, for a script
TOKEN=$(mattstash get "api-token" --raw)
USER=$(mattstash get "production-db" --raw --field username)

# Secrets as environment variables (shell-safe: eval cannot be tricked by a value)
eval "$(mattstash env --prefix myapp/ --upper)"            # myapp/db-password -> DB_PASSWORD
mattstash env --map PGPASSWORD=production-db --map PGUSER=production-db:username --format dotenv

# Run a command with the secrets in its environment (nothing touches the disk or stdout;
# the command's exit status is preserved)
mattstash exec --prefix myapp/ --upper -- ./server --port 8080
```

`env` and `exec` also work against a MattStash server (`--server-url`). See the
[CLI reference](docs/cli-reference.md#env---print-secrets-as-environment-variables) for the naming rules, formats
and a Kubernetes example, and the [CredStash migration guide](docs/credstash-migration.md) for the
`credstash env` / `getall` equivalents.

### Operations

```bash
mattstash backup                                  # consistent, private (0600) copy: <db>.bak-<timestamp>
mattstash rotate-password --new-password-file ./new-master-password   # re-key (after a backup) and update the sidecar
mattstash prune "api-key" --keep 5                # keep only the newest 5 versions
mattstash delete "api-key" --version 2            # delete a single version
```

`backup`, `rotate-password` and `prune` work on the database file and are not available in server mode.

## Server Mode (Optional)

MattStash can run as a network service for containerized environments. The CLI can target either local KeePass databases (default) or a remote MattStash server.

### Running the Server

The API server is distributed as a Docker image — it is **not** a CLI subcommand.

```bash
docker run -d \
  -e MATTSTASH_DB_PATH=/data/mattstash.kdbx \
  -e KDBX_PASSWORD=<password> \
  -e MATTSTASH_API_KEY=<api-key> \
  -v /path/to/data:/data:ro \
  -p 8000:8000 \
  ghcr.io/cornyhorse/mattstash:latest
```

The server exposes a health check at `/api/health` and credential endpoints under `/api/v1/`.

> **Tip:** Run `mattstash server` for a quick-reference of these instructions.

### Using CLI with Server

```bash
# Set server URL and API key
export MATTSTASH_SERVER_URL="http://localhost:8000"
export MATTSTASH_API_KEY="your-api-key"

# Now all commands use the server
mattstash get "api-token"
mattstash list

# Or specify inline
mattstash --server-url http://localhost:8000 --api-key "key" get "api-token"

# Prefer a file for the key (visible to nobody else, not in shell history)
mattstash --server-url http://localhost:8000 --api-key-file /run/secrets/mattstash_api_key get "api-token"
export MATTSTASH_API_KEY_FILE=/run/secrets/mattstash_api_key
```

The client verifies TLS certificates. Using a plain `http://` URL for a host other than `localhost` logs a warning
(the API key then travels in clear text); set `MATTSTASH_ALLOW_INSECURE_HTTP=1` to silence it for a trusted network such as
a compose or cluster network. See the [CLI reference](docs/cli-reference.md#mode-selection) for what works in server mode.

For full server setup, deployment, and Docker Compose examples, see [Server Documentation](server/README.md) and [Server Quick Start](server/QUICKSTART.md).

## Features

### Two Storage Modes

**Simple Secrets (CredStash-style)**
- Store single values using `--value`
- Retrieved as `{"name": "key", "value": "secret"}`
- Perfect for API tokens, passwords, etc.

**Full Credentials**
- Store complete credential sets with `--fields` (inferred when you give `--username`, `--url` or `--entry-password*`)
- Include username, password, URL, notes, tags
- Retrieved as structured credential objects

### Versioning

Every `put` creates a new version automatically; reads return the latest unless you ask for one:

```bash
# Auto-increment version
mattstash put "api-key" --value-file ./new-value

# Read a specific version, view the history
mattstash get "api-key" --version 1
mattstash versions "api-key"

# Housekeeping
mattstash delete "api-key" --version 1     # delete one version
mattstash prune "api-key" --keep 3         # keep the newest three
mattstash delete "api-key"                 # delete the secret and all its versions
```

Versions are a **history of values, not an audit log**: they do not record who changed a secret or when.

### Connection Caching

Optional performance optimization for batch operations:

```bash
# Enable caching (disabled by default)
export MATTSTASH_ENABLE_CACHE=true
export MATTSTASH_CACHE_TTL=300  # 5 minutes

# Or via configuration file
mattstash config  # Generate ~/.config/mattstash/config.yml
```

**Benefits:**
- Reduces database I/O for repeated lookups
- Ideal for scripts fetching multiple credentials
- Automatic cache invalidation on database changes
- TTL-based expiration for freshness

See [docs/caching.md](docs/caching.md) for details.

### S3 Integration

Store S3 credentials and get ready-to-use boto3 clients:

```bash
# Store S3 credentials (secret key from a file)
mattstash put "s3-backup" --username ACCESS_KEY --entry-password-file ./secret-key \
  --url https://s3.amazonaws.com

# Test connectivity (the endpoint line goes to stderr; --quiet prints nothing)
mattstash s3-test "s3-backup" --bucket my-bucket
```

### Database URL Building

Generate SQLAlchemy-compatible connection URLs for PostgreSQL (default), MySQL and MariaDB:

```bash
# Store database credentials (password from a file)
mattstash put "prod-db" --username dbuser --entry-password-file ./db-password \
  --url localhost:5432

# Generate connection URL
mattstash db-url "prod-db" --database myapp_prod
# postgresql+psycopg://dbuser@localhost:5432/myapp_prod

# MySQL / MariaDB: --dialect (or the custom property "dialect" on the credential) and an allow-listed --driver
mattstash db-url "shop-db" --dialect mysql --driver pymysql --database shop
```

`sslmode` (a custom property) is PostgreSQL-only; use `sslmode=require` in production.

## CLI Commands

| Command | Description |
|---------|-------------|
| `setup` | Create the database (the only command that does) |
| `list` | Show all credentials |
| `keys` | List credential names only |
| `get <name>` | Retrieve a credential (`--raw` / `--field` for scripts) |
| `put <name>` | Store or update a credential (`--value -`, `--value-file`, `--entry-password*`) |
| `delete <name>` | Remove a credential (`--version N` for one version) |
| `prune <name> --keep N` | Keep only the newest N versions (local only) |
| `versions <name>` | Show version history |
| `env` | Print secrets as environment variables (`shell`, `dotenv`, `json`) |
| `exec -- cmd` | Run a command with secrets in its environment |
| `backup [dest]` | Consistent, private copy of the database file (local only) |
| `rotate-password` | Change the master password (local only) |
| `s3-test <name>` | Test S3 connectivity |
| `db-url <name>` | Generate database URL (`--dialect postgresql\|mysql\|mariadb`) |
| `config` | Generate example configuration file |

See [CLI Documentation](docs/cli-reference.md) for complete command reference.

### Configuration Files

MattStash supports YAML configuration files for persistent settings:

```bash
# Generate example config
mattstash config

# Edit configuration
vi ~/.config/mattstash/config.yml
```

Configuration priority: CLI args > Environment variables > Config file > Defaults

See [Configuration Guide](docs/configuration.md) for details.


## Python API

```python
from mattstash import MattStash

# Initialize
stash = MattStash()

# Store simple secret
stash.put("api-token", value="sk-123456789")

# Store full credential
stash.put("database", 
          username="dbuser", 
          password="secret", 
          url="localhost:5432")

# Retrieve
token = stash.get("api-token")
db_creds = stash.get("database", show_password=True)

# S3 client
s3_client = stash.get_s3_client("s3-backup")

# Database URL
db_url = stash.get_db_url("database", database="myapp")

# Environment variables for a set of secrets (what `mattstash env` / `exec` use)
env = stash.resolve_env("myapp/", upper=True)

# Operations
stash.backup()
stash.rotate_password(new_password, backup=True)
stash.prune("api-token", keep=3)
```

See [Python API Documentation](docs/python-api.md) for complete reference.

## API Server (Optional)

MattStash includes an optional FastAPI-based HTTP service for accessing credentials over the network. This is useful for containerized environments where multiple services need secure access to credentials.

**Docker image:** `ghcr.io/cornyhorse/mattstash:latest`

**Features:**
- 🔒 API key authentication
- 🐳 Docker and Kubernetes ready
- 📊 Rate limiting and audit logging
- 🚀 Read-only by default (secure)

See the [Server README](server/README.md) for setup and deployment instructions.

## Documentation

- [CLI Reference](docs/cli-reference.md) - Complete command documentation
- [Python API](docs/python-api.md) - Python interface guide
- [Examples](docs/examples/) - Usage examples and tutorials
- [Configuration](docs/configuration.md) - Setup and configuration options

## Security

- **Encrypted storage**: All data stored in KeePass database with strong encryption
- **Private files**: databases, sidecar files and backups are created `0600`
- **No secrets on argv**: values and passwords can come from stdin, files or the environment (see above)
- **Version history**: older values are kept as versions (there is no who/when audit log)
- **Careful output**: values are masked unless you ask (`--show-password`, `--raw`, `env`); secret values are never
  logged and never appear in error messages

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error / invalid input / not supported in server mode |
| 2 | Entry not found |
| 3 | S3 client creation failed |
| 4 | S3 bucket access failed |
| 5 | `db-url`: URL could not be built |
| 6 | Database file not found (run `mattstash setup`) |
| 7 | Database cannot be opened (wrong/missing password, corrupt file, lock timeout) |
| 8 | `setup` / `backup` refused to overwrite existing files |
| 126, 127 | `exec`: command not executable / not found (otherwise the command's own status) |

## License

MattStash is licensed under the [MIT License](LICENSE).

### Important Dependency Note

This project depends on [`pykeepass`](https://github.com/libkeepass/pykeepass), which is licensed under GPL-3.0. Due to this dependency, **any redistribution of MattStash must comply with GPL-3.0 terms**.

**In practice:**
- ✅ Use MattStash internally in your projects
- ✅ Modify and integrate MattStash for internal use
- ⚠️ Distributing software that includes MattStash requires GPL-3.0 compliance

Optional dependencies (`boto3`, `sqlalchemy`, `psycopg`) use permissive licenses compatible with MIT.
