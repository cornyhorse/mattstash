# MattStash

A simple, CredStash-like interface to KeePass databases for credential management.

## Overview

MattStash provides both CLI and Python API access to KeePass databases, supporting:

- **Simple secrets** (CredStash-style key/value pairs)
- **Full credentials** (username, password, URL, notes, tags)
- **Versioning** with automatic incrementing
- **S3 client helpers** for boto3 integration
- **Database URL builders** for SQLAlchemy connections
- **Auto-bootstrapping** of databases and secure password storage

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

MattStash automatically bootstraps on first use:

```bash
# Creates ~/.credentials/mattstash.kdbx and ~/.credentials/.mattstash.txt
mattstash list
```

Or explicitly:

```bash
mattstash setup
```

### Basic Examples

```bash
# Store a simple secret
mattstash put "api-token" --value "sk-123456789"

# Store full credentials
mattstash put "production-db" --username dbuser --password secret123 \
  --url localhost:5432 --notes "Production PostgreSQL"

# Retrieve credentials
mattstash get "api-token"
mattstash get "production-db" --show-password --json

# List all credentials
mattstash list

# Delete credentials
mattstash delete "old-token"
```

## Server Mode (Optional)

MattStash can run as a network service for containerized environments. The CLI can target either local KeePass databases (default) or a remote MattStash server.

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
```

For server setup and deployment, see [Server Documentation](server/README.md) and [Server Quick Start](server/QUICKSTART.md).

## Features

### Two Storage Modes

**Simple Secrets (CredStash-style)**
- Store single values using `--value`
- Retrieved as `{"name": "key", "value": "secret"}`
- Perfect for API tokens, passwords, etc.

**Full Credentials**
- Store complete credential sets with `--fields`
- Include username, password, URL, notes, tags
- Retrieved as structured credential objects

### Versioning

All entries support automatic versioning:

```bash
# Auto-increment version
mattstash put "api-key" --value "new-value"

# Explicit version
mattstash put "api-key" --value "specific-value" --version 5

# View version history
mattstash versions "api-key"
```

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
# Store S3 credentials
mattstash put "s3-backup" --username ACCESS_KEY --password SECRET_KEY \
  --url https://s3.amazonaws.com

# Test connectivity
mattstash s3-test "s3-backup" --bucket my-bucket
```

### Database URL Building

Generate SQLAlchemy-compatible connection URLs:

```bash
# Store database credentials
mattstash put "prod-db" --username dbuser --password dbpass \
  --url localhost:5432

# Generate connection URL
mattstash db-url "prod-db" --database myapp_prod
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `setup` | Initialize database and password file |
| `list` | Show all credentials |
| `keys` | List credential names only |
| `get <name>` | Retrieve a specific credential |
| `put <name>` | Store or update a credential |
| `delete <name>` | Remove a credential |
| `versions <name>` | Show version history |
| `s3-test <name>` | Test S3 connectivity |
| `db-url <name>` | Generate database URL |
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
```

See [Python API Documentation](docs/python-api.md) for complete reference.

## API Server (Optional)

MattStash includes an optional FastAPI-based HTTP service for accessing credentials over the network. This is useful for containerized environments where multiple services need secure access to credentials.

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
- **Secure defaults**: Auto-generated passwords with 0600 file permissions
- **No plaintext**: Passwords never stored in plaintext files
- **Versioning**: Complete audit trail of credential changes

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | General error |
| 2 | Entry not found |
| 3 | S3 client creation failed |
| 4 | S3 bucket access failed |

## License

MattStash is licensed under the [MIT License](LICENSE).

### Important Dependency Note

This project depends on [`pykeepass`](https://github.com/libkeepass/pykeepass), which is licensed under GPL-3.0. Due to this dependency, **any redistribution of MattStash must comply with GPL-3.0 terms**.

**In practice:**
- ✅ Use MattStash internally in your projects
- ✅ Modify and integrate MattStash for internal use
- ⚠️ Distributing software that includes MattStash requires GPL-3.0 compliance

Optional dependencies (`boto3`, `sqlalchemy`, `psycopg`) use permissive licenses compatible with MIT.
