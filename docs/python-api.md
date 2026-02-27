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
MattStash(path=None, password=None)
```

**Parameters:**
- `path` (str, optional) - Path to KeePass database. Default: `~/.credentials/mattstash.kdbx`
- `password` (str, optional) - Database password. If None, reads from sidecar file or environment

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

#### `delete(title)`

Delete a credential.

**Parameters:**
- `title` (str) - Credential name

**Returns:**
- `bool` - True if deleted, False if not found

**Example:**
```python
success = stash.delete("old-api-key")
if success:
    print("Deleted successfully")
```

#### `list(show_password=False)`

List all credentials.

**Parameters:**
- `show_password` (bool) - Whether to include passwords

**Returns:**
- `list[Credential]` - List of all credentials

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
- `verbose` (bool) - Enable verbose output (default: True)

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
- `driver` (str, optional) - Database driver (default: None)
- `mask_password` (bool) - Mask password in URL (default: True)
- `mask_style` (str) - "stars" or "omit" (default: "stars")
- `database` (str, optional) - Database name
- `sslmode_override` (str, optional) - SSL mode override

**Returns:**
- `str` - SQLAlchemy-compatible database URL

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
```

**Required credential format:**
- `username` - Database username
- `password` - Database password
- `url` - Host and port (e.g., "localhost:5432")
- Custom property `database` or `dbname` (optional if passed as parameter)

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

Set environment variables from stored credentials.

**Parameters:**
- `mapping` (dict) - Map of env var names to credential specs

**Example:**
```python
# Set environment variables
stash.hydrate_env({
    "DATABASE_URL": "prod-db:url",
    "API_TOKEN": "api-creds:password",
    "S3_KEY": "s3-backup:username"
})
```

## Module-Level Functions

For convenience, MattStash provides module-level functions that use a shared instance:

```python
from mattstash import get, put, delete, list_creds, get_s3_client, get_db_url
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

### `delete(title, path=None, password=None)`

Module-level credential deletion.

```python
from mattstash import delete

success = delete("old-token")
```

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

Module-level database URL generation.

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
```

### Properties

- `credential_name` - The credential's title/name
- `username` - Username field
- `password` - Password field (masked unless show_password=True)
- `url` - URL field
- `notes` - Notes/comments
- `tags` - List of tags
- `show_password` - Whether passwords are visible

### Methods

#### `get_custom_property(key)`

Get custom property value from the underlying KeePass entry.

```python
cred = stash.get("database")
db_name = cred.get_custom_property("database")
```

## Error Handling

MattStash raises standard Python exceptions:

```python
try:
    cred = stash.get("nonexistent")
except FileNotFoundError:
    print("Database file not found")
except PermissionError:
    print("Cannot access database file")
except ValueError as e:
    print(f"Invalid data: {e}")
```

## Configuration

### Default Paths

```python
from mattstash import config

print(config.default_db_path)      # ~/.credentials/mattstash.kdbx
print(config.sidecar_basename)     # .mattstash.txt
print(config.version_pad_width)    # 10
```

### Environment Variables

- `KDBX_PASSWORD` - Database password (lowest priority)

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
