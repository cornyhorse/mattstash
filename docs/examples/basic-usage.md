# Basic Usage Examples

Getting started with MattStash through practical examples.

## Installation and Setup

```bash
# Install MattStash
pip install mattstash

# First-time setup (automatic)
mattstash list
# Creates ~/.credentials/mattstash.kdbx and password file

# Or explicit setup
mattstash setup
```

## Simple Secrets (CredStash-style)

Perfect for API tokens, passwords, and single values.

### Storing Simple Secrets

```bash
# Store an API token
mattstash put "github-token" --value "ghp_xxxxxxxxxxxxxxxxxxxx"

# Store a password
mattstash put "admin-password" --value "super-secret-123"

# Store with notes
mattstash put "stripe-key" --value "sk_test_xxxx" --notes "Test environment key"
```

### Retrieving Simple Secrets

```bash
# Get value (password masked)
mattstash get "github-token"
# Output: github-token: *****

# Get actual value
mattstash get "github-token" --show-password
# Output: github-token: ghp_xxxxxxxxxxxxxxxxxxxx

# JSON format for scripting
mattstash get "github-token" --json --show-password
# Output: {"name": "github-token", "value": "ghp_xxxxxxxxxxxxxxxxxxxx", "notes": null}
```

### Using in Scripts

```bash
#!/bin/bash
# Deploy script example

API_TOKEN=$(mattstash get "deploy-token" --json --show-password | jq -r .value)
curl -H "Authorization: Bearer $API_TOKEN" https://api.example.com/deploy
```

## Full Credentials

Store complete credential sets with username, password, URL, and metadata.

### Storing Full Credentials

```bash
# Database credentials
mattstash put "production-db" --fields \
  --username "app_user" \
  --password "db_password_123" \
  --url "db.company.com:5432" \
  --notes "Production PostgreSQL database" \
  --tag "production" \
  --tag "database"

# SSH credentials
mattstash put "web-server" --fields \
  --username "deploy" \
  --password "ssh_key_password" \
  --url "web01.company.com:22" \
  --notes "Web server SSH access"

# Web service credentials
mattstash put "admin-panel" --fields \
  --username "admin@company.com" \
  --password "admin_password_456" \
  --url "https://admin.company.com" \
  --notes "Internal admin panel"
```

### Retrieving Full Credentials

```bash
# View credential summary
mattstash get "production-db"
# Output:
# production-db
#   username: app_user
#   password: *****
#   url: db.company.com:5432
#   notes: Production PostgreSQL database
#   tags: production, database

# View with passwords
mattstash get "production-db" --show-password

# JSON for automation
mattstash get "production-db" --json --show-password
```

## Version Management

Track changes to credentials over time.

### Automatic Versioning

```bash
# Initial credential
mattstash put "api-key" --value "key-v1"
# Creates version 0000000001

# Update credential (auto-increments)
mattstash put "api-key" --value "key-v2"
# Creates version 0000000002

# Another update
mattstash put "api-key" --value "key-v3"
# Creates version 0000000003
```

### Explicit Versioning

```bash
# Set specific version
mattstash put "api-key" --value "key-v5" --version 5
# Creates version 0000000005

# View version history
mattstash versions "api-key"
# Output:
# api-key versions:
#   0000000001
#   0000000002
#   0000000003
#   0000000005 (latest)
```

### Retrieving Specific Versions

```bash
# Get latest version (default)
mattstash get "api-key"

# Get specific version
mattstash get "api-key" --version 2

# Compare versions
mattstash get "api-key" --version 1 --show-password
mattstash get "api-key" --version 3 --show-password
```

## Python API Examples

### Basic Operations

```python
from mattstash import MattStash

# Initialize
stash = MattStash()

# Store simple secret
stash.put("api-token", value="sk-123456789")

# Store full credential
stash.put("database",
          username="dbuser",
          password="dbpass123",
          url="localhost:5432",
          notes="Development database",
          tags=["dev", "postgres"])

# Retrieve credentials
token = stash.get("api-token", show_password=True)
print(f"Token: {token['value']}")

db_creds = stash.get("database", show_password=True)
print(f"DB: {db_creds.username}@{db_creds.url}")
```

### Application Integration

```python
import os
from mattstash import get

class DatabaseConfig:
    def __init__(self):
        # Get database credentials
        db_creds = get("app-database", show_password=True)
        
        self.host = db_creds.url.split(':')[0]
        self.port = int(db_creds.url.split(':')[1])
        self.username = db_creds.username
        self.password = db_creds.password
        self.database = db_creds.get_custom_property("database")

# Usage
config = DatabaseConfig()
connection_string = f"postgresql://{config.username}:{config.password}@{config.host}:{config.port}/{config.database}"
```

### Bulk Operations

```python
from mattstash import MattStash

stash = MattStash()

# Store multiple credentials
credentials = [
    ("dev-db", {"username": "dev", "password": "dev123", "url": "dev.db:5432"}),
    ("staging-db", {"username": "staging", "password": "stage123", "url": "staging.db:5432"}),
    ("prod-db", {"username": "prod", "password": "prod123", "url": "prod.db:5432"}),
]

for name, creds in credentials:
    stash.put(name, **creds, tags=["database"])

# List and filter
all_creds = stash.list()
db_creds = [c for c in all_creds if "database" in c.tags]

for cred in db_creds:
    print(f"{cred.credential_name}: {cred.url}")
```

## S3 Integration Examples

### Storing S3 Credentials

```bash
# AWS S3
mattstash put "aws-s3" --fields \
  --username "AKIA..." \
  --password "secret-access-key" \
  --url "https://s3.amazonaws.com" \
  --notes "AWS S3 production account"

# MinIO/Hetzner
mattstash put "hetzner-s3" --fields \
  --username "access-key" \
  --password "secret-key" \
  --url "https://fsn1.your-objectstorage.com" \
  --notes "Hetzner Object Storage"
```

### Testing S3 Connectivity

```bash
# Test client creation
mattstash s3-test "aws-s3"

# Test bucket access
mattstash s3-test "aws-s3" --bucket "my-production-bucket"

# Custom configuration
mattstash s3-test "hetzner-s3" \
  --region "fsn1" \
  --addressing "path" \
  --bucket "backup-data"
```

### Python S3 Usage

```python
from mattstash import get_s3_client

# Get configured S3 client
s3 = get_s3_client("aws-s3")

# Upload file
s3.upload_file('local-file.txt', 'my-bucket', 'remote/path/file.txt')

# Download file
s3.download_file('my-bucket', 'remote/path/file.txt', 'downloaded-file.txt')

# List objects
response = s3.list_objects_v2(Bucket='my-bucket', Prefix='backup/')
for obj in response.get('Contents', []):
    print(obj['Key'])
```

## Database Integration Examples

### Storing Database Credentials

```bash
# PostgreSQL
mattstash put "postgres-prod" --fields \
  --username "app_user" \
  --password "secure_password" \
  --url "db.company.com:5432" \
  --notes "Production PostgreSQL"

# MySQL
mattstash put "mysql-analytics" --fields \
  --username "analytics" \
  --password "analytics_pass" \
  --url "analytics.db.company.com:3306" \
  --notes "Analytics MySQL database"
```

### Generating Database URLs

```bash
# PostgreSQL URL
mattstash db-url "postgres-prod" --database "myapp_production"
# Output: postgresql+psycopg://app_user:*****@db.company.com:5432/myapp_production

# MySQL URL with custom driver
mattstash db-url "mysql-analytics" --database "analytics" --driver "pymysql"
# Output: mysql+pymysql://analytics:*****@analytics.db.company.com:3306/analytics

# Show actual password for development
mattstash db-url "postgres-dev" --database "myapp_dev" --mask-password false
```

### Python Database Usage

```python
from mattstash import get_db_url
from sqlalchemy import create_engine

# Get database URL
db_url = get_db_url("postgres-prod", 
                    database="myapp_production",
                    mask_password=False)

# Create SQLAlchemy engine
engine = create_engine(db_url)

# Use with your ORM
from sqlalchemy.orm import sessionmaker
Session = sessionmaker(bind=engine)
session = Session()
```

## Management Operations

### Listing and Discovery

```bash
# List all credentials
mattstash list

# List with passwords (for backup/migration)
mattstash list --show-password

# List just names
mattstash keys

# JSON output for scripting
mattstash keys --json
```

### Cleanup and Maintenance

```bash
# Delete old credentials
mattstash delete "old-api-key"
mattstash delete "deprecated-service"

# View version history before cleanup
mattstash versions "api-key"

# Keep only latest versions (manual process)
# Note: MattStash doesn't auto-clean old versions
```

### Backup and Migration

```bash
# Export all credentials (JSON)
mattstash list --json --show-password > backup.json

# Export specific credential
mattstash get "important-cred" --json --show-password > important-backup.json

# Copy database file (encrypted backup)
cp ~/.credentials/mattstash.kdbx backup/mattstash-$(date +%Y%m%d).kdbx
```

## Environment Integration

### Shell Integration

```bash
# Add to ~/.bashrc or ~/.zshrc
export GITHUB_TOKEN=$(mattstash get "github-token" --json --show-password | jq -r .value)
export DATABASE_URL=$(mattstash db-url "app-db" --database "myapp" --mask-password false)

# Function for easy access
get_secret() {
    mattstash get "$1" --json --show-password | jq -r .value
}

# Usage
API_KEY=$(get_secret "api-key")
```

### Docker Integration

```dockerfile
# Copy credentials into container
COPY credentials/ /app/credentials/
RUN chmod 600 /app/credentials/.mattstash.txt

# Use in startup script
COPY startup.sh /app/
RUN chmod +x /app/startup.sh
```

```bash
#!/bin/bash
# startup.sh
export DATABASE_URL=$(mattstash --db /app/credentials/mattstash.kdbx db-url "app-db" --database "production" --mask-password false)
export API_TOKEN=$(mattstash --db /app/credentials/mattstash.kdbx get "api-token" --json --show-password | jq -r .value)

exec "$@"
```

These examples demonstrate the flexibility and power of MattStash for various credential management scenarios!
