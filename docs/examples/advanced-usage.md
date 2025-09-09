# Advanced Usage Examples

Advanced patterns and integrations for MattStash.

## Custom Properties and Metadata

Store additional metadata beyond the standard fields using custom properties.

### Setting Custom Properties (Python API)

```python
from mattstash import MattStash

stash = MattStash()

# Store database with custom properties
stash.put("analytics-db",
          username="analytics_user",
          password="secure_pass",
          url="analytics.db.company.com:5432",
          notes="Analytics database with SSL")

# Access the underlying KeePass entry to set custom properties
# Note: This requires direct access to the KeePass entry
```

### Using Custom Properties for Database URLs

```bash
# Store database credentials with custom database property
mattstash put "app-db" --fields \
  --username "app_user" \
  --password "db_password" \
  --url "db.company.com:5432" \
  --notes "Main application database"

# The database name can be stored as a custom property
# This requires manual setup in KeePass client or Python API
```

```python
# Access custom properties
cred = stash.get("app-db")
database_name = cred.get_custom_property("database")
ssl_mode = cred.get_custom_property("sslmode")

# Generate URL using custom properties
db_url = stash.get_db_url("app-db")  # Uses custom "database" property
```

## Multi-Environment Management

Organize credentials across different environments and projects.

### Environment-Specific Databases

```bash
# Development environment
mattstash --db ~/.credentials/dev.kdbx put "api-key" --value "dev-key-123"
mattstash --db ~/.credentials/dev.kdbx put "database" --fields \
  --username "dev_user" --password "dev_pass" --url "localhost:5432"

# Staging environment
mattstash --db ~/.credentials/staging.kdbx put "api-key" --value "staging-key-456"
mattstash --db ~/.credentials/staging.kdbx put "database" --fields \
  --username "staging_user" --password "staging_pass" --url "staging.db:5432"

# Production environment
mattstash --db ~/.credentials/prod.kdbx put "api-key" --value "prod-key-789"
mattstash --db ~/.credentials/prod.kdbx put "database" --fields \
  --username "prod_user" --password "prod_pass" --url "prod.db:5432"
```

### Python Multi-Environment Class

```python
from mattstash import MattStash
import os

class EnvironmentCredentials:
    def __init__(self, environment="dev"):
        self.environment = environment
        db_path = f"~/.credentials/{environment}.kdbx"
        self.stash = MattStash(path=os.path.expanduser(db_path))
    
    def get_database_config(self):
        """Get database configuration for current environment"""
        db_creds = self.stash.get("database", show_password=True)
        return {
            "host": db_creds.url.split(':')[0],
            "port": int(db_creds.url.split(':')[1]),
            "username": db_creds.username,
            "password": db_creds.password,
            "database": db_creds.get_custom_property("database") or f"myapp_{self.environment}"
        }
    
    def get_api_token(self):
        """Get API token for current environment"""
        token_cred = self.stash.get("api-key", show_password=True)
        return token_cred["value"]
    
    def get_s3_client(self):
        """Get S3 client for current environment"""
        return self.stash.get_s3_client("s3-storage")

# Usage
dev_creds = EnvironmentCredentials("dev")
staging_creds = EnvironmentCredentials("staging")
prod_creds = EnvironmentCredentials("prod")

# Get environment-specific configurations
dev_db = dev_creds.get_database_config()
prod_token = prod_creds.get_api_token()
```

## Automated Backup and Synchronization

### Backup Script

```bash
#!/bin/bash
# backup-credentials.sh

BACKUP_DIR="$HOME/secure-backup/credentials"
CREDENTIALS_DIR="$HOME/.credentials"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup encrypted databases (safe for cloud storage)
for db in "$CREDENTIALS_DIR"/*.kdbx; do
    if [[ -f "$db" ]]; then
        filename=$(basename "$db" .kdbx)
        cp "$db" "$BACKUP_DIR/${filename}_${DATE}.kdbx"
        echo "Backed up: $filename"
    fi
done

# Backup password files to secure local storage ONLY
SECURE_LOCAL_BACKUP="$HOME/secure-local-backup"
mkdir -p "$SECURE_LOCAL_BACKUP"
cp "$CREDENTIALS_DIR"/.*.txt "$SECURE_LOCAL_BACKUP/" 2>/dev/null

# Clean old backups (keep last 10)
find "$BACKUP_DIR" -name "*.kdbx" -type f | sort -r | tail -n +11 | xargs rm -f

echo "Backup completed: $BACKUP_DIR"
```

### Git Synchronization (Databases Only)

```bash
#!/bin/bash
# sync-credentials.sh

CREDENTIALS_REPO="$HOME/credentials-sync"
CREDENTIALS_DIR="$HOME/.credentials"

# Initialize git repo for database files only
if [[ ! -d "$CREDENTIALS_REPO/.git" ]]; then
    mkdir -p "$CREDENTIALS_REPO"
    cd "$CREDENTIALS_REPO"
    git init
    
    # Ignore password files (never sync plaintext passwords)
    echo "*.txt" > .gitignore
    echo ".*txt" >> .gitignore
    git add .gitignore
    git commit -m "Initial commit with gitignore"
fi

# Copy database files (encrypted, safe to sync)
cp "$CREDENTIALS_DIR"/*.kdbx "$CREDENTIALS_REPO/" 2>/dev/null

# Commit and push changes
cd "$CREDENTIALS_REPO"
git add *.kdbx
if git diff --staged --quiet; then
    echo "No changes to sync"
else
    git commit -m "Update credentials: $(date)"
    git push origin main  # Configure remote first
    echo "Credentials synced"
fi
```

## Application Integration Patterns

### Django Integration

```python
# settings.py
import os
from mattstash import get, get_db_url

# Get database URL
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ.get('DB_NAME', 'myapp'),
        'USER': os.environ.get('DB_USER'),
        'PASSWORD': os.environ.get('DB_PASSWORD'),
        'HOST': os.environ.get('DB_HOST', 'localhost'),
        'PORT': os.environ.get('DB_PORT', '5432'),
    }
}

# Alternative: Use MattStash directly
try:
    db_creds = get("django-db", show_password=True)
    DATABASES['default'].update({
        'USER': db_creds.username,
        'PASSWORD': db_creds.password,
        'HOST': db_creds.url.split(':')[0],
        'PORT': db_creds.url.split(':')[1],
    })
except Exception:
    pass  # Fall back to environment variables

# Get API keys
STRIPE_SECRET_KEY = get("stripe-secret", show_password=True)["value"]
SENDGRID_API_KEY = get("sendgrid-api", show_password=True)["value"]
```

### FastAPI Integration

```python
from fastapi import FastAPI, Depends
from mattstash import MattStash
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

app = FastAPI()

# Initialize credentials
stash = MattStash()

# Database setup
db_url = stash.get_db_url("api-database", 
                          database="myapi_prod", 
                          mask_password=False)
engine = create_engine(db_url)
SessionLocal = sessionmaker(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# External service clients
def get_s3_client():
    return stash.get_s3_client("api-s3-storage")

def get_api_token(service_name: str):
    cred = stash.get(f"{service_name}-token", show_password=True)
    return cred["value"]

# API endpoints
@app.get("/upload")
async def upload_file(db: Session = Depends(get_db)):
    s3_client = get_s3_client()
    # Use s3_client for file operations
    return {"status": "uploaded"}

@app.get("/external-data")
async def get_external_data():
    api_token = get_api_token("external-service")
    # Use api_token for external API calls
    return {"data": "external_data"}
```

### Docker Compose Integration

```yaml
# docker-compose.yml
version: '3.8'

services:
  app:
    build: .
    environment:
      - MATTSTASH_DB=/app/credentials/app.kdbx
    volumes:
      - ./credentials:/app/credentials:ro
    depends_on:
      - db
      - redis
    command: >
      sh -c "
        export DATABASE_URL=$$(mattstash db-url app-database --database myapp --mask-password false) &&
        export REDIS_URL=$$(mattstash get redis-url --json --show-password | jq -r .value) &&
        python app.py
      "

  db:
    image: postgres:13
    environment:
      - POSTGRES_DB=myapp
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
    secrets:
      - db_password

secrets:
  db_password:
    external: true
```

## Monitoring and Alerting

### Credential Expiry Monitoring

```python
#!/usr/bin/env python3
# check-credential-expiry.py

from mattstash import MattStash
from datetime import datetime, timedelta
import re

def check_credential_expiry():
    stash = MattStash()
    credentials = stash.list()
    
    expiring_soon = []
    expired = []
    
    for cred in credentials:
        # Check for expiry date in notes
        if cred.notes:
            expiry_match = re.search(r'expires?[:\s]*(\d{4}-\d{2}-\d{2})', 
                                   cred.notes, re.IGNORECASE)
            if expiry_match:
                expiry_date = datetime.strptime(expiry_match.group(1), '%Y-%m-%d')
                days_until_expiry = (expiry_date - datetime.now()).days
                
                if days_until_expiry < 0:
                    expired.append((cred.credential_name, expiry_date))
                elif days_until_expiry <= 30:
                    expiring_soon.append((cred.credential_name, expiry_date, days_until_expiry))
    
    # Report findings
    if expired:
        print("🚨 EXPIRED CREDENTIALS:")
        for name, date in expired:
            print(f"  - {name}: expired {date}")
    
    if expiring_soon:
        print("⚠️  EXPIRING SOON:")
        for name, date, days in expiring_soon:
            print(f"  - {name}: expires {date} ({days} days)")
    
    if not expired and not expiring_soon:
        print("✅ All credentials are current")
    
    return len(expired) + len(expiring_soon)

if __name__ == "__main__":
    exit_code = check_credential_expiry()
    exit(1 if exit_code > 0 else 0)
```

### Usage Audit Script

```python
#!/usr/bin/env python3
# audit-credential-usage.py

from mattstash import MattStash
import json
from datetime import datetime

def audit_credentials():
    stash = MattStash()
    credentials = stash.list()
    
    audit_report = {
        "timestamp": datetime.now().isoformat(),
        "total_credentials": len(credentials),
        "by_type": {"simple": 0, "full": 0},
        "by_tags": {},
        "credentials": []
    }
    
    for cred in credentials:
        # Determine type
        cred_type = "simple" if not cred.username and not cred.url else "full"
        audit_report["by_type"][cred_type] += 1
        
        # Count tags
        for tag in cred.tags:
            audit_report["by_tags"][tag] = audit_report["by_tags"].get(tag, 0) + 1
        
        # Add to report
        audit_report["credentials"].append({
            "name": cred.credential_name,
            "type": cred_type,
            "has_url": bool(cred.url),
            "has_notes": bool(cred.notes),
            "tag_count": len(cred.tags),
            "tags": cred.tags
        })
    
    # Save report
    report_file = f"credential_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(audit_report, f, indent=2)
    
    print(f"Audit completed: {report_file}")
    print(f"Total credentials: {audit_report['total_credentials']}")
    print(f"Simple secrets: {audit_report['by_type']['simple']}")
    print(f"Full credentials: {audit_report['by_type']['full']}")

if __name__ == "__main__":
    audit_credentials()
```

## Testing and Development

### Test Credential Setup

```python
# test_credentials.py
import pytest
import tempfile
import os
from mattstash import MattStash

@pytest.fixture
def test_stash():
    """Create a temporary MattStash instance for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test.kdbx")
        password_file = os.path.join(tmpdir, ".test.txt")
        
        # Create test password file
        with open(password_file, 'w') as f:
            f.write("test-password-123")
        os.chmod(password_file, 0o600)
        
        # Initialize test stash
        stash = MattStash(path=db_path, password="test-password-123")
        
        # Pre-populate with test data
        stash.put("test-api-key", value="test-key-123")
        stash.put("test-database",
                  username="testuser",
                  password="testpass",
                  url="localhost:5432",
                  tags=["test"])
        
        yield stash

def test_credential_operations(test_stash):
    # Test retrieval
    api_key = test_stash.get("test-api-key", show_password=True)
    assert api_key["value"] == "test-key-123"
    
    # Test database URL generation
    db_url = test_stash.get_db_url("test-database", database="testdb")
    assert "postgresql://" in db_url
    assert "testuser" in db_url
    assert "localhost:5432" in db_url
    
    # Test listing
    creds = test_stash.list()
    assert len(creds) == 2
```

These advanced examples show how to leverage MattStash for complex credential management scenarios across different environments and applications!
