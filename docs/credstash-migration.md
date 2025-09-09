# CredStash Migration Guide

MattStash provides a CredStash-compatible interface while offering additional features and improved security. This guide shows how to migrate from CredStash to MattStash and highlights the areas where it serves as a drop-in replacement.

## Overview Comparison

| Feature | CredStash | MattStash |
|---------|-----------|-----------|
| **Storage Backend** | AWS DynamoDB + KMS | KeePass database (local/encrypted) |
| **Authentication** | AWS credentials | Database password (auto-generated) |
| **Simple Secrets** | ✅ Key/value pairs | ✅ Compatible interface |
| **Versioning** | ✅ Automatic | ✅ Automatic + manual |
| **Encryption** | AWS KMS | KeePass encryption (AES-256) |
| **Dependencies** | AWS SDK, boto3 | pykeepass only |
| **Offline Access** | ❌ Requires AWS | ✅ Works offline |
| **Full Credentials** | ❌ Values only | ✅ Username, password, URL, notes |
| **Tags/Metadata** | ❌ Limited | ✅ Full support |
| **Cost** | AWS charges | ✅ Free |

## Drop-in Replacement Areas

### 1. Basic Operations (100% Compatible)

**CredStash Commands:**
```bash
# Store a secret
credstash put mykey myvalue

# Retrieve a secret
credstash get mykey

# List all keys
credstash list

# Delete a secret
credstash delete mykey
```

**MattStash Equivalents (Direct Replacement):**
```bash
# Store a secret
mattstash put "mykey" --value "myvalue"

# Retrieve a secret  
mattstash get "mykey" --show-password

# List all keys
mattstash keys

# Delete a secret
mattstash delete "mykey"
```

### 2. Versioning (Compatible)

**CredStash:**
```bash
# Automatic versioning
credstash put mykey newvalue

# Get specific version
credstash get mykey -v 1

# List versions
credstash list -v
```

**MattStash:**
```bash
# Automatic versioning
mattstash put "mykey" --value "newvalue"

# Get specific version
mattstash get "mykey" --version 1

# List versions
mattstash versions "mykey"
```

### 3. Python API (Nearly Compatible)

**CredStash Python API:**
```python
import credstash

# Store secret
credstash.putSecret("mykey", "myvalue")

# Retrieve secret
secret = credstash.getSecret("mykey")

# List secrets
secrets = credstash.listSecrets()

# Delete secret
credstash.deleteSecret("mykey")
```

**MattStash Python API:**
```python
from mattstash import put, get, list_creds, delete

# Store secret (compatible)
put("mykey", value="myvalue")

# Retrieve secret (compatible)
secret = get("mykey", show_password=True)["value"]

# List secrets (different return format)
secrets = [cred.credential_name for cred in list_creds()]

# Delete secret (compatible)
delete("mykey")
```

## Migration Strategies

### 1. Simple Script Migration

Create a migration script to transfer secrets from CredStash to MattStash:

```python
#!/usr/bin/env python3
# migrate-from-credstash.py

import credstash
from mattstash import put

def migrate_secrets():
    """Migrate all secrets from CredStash to MattStash"""
    
    # Get all secrets from CredStash
    try:
        secrets = credstash.listSecrets()
        print(f"Found {len(secrets)} secrets in CredStash")
        
        migrated = 0
        for secret_name in secrets:
            try:
                # Get the secret value
                value = credstash.getSecret(secret_name)
                
                # Store in MattStash
                put(secret_name, value=value)
                
                print(f"✅ Migrated: {secret_name}")
                migrated += 1
                
            except Exception as e:
                print(f"❌ Failed to migrate {secret_name}: {e}")
        
        print(f"\nMigration completed: {migrated}/{len(secrets)} secrets migrated")
        
    except Exception as e:
        print(f"Failed to access CredStash: {e}")
        print("Make sure AWS credentials are configured")

if __name__ == "__main__":
    migrate_secrets()
```

### 2. Wrapper for Gradual Migration

Create a wrapper that tries MattStash first, falls back to CredStash:

```python
# credential_wrapper.py
"""
Wrapper to gradually migrate from CredStash to MattStash
"""

from mattstash import get as mattstash_get, put as mattstash_put
import credstash

def get_secret(name, show_password=True):
    """Get secret from MattStash first, fallback to CredStash"""
    try:
        # Try MattStash first
        result = mattstash_get(name, show_password=show_password)
        if result:
            return result["value"] if isinstance(result, dict) else result.password
    except Exception:
        pass
    
    try:
        # Fallback to CredStash
        return credstash.getSecret(name)
    except Exception:
        pass
    
    return None

def put_secret(name, value):
    """Store secret in MattStash (primary) and optionally CredStash"""
    # Store in MattStash
    mattstash_put(name, value=value)
    
    # Optionally also store in CredStash for backwards compatibility
    # credstash.putSecret(name, value)

# Usage in your application
API_TOKEN = get_secret("api-token")
DATABASE_PASSWORD = get_secret("db-password")
```

## Key Differences to Consider

### 1. Storage Location

**CredStash:**
- Stores data in AWS DynamoDB
- Requires AWS credentials and internet connectivity
- Data distributed across AWS infrastructure

**MattStash:**
- Stores data in local KeePass database
- Works offline
- Database file can be synced/backed up as needed

### 2. Authentication Model

**CredStash:**
```bash
# Requires AWS credentials
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"

credstash get mykey
```

**MattStash:**
```bash
# Auto-generates and manages database password
mattstash get "mykey"

# Or explicit password
mattstash --password "custom-password" get "mykey"
```

### 3. Advanced Features

MattStash offers features beyond CredStash's simple key/value model:

```bash
# Full credential storage (not available in CredStash)
mattstash put "database" --fields \
  --username "dbuser" \
  --password "dbpass" \
  --url "db.company.com:5432" \
  --notes "Production database" \
  --tag "production"

# S3 client integration (not available in CredStash)
mattstash put "s3-backup" --fields \
  --username "ACCESS_KEY" \
  --password "SECRET_KEY" \
  --url "https://s3.amazonaws.com"

# Test S3 connectivity
mattstash s3-test "s3-backup" --bucket "my-bucket"

# Generate database URLs
mattstash db-url "database" --database "myapp_prod"
```

## Migration Checklist

### Pre-Migration

- [ ] Install MattStash: `pip install mattstash`
- [ ] Test MattStash setup: `mattstash setup`
- [ ] Backup CredStash data: `credstash list > credstash-backup.txt`
- [ ] Document current CredStash usage patterns

### Migration Process

- [ ] Run migration script to transfer secrets
- [ ] Update application code to use MattStash
- [ ] Test applications with MattStash
- [ ] Update deployment scripts/CI/CD
- [ ] Update documentation

### Post-Migration

- [ ] Verify all secrets migrated correctly
- [ ] Test application functionality
- [ ] Set up MattStash backup strategy
- [ ] Remove CredStash dependencies
- [ ] Clean up AWS DynamoDB tables (optional)

## Code Examples: Before and After

### Simple Secret Management

**Before (CredStash):**
```python
import credstash

class Config:
    def __init__(self):
        self.api_token = credstash.getSecret("api-token")
        self.db_password = credstash.getSecret("db-password")
        self.stripe_key = credstash.getSecret("stripe-secret-key")
```

**After (MattStash):**
```python
from mattstash import get

class Config:
    def __init__(self):
        self.api_token = get("api-token", show_password=True)["value"]
        self.db_password = get("db-password", show_password=True)["value"]
        self.stripe_key = get("stripe-secret-key", show_password=True)["value"]
```

### Environment Variable Population

**Before (CredStash):**
```bash
#!/bin/bash
export API_TOKEN=$(credstash get api-token)
export DB_PASSWORD=$(credstash get db-password)
export STRIPE_KEY=$(credstash get stripe-key)

python app.py
```

**After (MattStash):**
```bash
#!/bin/bash
export API_TOKEN=$(mattstash get "api-token" --json --show-password | jq -r .value)
export DB_PASSWORD=$(mattstash get "db-password" --json --show-password | jq -r .value)
export STRIPE_KEY=$(mattstash get "stripe-key" --json --show-password | jq -r .value)

python app.py
```

### Deployment Scripts

**Before (CredStash):**
```python
import credstash
import subprocess

def deploy():
    # Get deployment key
    deploy_key = credstash.getSecret("deploy-key")
    
    # Deploy application
    subprocess.run([
        "ssh", "-i", deploy_key, 
        "user@server", "deploy.sh"
    ])
```

**After (MattStash):**
```python
from mattstash import get
import subprocess

def deploy():
    # Get deployment key
    deploy_key = get("deploy-key", show_password=True)["value"]
    
    # Deploy application
    subprocess.run([
        "ssh", "-i", deploy_key,
        "user@server", "deploy.sh"
    ])
```

## Benefits of Migration

### 1. **Cost Savings**
- No AWS charges for DynamoDB storage and KMS operations
- Especially beneficial for high-volume secret access

### 2. **Improved Security**
- Local encryption instead of cloud storage
- No network traffic for secret retrieval
- Complete control over encryption keys

### 3. **Enhanced Functionality**
- Full credential objects (username, password, URL, notes)
- Tags and metadata support
- S3 and database integration helpers
- Better versioning control

### 4. **Operational Benefits**
- Works offline
- No AWS dependency
- Faster secret retrieval
- Better debugging and auditing

### 5. **Development Experience**
- Consistent interface across environments
- No AWS configuration required for development
- Better testing capabilities

## Compatibility Matrix

| CredStash Feature | MattStash Support | Notes |
|-------------------|-------------------|-------|
| `putSecret()` | ✅ Fully compatible | Use `put(name, value=...)` |
| `getSecret()` | ✅ Fully compatible | Use `get(name, show_password=True)["value"]` |
| `deleteSecret()` | ✅ Fully compatible | Use `delete(name)` |
| `listSecrets()` | ✅ Compatible | Returns different format |
| Version history | ✅ Enhanced | Better version management |
| Encryption contexts | ⚠️ Not applicable | Uses KeePass encryption |
| IAM permissions | ⚠️ Not applicable | Uses file system permissions |
| Region support | ⚠️ Not applicable | Local storage |

## Troubleshooting Migration

### Common Issues

**1. AWS Credentials Not Found**
```bash
# CredStash error
NoCredentialsError: Unable to locate credentials

# Solution: Run migration on machine with AWS access
```

**2. Different Return Formats**
```python
# CredStash returns string
secret = credstash.getSecret("mykey")  # Returns: "myvalue"

# MattStash returns dict for simple secrets
secret = get("mykey", show_password=True)  # Returns: {"name": "mykey", "value": "myvalue"}
secret_value = secret["value"]  # Extract value
```

**3. Version Number Differences**
```python
# CredStash versions start at 1
credstash.getSecret("mykey", version=1)

# MattStash versions start at 1 but use different format
mattstash get "mykey" --version 1  # Gets version 0000000001
```

### Migration Verification

```python
#!/usr/bin/env python3
# verify-migration.py

import credstash
from mattstash import get

def verify_migration():
    """Verify that all CredStash secrets are available in MattStash"""
    
    credstash_secrets = credstash.listSecrets()
    missing = []
    mismatched = []
    
    for secret_name in credstash_secrets:
        try:
            # Get values from both systems
            credstash_value = credstash.getSecret(secret_name)
            mattstash_result = get(secret_name, show_password=True)
            mattstash_value = mattstash_result["value"] if isinstance(mattstash_result, dict) else mattstash_result.password
            
            if credstash_value != mattstash_value:
                mismatched.append(secret_name)
            else:
                print(f"✅ {secret_name}: values match")
                
        except Exception as e:
            missing.append(secret_name)
            print(f"❌ {secret_name}: not found in MattStash")
    
    if missing:
        print(f"\n⚠️  Missing secrets: {missing}")
    if mismatched:
        print(f"\n⚠️  Mismatched values: {mismatched}")
    
    if not missing and not mismatched:
        print("\n🎉 Migration verification successful!")

if __name__ == "__main__":
    verify_migration()
```

This migration guide provides a comprehensive path from CredStash to MattStash, highlighting compatibility areas and providing practical migration strategies.
