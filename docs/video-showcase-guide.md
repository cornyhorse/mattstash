# MattStash Video Showcase Guide

This document outlines video demonstrations for showcasing MattStash's features using terminalizer. Each section represents a focused video that can be embedded on different parts of the website.

## Video 1: Quick Start & Setup (30-45 seconds)
*Perfect for: Landing page hero section*

**Purpose:** Show how easy it is to get started with MattStash
**Target audience:** First-time visitors

### Demo Script:
```bash
# Show installation
pip install mattstash

# First use - explicit setup to show bootstrap
mattstash setup
# Shows: "Database created: ~/.config/mattstash/mattstash.kdbx"
#        "Password file created: ~/.config/mattstash/.mattstash.txt"

# Store first secret
mattstash put "api-token" --value "sk-123456789"
# Shows: api-token: stored

# Retrieve it
mattstash get "api-token" --show-password
# Shows: api-token: sk-123456789

# Show it's there
mattstash keys
# Shows: api-token
```

**Key messages:**
- Zero configuration required
- Explicit setup shows what's created
- Simple put/get operations
- Works immediately after install

---

## Video 2: Simple Secrets vs Full Credentials (60-90 seconds)
*Perfect for: Features overview page*

**Purpose:** Demonstrate the two storage modes and their use cases
**Target audience:** Users evaluating credential storage options

### Demo Script:
```bash
# === Simple Secrets (CredStash-style) ===
echo "=== Simple Secrets ==="

# API tokens
mattstash put "github-token" --value "ghp_xxxxxxxxxxxxxxxxxxxx"
mattstash put "stripe-key" --value "sk_test_xxxxxxxxxxxx"

# Show simple retrieval
mattstash get "github-token"
# Shows: github-token: *****

# JSON output for scripting
mattstash get "stripe-key" --json --show-password
# Shows: {"name": "stripe-key", "value": "sk_test_...", "notes": null}

# === Full Credentials ===
echo "=== Full Credentials ==="

# Database credentials (FIXED: --fields not -- fields)
mattstash put "production-db" --fields \
  --username "app_user" \
  --password "secure_db_pass" \
  --url "db.company.com:5432" \
  --notes "Production PostgreSQL" \
  --tag "production" \
  --tag "database"

# Show structured output
mattstash get "production-db"
# Shows formatted credential with all fields

# Show what we have
mattstash keys
# Shows: github-token, stripe-key, production-db
```

**Key messages:**
- Two modes: simple values vs structured credentials
- Simple secrets perfect for API keys
- Full credentials for complex service access
- Rich metadata with tags and notes

---

## Video 3: Versioning & History (45-60 seconds)
*Perfect for: Advanced features section*

**Purpose:** Show how MattStash tracks credential changes over time
**Target audience:** Teams managing production credentials

### Demo Script:
```bash
# Create initial credential
mattstash put "api-key" --value "key-v1-initial"

# Update it several times (auto-versioning)
mattstash put "api-key" --value "key-v2-updated"
mattstash put "api-key" --value "key-v3-rotated"

# Show version history
mattstash versions "api-key"
# Shows: api-key versions: 0000000001, 0000000002, 0000000003 (latest)

# Retrieve specific version
mattstash get "api-key" --version 1 --show-password
# Shows: api-key: key-v1-initial

# Get latest
mattstash get "api-key" --show-password  
# Shows: api-key: key-v3-rotated

# Explicit version number
mattstash put "api-key" --value "key-v5-explicit" --version 5
mattstash versions "api-key"
# Shows jump to version 5
```

**Key messages:**
- Automatic versioning on updates
- Complete audit trail
- Access any historical version
- Explicit version control available

---

## Video 4: S3 Integration Demo (60-75 seconds)
*Perfect for: AWS/Cloud integration page*

**Purpose:** Demonstrate S3 credential storage and client creation
**Target audience:** DevOps teams using AWS/S3

### Demo Script:
```bash
# Store S3 credentials
mattstash put "aws-s3" --fields \
  --username "AKIA..." \
  --password "secret-access-key" \
  --url "https://s3.amazonaws.com" \
  --notes "AWS S3 production account"

# Store MinIO/alternative S3
mattstash put "backup-storage" --fields \
  --username "minioaccess" \
  --password "miniosecret" \
  --url "https://minio.company.com" \
  --notes "Internal backup storage"

# Test S3 connectivity
mattstash s3-test "aws-s3"
# Shows: S3 client created successfully

# Test with bucket
mattstash s3-test "backup-storage" --bucket "daily-backups"
# Shows: Bucket access verified

# Show Python integration
cat > s3_demo.py << 'EOF'
from mattstash import get_s3_client

# Get ready-to-use S3 client
s3 = get_s3_client("aws-s3")
print("✅ S3 client ready for use")

# List buckets
buckets = s3.list_buckets()
print(f"Found {len(buckets['Buckets'])} buckets")
EOF

python s3_demo.py
```

**Key messages:**
- Store S3 credentials securely
- Test connectivity before deployment
- Ready-to-use boto3 clients
- Works with AWS and S3-compatible services

---

## Video 5: Database URL Generation (45-60 seconds)
*Perfect for: Database integration section*

**Purpose:** Show database credential management and URL building
**Target audience:** Application developers using databases

### Demo Script:
```bash
# Store database credentials
mattstash put "app-database" --fields \
  --username "myapp_user" \
  --password "secure_db_password" \
  --url "db.production.com:5432" \
  --notes "Production PostgreSQL database"

# Generate SQLAlchemy URL
mattstash db-url "app-database" --database "myapp_production"
# Shows: postgresql+psycopg://myapp_user:*****@db.production.com:5432/myapp_production

# Show different drivers
mattstash db-url "app-database" --database "myapp_prod" --driver "asyncpg"
# Shows: postgresql+asyncpg://...

# Unmask for development
mattstash db-url "app-database" --database "myapp_dev" --mask-password false
# Shows: postgresql+psycopg://myapp_user:secure_db_password@...

# Show Python usage
cat > db_demo.py << 'EOF'
from mattstash import get_db_url
from sqlalchemy import create_engine

# Get database URL
db_url = get_db_url("app-database", 
                    database="myapp_production",
                    mask_password=False)

# Create engine
engine = create_engine(db_url)
print("✅ Database engine created successfully")
EOF

python db_demo.py
```

**Key messages:**
- Secure database credential storage
- Generate SQLAlchemy URLs instantly
- Support for multiple database drivers
- Safe password masking for logs

---

## Video 6: CLI Power Features (75-90 seconds)
*Perfect for: CLI reference section*

**Purpose:** Show advanced CLI features for power users
**Target audience:** DevOps engineers, CI/CD builders

### Demo Script:
```bash
# Show all keys
mattstash keys

# JSON output for scripting
mattstash list --json | jq '.[] | select(.tags[]? == "production")'

# Environment integration
export API_TOKEN=$(mattstash get "github-token" --json --show-password | jq -r .value)
echo "Token loaded: ${API_TOKEN:0:8}..."

# Bulk operations demo
echo "=== Storing multiple environments ==="

# Development
mattstash put "dev-db" --fields --username "dev" --password "dev123" \
  --url "localhost:5432" --tag "development"

# Staging  
mattstash put "staging-db" --fields --username "staging" --password "stage123" \
  --url "staging.db:5432" --tag "staging"

# Production
mattstash put "prod-db" --fields --username "prod" --password "prod123" \
  --url "prod.db:5432" --tag "production"

# Show organized listing
mattstash list

# Cleanup demo
mattstash delete "old-credential"
# Shows: old-credential: deleted

# Show version cleanup workflow
mattstash versions "api-key"
# Shows multiple versions exist
```

**Key messages:**
- Powerful JSON output for automation
- Environment variable integration
- Bulk credential management
- Version cleanup and maintenance

---

## Video 7: Security & Migration (60-75 seconds)
*Perfect for: Security/migration documentation page*

**Purpose:** Highlight security features and CredStash migration
**Target audience:** Security-conscious teams, CredStash users

### Demo Script:
```bash
# Show secure file permissions
ls -la ~/.credentials/
# Shows: -rw------- .mattstash.txt, -rw-r--r-- mattstash.kdbx

# Show multiple database support
echo "=== Multi-environment security ==="

# Development database (separate file)
mattstash --db ~/.credentials/dev.kdbx put "dev-secret" --value "dev-value"

# Production database (separate file)  
mattstash --db ~/.credentials/prod.kdbx put "prod-secret" --value "prod-value"

# Show they're isolated
mattstash --db ~/.credentials/dev.kdbx keys
mattstash --db ~/.credentials/prod.kdbx keys

# CredStash migration demo
echo "=== CredStash Migration ==="

# Show the migration script in action
cat > migrate_demo.py << 'EOF'
# Simulated CredStash to MattStash migration
from mattstash import put

# Simulated CredStash secrets
credstash_secrets = {
    "api-key": "credstash-api-value",
    "db-password": "credstash-db-pass"
}

print("Migrating from CredStash...")
for name, value in credstash_secrets.items():
    put(name, value=value)
    print(f"✅ Migrated: {name}")

print("Migration complete!")
EOF

python migrate_demo.py

# Verify migration
mattstash list
```

**Key messages:**
- Secure file permissions by default
- Multi-environment isolation
- Easy migration from CredStash
- Local encryption vs cloud dependency

---

## Video 8: Python API Deep Dive (90-120 seconds)
*Perfect for: Developer documentation/API reference*

**Purpose:** Show comprehensive Python integration patterns
**Target audience:** Python developers building applications

### Demo Script:
```bash
# Create comprehensive Python demo
cat > python_demo.py << 'EOF'
from mattstash import MattStash, get, put, get_s3_client, get_db_url

print("=== MattStash Python API Demo ===")

# 1. Class-based usage
print("\n1. Using MattStash class:")
stash = MattStash()

# Store different types of credentials
stash.put("app-config", 
          username="admin",
          password="secret123", 
          url="https://admin.myapp.com",
          notes="Admin panel access",
          tags=["admin", "web"])

print("✅ Stored full credential")

# 2. Module-level functions
print("\n2. Using module functions:")
put("simple-token", value="abc123xyz")
token = get("simple-token", show_password=True)
print(f"✅ Retrieved token: {token['value']}")

# 3. S3 integration
print("\n3. S3 integration:")
# First store S3 creds
put("demo-s3", 
    username="ACCESS_KEY", 
    password="SECRET_KEY",
    url="https://s3.amazonaws.com")

try:
    s3_client = get_s3_client("demo-s3")
    print("✅ S3 client created successfully")
except Exception as e:
    print(f"ℹ️ S3 demo (boto3 not installed): {e}")

# 4. Database URL generation
print("\n4. Database URL generation:")
put("demo-db",
    username="dbuser",
    password="dbpass", 
    url="localhost:5432")

db_url = get_db_url("demo-db", database="myapp", mask_password=False)
print(f"✅ Database URL: {db_url}")

# 5. Application integration pattern
print("\n5. Application config pattern:")
class AppConfig:
    def __init__(self):
        self.api_token = get("simple-token", show_password=True)["value"]
        self.admin_creds = get("app-config", show_password=True)
        self.database_url = get_db_url("demo-db", database="myapp")
        
    def display(self):
        print(f"  API Token: {self.api_token[:8]}...")
        print(f"  Admin User: {self.admin_creds.username}")
        print(f"  Database: {self.database_url.split('@')[1].split('/')[0]}")

config = AppConfig()
config.display()
print("✅ Application configuration loaded")

print("\n🎉 Python API demo complete!")
EOF

python python_demo.py
```

**Key messages:**
- Flexible API: class-based or module functions
- Seamless integration with existing applications  
- Type-safe credential objects
- Ready-to-use service clients

---

## Production Tips for Videos

### Terminal Setup
```bash
# Clean terminal appearance
export PS1="$ "
clear

# Consistent timing
# Use terminalizer with --config for consistent timing
terminalizer record demo1 --config custom-config.yml
```

### Video Organization Strategy

**Landing Page:** Video 1 (Quick Start)
**Features Page:** Videos 2, 3 (Core Features)  
**Integration Docs:** Videos 4, 5 (S3, Database)
**CLI Reference:** Video 6 (Power Features)
**Migration Guide:** Video 7 (Security/Migration)
**API Docs:** Video 8 (Python Deep Dive)

### Key Visual Elements to Highlight

1. **Speed**: Show instant responses, no waiting
2. **Security**: File permissions, masked passwords
3. **Simplicity**: Minimal commands, clear output
4. **Power**: JSON output, scripting integration
5. **Compatibility**: Multiple environments, migration

Each video should be focused, demonstrate real value, and leave viewers wanting to try the specific feature shown.
