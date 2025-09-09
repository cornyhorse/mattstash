# Configuration Guide

MattStash configuration options and setup guide.

## Default Configuration

MattStash uses sensible defaults that work out of the box:

```python
# Default paths
Database: ~/.credentials/mattstash.kdbx
Password: ~/.credentials/.mattstash.txt
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
# Database password (lowest priority)
export KDBX_PASSWORD="your-db-password"
```

## Password Management

MattStash uses a priority system for database passwords:

1. **Explicit parameter** (highest priority)
   ```bash
   mattstash --password "explicit-pass" list
   ```

2. **Sidecar file** (auto-generated)
   ```
   ~/.credentials/.mattstash.txt  # 0600 permissions
   ```

3. **Environment variable** (lowest priority)
   ```bash
   export KDBX_PASSWORD="fallback-password"
   ```

## Auto-Bootstrap Process

On first use, MattStash automatically:

1. Creates `~/.credentials/` directory
2. Generates a strong random password
3. Writes password to `.mattstash.txt` with 0600 permissions
4. Creates empty KeePass database at default location

### Manual Bootstrap

Force re-initialization:

```bash
# Initialize with defaults
mattstash setup

# Initialize with custom location
mattstash --db /custom/path.kdbx setup

# Force overwrite existing
mattstash setup --force
```

## File Permissions

MattStash sets secure permissions automatically:

```bash
# Password sidecar file
-rw------- (0600) ~/.credentials/.mattstash.txt

# Database file  
-rw-r--r-- (0644) ~/.credentials/mattstash.kdbx
```

The database file uses KeePass encryption, so broader read permissions are acceptable.

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

# Explicit version
mattstash put "api-key" --value "v5" --version 5  # Creates version 5
```

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
chmod 700 ~/.credentials/

# Verify permissions
ls -la ~/.credentials/
# drwx------ ~/.credentials/
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
cp ~/.credentials/mattstash.kdbx backup/mattstash-$(date +%Y%m%d).kdbx

# Backup password file (plaintext, secure storage only)
cp ~/.credentials/.mattstash.txt secure-backup/
```

## Custom Properties

Store additional metadata using custom properties:

```bash
# Database credentials with custom properties
mattstash put "prod-db" --fields \
  --username dbuser \
  --password secret123 \
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
chmod 700 ~/.credentials/

# Fix password file permissions  
chmod 600 ~/.credentials/.mattstash.txt
```

### Database Corruption

```bash
# Verify database integrity
mattstash list  # Should work if database is OK

# Re-create if corrupted
rm ~/.credentials/mattstash.kdbx ~/.credentials/.mattstash.txt
mattstash setup
```

### Password Issues

```bash
# Clear cached password
unset KDBX_PASSWORD

# Regenerate password file
rm ~/.credentials/.mattstash.txt
mattstash setup --force
```

### Path Issues

```bash
# Verify paths
echo $HOME/.credentials/

# Create directory if missing
mkdir -p ~/.credentials/
chmod 700 ~/.credentials/
```

## Integration Examples

### Docker

```dockerfile
# Copy database into container
COPY credentials/mattstash.kdbx /app/credentials/
COPY credentials/.mattstash.txt /app/credentials/

# Set permissions
RUN chmod 600 /app/credentials/.mattstash.txt

# Use in application
ENV MATTSTASH_DB=/app/credentials/mattstash.kdbx
```

### CI/CD

```yaml
# GitHub Actions example
- name: Setup credentials
  run: |
    mkdir -p ~/.credentials
    echo "${{ secrets.KDBX_PASSWORD }}" > ~/.credentials/.mattstash.txt
    chmod 600 ~/.credentials/.mattstash.txt
    
- name: Deploy
  run: |
    # MattStash will use the password file automatically
    mattstash get "deploy-key"
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
Environment=MATTSTASH_DB=/etc/myapp/credentials.kdbx
Environment=KDBX_PASSWORD_FILE=/etc/myapp/.password

[Install]
WantedBy=multi-user.target
```
