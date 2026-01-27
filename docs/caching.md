## Connection Caching

MattStash supports optional connection caching to improve performance for batch operations and scripts that make multiple sequential credential lookups.

### Configuration

Caching is **disabled by default** and must be explicitly enabled.

#### Environment Variables

```bash
# Enable caching
export MATTSTASH_ENABLE_CACHE=true

# Set cache TTL (time-to-live) in seconds (default: 300)
export MATTSTASH_CACHE_TTL=60
```

#### Configuration File

```yaml
# ~/.config/mattstash/config.yml
cache:
  enabled: true
  ttl: 300  # 5 minutes
```

#### Programmatic Configuration

```python
from mattstash import MattStash
from mattstash.credential_store import CredentialStore

# Option 1: Via MattStash (reads from config)
ms = MattStash()

# Option 2: Direct CredentialStore with caching
store = CredentialStore(
    db_path="~/.config/mattstash/mattstash.kdbx",
    password="your-password",
    cache_enabled=True,
    cache_ttl=300  # 5 minutes
)
```

### How It Works

1. **First Lookup**: Entry is fetched from the KeePass database and stored in memory cache with a timestamp
2. **Subsequent Lookups**: If the same entry is requested within the TTL, it's returned from cache without opening the database
3. **Cache Expiration**: After TTL seconds, cached entries are considered stale and removed on next access
4. **Cache Invalidation**: Cache is automatically cleared when the database is saved (put, delete operations)

### Performance Benefits

Caching reduces database I/O operations:

```python
from mattstash.credential_store import CredentialStore
import time

# Without caching (default)
store = CredentialStore(db_path, password, cache_enabled=False)
for i in range(100):
    entry = store.find_entry_by_title("api-key")  # 100 DB operations

# With caching
store = CredentialStore(db_path, password, cache_enabled=True)
for i in range(100):
    entry = store.find_entry_by_title("api-key")  # 1 DB operation + 99 cache hits
```

### Use Cases

**✅ Good use cases for caching:**
- Batch credential retrieval scripts
- Automated deployment scripts that lookup multiple credentials
- CLI tools that make repeated credential requests
- Applications with frequent read-heavy workloads

**❌ Not recommended for:**
- Long-running services (use short TTLs if needed)
- Multi-process applications (cache is per-process)
- Scenarios requiring always-fresh credentials
- Single credential lookups (no performance benefit)

### Cache Management

```python
from mattstash.credential_store import CredentialStore

store = CredentialStore(db_path, password, cache_enabled=True)

# Fetch and cache an entry
entry = store.find_entry_by_title("api-key")

# Manually clear cache if needed
store.clear_cache()

# Cache is automatically cleared on save operations
store.save()
```

### Security Considerations

- **Memory Storage**: Cached entries are stored in process memory (not disk)
- **TTL Expiration**: Old entries are automatically removed after TTL expires
- **Process Isolation**: Each process has its own cache
- **Automatic Invalidation**: Cache is cleared on database modifications

### Configuration Priority

Cache settings follow the standard configuration priority:

1. **Explicit parameters** (highest priority)
   ```python
   CredentialStore(db_path, password, cache_enabled=True, cache_ttl=60)
   ```

2. **Environment variables**
   ```bash
   export MATTSTASH_ENABLE_CACHE=true
   export MATTSTASH_CACHE_TTL=300
   ```

3. **Configuration file**
   ```yaml
   cache:
     enabled: true
     ttl: 300
   ```

4. **Defaults** (lowest priority)
   - `cache_enabled`: `false`
   - `cache_ttl`: `300` seconds (5 minutes)

### Example: Batch Script with Caching

```python
#!/usr/bin/env python3
"""
Deploy script that fetches multiple credentials.
With caching enabled, this is significantly faster.
"""

from mattstash import MattStash

# Enable caching via environment or config file
ms = MattStash()

# Fetch multiple credentials - first lookup hits DB, rest hit cache
api_key = ms.get("api-key")
db_creds = ms.get("database-prod")
s3_access = ms.get("s3-access-key")
auth_token = ms.get("auth-token")

# Use credentials for deployment...
```

### Monitoring Cache Performance

Enable debug logging to see cache hits/misses:

```python
import logging
logging.basicConfig(level=logging.DEBUG)

from mattstash.credential_store import CredentialStore

store = CredentialStore(db_path, password, cache_enabled=True)
entry1 = store.find_entry_by_title("test")  # Logs: No cache debug message (first lookup)
entry2 = store.find_entry_by_title("test")  # Logs: "Cache hit for 'test'"
```

Debug output example:
```
DEBUG:mattstash.credential_store:Successfully opened database
DEBUG:mattstash.credential_store:Cached entry 'test'
DEBUG:mattstash.credential_store:Cache hit for 'test'
DEBUG:mattstash.credential_store:Entry cache cleared
```
