# MattStash API - Quick Reference

## Setup (5 minutes)

```bash
cd server

# 1. Create secrets
echo "my-api-key-12345" > secrets/api_keys.txt
echo "my-kdbx-password" > secrets/kdbx_password.txt

# 2. Copy your KeePass database
cp ~/my-passwords.kdbx data/mattstash.kdbx

# 3. Start server
docker-compose up -d

# 4. Test
curl http://localhost:8000/health
```

## Common API Calls

```bash
# Set your API key
export API_KEY="my-api-key-12345"
export API_URL="http://localhost:8000/api/v1"

# List all credentials (passwords masked)
curl -H "X-API-Key: $API_KEY" "$API_URL/credentials"

# Get specific credential with password
curl -H "X-API-Key: $API_KEY" \
  "$API_URL/credentials/my-db?show_password=true"

# Get database URL
curl -H "X-API-Key: $API_KEY" \
  "$API_URL/db-url/my-db?driver=psycopg&database=myapp"

# List versions of a credential
curl -H "X-API-Key: $API_KEY" \
  "$API_URL/credentials/my-db/versions"

# Get specific version
curl -H "X-API-Key: $API_KEY" \
  "$API_URL/credentials/my-db?version=1&show_password=true"

# Filter credentials by prefix
curl -H "X-API-Key: $API_KEY" \
  "$API_URL/credentials?prefix=db-"
```

## Python Client

```python
import requests

class MattStashClient:
    def __init__(self, url, api_key):
        self.url = url
        self.headers = {"X-API-Key": api_key}
    
    def get(self, name, show_password=True):
        r = requests.get(
            f"{self.url}/credentials/{name}",
            headers=self.headers,
            params={"show_password": show_password}
        )
        r.raise_for_status()
        return r.json()
    
    def list(self, prefix=None):
        params = {"prefix": prefix} if prefix else {}
        r = requests.get(
            f"{self.url}/credentials",
            headers=self.headers,
            params=params
        )
        r.raise_for_status()
        return r.json()["credentials"]
    
    def get_db_url(self, name, driver="psycopg", database=None):
        params = {"driver": driver, "mask_password": False}
        if database:
            params["database"] = database
        r = requests.get(
            f"{self.url}/db-url/{name}",
            headers=self.headers,
            params=params
        )
        r.raise_for_status()
        return r.json()["url"]

# Usage
client = MattStashClient(
    url="http://mattstash-api:8000/api/v1",
    api_key="my-api-key"
)

# Get credential
cred = client.get("db-prod")
print(f"Username: {cred['username']}")
print(f"Password: {cred['password']}")

# Get database URL
db_url = client.get_db_url("db-prod", database="myapp")
print(f"Database URL: {db_url}")
```

## Docker Compose Integration

```yaml
version: "3.8"

services:
  # Your application
  myapp:
    image: myapp:latest
    environment:
      MATTSTASH_URL: http://mattstash:8000/api/v1
      MATTSTASH_KEY: ${MATTSTASH_API_KEY}
    networks:
      - backend
    depends_on:
      - mattstash
    # Get database URL on startup
    command: |
      sh -c '
        export DB_URL=$$(curl -s -H "X-API-Key: $$MATTSTASH_KEY" \
          "$$MATTSTASH_URL/db-url/mydb?mask_password=false" | jq -r .url)
        python app.py
      '

  # MattStash API
  mattstash:
    image: mattstash-api:latest
    volumes:
      - ./mattstash-data:/data:ro
      - ./mattstash-secrets:/secrets:ro
    environment:
      MATTSTASH_DB_PATH: /data/mattstash.kdbx
      KDBX_PASSWORD_FILE: /secrets/kdbx_password.txt
      MATTSTASH_API_KEYS_FILE: /secrets/api_keys.txt
    networks:
      - backend

networks:
  backend:
    driver: bridge
```

## Troubleshooting

### Can't connect to server
```bash
# Check if running
docker-compose ps

# Check logs
docker-compose logs mattstash-api

# Test health endpoint
curl http://localhost:8000/health
```

### Authentication errors
```bash
# Verify API key
cat secrets/api_keys.txt

# Test with correct key
curl -H "X-API-Key: $(cat secrets/api_keys.txt | head -1)" \
  http://localhost:8000/api/v1/credentials
```

### Credential not found
```bash
# List all available credentials
curl -H "X-API-Key: $API_KEY" \
  http://localhost:8000/api/v1/credentials | jq '.credentials[].name'
```

## API Documentation

Once running, visit:
- Swagger UI: http://localhost:8000/api/v1/docs
- ReDoc: http://localhost:8000/api/v1/redoc

## Security Notes

✅ **Production Checklist**:
- [ ] Use file-based secrets (not env vars)
- [ ] Enable TLS (reverse proxy or built-in)
- [ ] Restrict network access (not public internet)
- [ ] Rotate API keys regularly
- [ ] Monitor access logs
- [ ] Use read-only volume mounts
- [ ] Don't log passwords
- [ ] Keep Docker image updated

❌ **Never**:
- Expose on public internet without TLS
- Commit secrets to git
- Use same API key everywhere
- Log credential values
