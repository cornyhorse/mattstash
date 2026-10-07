# MattStash API - Quick Reference

## Setup (5 minutes)

The server is **read-only by default**: it serves the credentials that are already in the database and refuses
`POST`/`DELETE` with `405`. Writes are an explicit opt-in (see [Write mode](#write-mode-opt-in)).

```bash
cd server
mkdir -p data secrets

# 1. Secrets. API keys must be at least 32 characters; the server refuses weaker ones.
(umask 077; openssl rand -base64 32 > secrets/api_keys.txt)
(umask 077; openssl rand -base64 32 > secrets/kdbx_password.txt)

# 2. The database. Only `mattstash setup` creates one (pip install mattstash); the server never does.
mattstash --db data/mattstash.kdbx setup --password-file secrets/kdbx_password.txt
#    ...then add what the services need with `mattstash put` (see ../docs/cli-reference.md), after
#    `export KDBX_PASSWORD_FILE=secrets/kdbx_password.txt`
#    (or copy an existing database to data/mattstash.kdbx and put its password in secrets/kdbx_password.txt)

# 3. Start (builds the image from this checkout)
docker compose up -d --build

# 4. Test
curl http://127.0.0.1:8000/health    # liveness: process is up
curl http://127.0.0.1:8000/ready     # readiness: database opened (503 if not)
```

`./start.sh` does steps 1 (API key only) and 3-4 for you, and tells you what is missing. The container runs as
`${MATTSTASH_UID:-1000}:${MATTSTASH_GID:-1000}`; `start.sh` sets those to your uid/gid so the files in `data/` and
`secrets/` are readable.

Keep the master password in `secrets/`, **not** in `data/`. Do not use `mattstash setup --sidecar` for a service:
a `.mattstash.txt` next to the database defeats the separate secrets mount.

## Write mode (opt-in)

```bash
docker compose -f docker-compose.yml -f docker-compose.writable.yml up -d --build
```

Single instance only, and `data/` must be writable by the container user (the server creates `<db>.lock` and a
temporary file next to the database on every write). Never run two writers on one database file. In Kubernetes use
`k8s/writable/` (one replica, `Recreate`, PVC).

## Common API Calls

```bash
# Set your API key (the first non-comment line of the keys file)
export API_KEY="$(head -n1 secrets/api_keys.txt)"
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

# Write mode only: create / delete (405 otherwise)
curl -X POST -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"value": "s3cret"}' "$API_URL/credentials/new-secret"
curl -X DELETE -H "X-API-Key: $API_KEY" "$API_URL/credentials/new-secret"
```

## Python Client

```python
import os

import requests


class MattStashClient:
    def __init__(self, url, api_key):
        self.url = url
        self.headers = {"X-API-Key": api_key}

    def get(self, name, show_password=True):
        r = requests.get(
            f"{self.url}/credentials/{name}",
            headers=self.headers,
            params={"show_password": show_password},
            timeout=10,
        )
        r.raise_for_status()
        return r.json()

    def list(self, prefix=None):
        params = {"prefix": prefix} if prefix else {}
        r = requests.get(
            f"{self.url}/credentials",
            headers=self.headers,
            params=params,
            timeout=10,
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
            params=params,
            timeout=10,
        )
        r.raise_for_status()
        return r.json()["url"]


# Usage: the key comes from the environment / a secret, never from source code
client = MattStashClient(
    url="http://mattstash-api:8000/api/v1",
    api_key=os.environ["MATTSTASH_API_KEY"],
)

cred = client.get("db-prod")
print(f"Username: {cred['username']}")

db_url = client.get_db_url("db-prod", database="myapp")
```

## Docker Compose Integration

Your application joins the same network as the API. The production file keeps that network `internal: true`
(no outside access, no published ports); see `docker-compose.prod.yml`.

```yaml
services:
  # Your application
  myapp:
    image: myapp:latest
    environment:
      MATTSTASH_SERVER_URL: http://mattstash-api:8000
      MATTSTASH_API_KEY: ${MATTSTASH_API_KEY:?set MATTSTASH_API_KEY}
      MATTSTASH_ALLOW_INSECURE_HTTP: "1"   # plain http on a private network; silences the CLI warning
    networks:
      - backend
    depends_on:
      mattstash-api:
        condition: service_healthy

  # MattStash API (read-only)
  mattstash-api:
    image: ghcr.io/cornyhorse/mattstash:v0.2.0   # pin a released tag or digest, never :latest
    user: "1000:1000"
    volumes:
      - ./mattstash-data:/data:ro
      - ./mattstash-secrets:/secrets:ro          # holds kdbx_password.txt and api_keys.txt
    environment:
      MATTSTASH_DB_PATH: /data/mattstash.kdbx
      KDBX_PASSWORD_FILE: /secrets/kdbx_password.txt
      MATTSTASH_API_KEYS_FILE: /secrets/api_keys.txt
      MATTSTASH_ALLOW_WRITES: "false"
    networks:
      - backend

networks:
  backend:
    driver: bridge
```

## Troubleshooting

### Can't connect to server
```bash
# Check if running (and whether it reports healthy)
docker compose ps

# Check logs
docker compose logs mattstash-api

# Liveness and readiness
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/ready
```

`/health` fine but `/ready` returns 503: the database could not be opened (wrong master password, missing file,
unreadable password file). The logs say which.

### Container exits or restarts
- An API key shorter than 32 characters, no API key, or no master password makes the server refuse to start.
- Files in `data/` and `secrets/` must be readable by the container user (`MATTSTASH_UID`/`MATTSTASH_GID`).

### Authentication errors
```bash
# Verify the key you are sending is the one in the file
head -n1 secrets/api_keys.txt

# Test with it
curl -H "X-API-Key: $(head -n1 secrets/api_keys.txt)" \
  http://127.0.0.1:8000/api/v1/credentials
```
Repeated failures from one address are throttled.

### 405 on POST/DELETE
The server is read-only (the default). Use the write-mode override above if you really need writes.

### Credential not found
```bash
# List all available credentials
curl -H "X-API-Key: $API_KEY" \
  http://127.0.0.1:8000/api/v1/credentials | jq '.credentials[].name'
```

## API Documentation

Unless disabled with `MATTSTASH_DISABLE_DOCS` (the production file does):
- Swagger UI: http://localhost:8000/api/v1/docs
- ReDoc: http://localhost:8000/api/v1/redoc

Full configuration reference: [docs/configuration.md](docs/configuration.md). Kubernetes: [k8s/README.md](k8s/README.md).

## Security Notes

**Production checklist**:
- [ ] Keys of at least 32 characters (`openssl rand -base64 32`), one per client
- [ ] Master password and API keys in files (Compose `secrets:` / Kubernetes Secrets), outside the data volume
- [ ] Read-only mode unless you truly need writes; one instance only when you do
- [ ] TLS for anything that crosses hosts (reverse proxy / ingress, or `MATTSTASH_TLS_CERT_FILE`/`_KEY_FILE`);
      set `MATTSTASH_TRUSTED_PROXY_HOPS` when behind a proxy
- [ ] Restrict network access (internal Docker network, Kubernetes NetworkPolicy), not the public internet
- [ ] Rotate API keys regularly; monitor access logs
- [ ] Pin the image to a released tag or digest and keep it updated

**Never**:
- Expose on the public internet without TLS
- Commit secrets, databases or `.mattstash.txt` files to git
- Use the same API key everywhere
- Log credential values
