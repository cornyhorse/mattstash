# MattStash API Server

A FastAPI-based HTTP service that exposes MattStash credentials to other services in a Docker Compose stack or a
Kubernetes cluster, so they can fetch secrets without having direct access to the KeePass file.

## Overview

The server wraps a KeePass database (`.kdbx`) in a small REST API. It is designed for private networks: other
containers or pods query it for credentials, authenticating with an API key.

**Key features**

- **Read-only by default.** The database is mounted read-only and writes are off; `POST`/`DELETE` answer `405`.
  Writing is an explicit opt-in (`MATTSTASH_ALLOW_WRITES=true`) with its own deployment files.
- **API-key authentication** on every credential endpoint. Keys must be at least 32 characters. Per-key scopes are
  available (see [docs/configuration.md](docs/configuration.md)).
- **Optional in-app TLS**, and TLS-terminating proxy/ingress examples. Plain HTTP is the default listener; see
  [TLS](#tls).
- **Container-native**: Docker Compose and Kubernetes examples, liveness and readiness endpoints, non-root user,
  read-only root filesystem.
- **Built from source, pinned dependencies**: the image installs the mattstash library from the same commit and the
  server's dependencies from a hash-pinned lockfile.
- **Request logging** (client address, method, path, status; never secrets). It is operational logging, not a
  tamper-evident audit trail: ship the logs somewhere durable if you need one.
- **Complete separation**: the server code is not part of the `pip install mattstash` package.

### Read-only and writable mode

| | Read-only (default) | Writable (opt-in) |
|---|---|---|
| `MATTSTASH_ALLOW_WRITES` | unset / `false` | `true` |
| `POST` / `DELETE` credentials | `405` with a clear message | enabled |
| Database mount | read-only (compose `:ro`, k8s Secret) | read-write directory (compose bind/volume, k8s PVC) |
| Instances | any number | **exactly one** (compose: single container; k8s: `replicas: 1`, `strategy: Recreate`) |
| Compose | `docker-compose.yml`, `docker-compose.prod.yml` | add `docker-compose.writable.yml` |
| Kubernetes | `k8s/deployment.yaml` | `k8s/writable/` |

Never run more than one instance against a writable database file: concurrent writers lose updates and the lock
file (`<db>.lock`) cannot protect you across hosts or most network filesystems. In write mode the data
**directory** must be writable by the container user, not just the `.kdbx`, because every write creates the lock
file and a temporary file next to the database.

## Quick Start (Docker Compose, read-only)

### Prerequisites

- Docker with the Compose plugin (`docker compose`, v2)
- The `mattstash` CLI to create the database (`pip install mattstash`)

### 1. Create the secrets and the database

```bash
cd server
mkdir -p data secrets

# API key: at least 32 characters (the server refuses to start with weaker ones)
(umask 077; openssl rand -base64 32 > secrets/api_keys.txt)

# KeePass master password, kept in a file OUTSIDE the data directory
(umask 077; openssl rand -base64 32 > secrets/kdbx_password.txt)

# Create the database. Only `mattstash setup` creates one; the server never does.
mattstash --db data/mattstash.kdbx setup --password-file secrets/kdbx_password.txt

# ... or copy an existing database instead of running setup:
#   cp /path/to/your/database.kdbx data/mattstash.kdbx   (and put its password in secrets/kdbx_password.txt)
```

Add credentials with the CLI (`mattstash --db data/mattstash.kdbx put ...`) before starting the read-only server.
`./start.sh` automates the secrets and startup steps (it generates a strong API key if there is none).

### 2. Start

```bash
# Read-only (default)
docker compose up -d --build

# Production-oriented file (secrets: mounts, internal network, no published port; see below)
docker compose -f docker-compose.prod.yml up -d --build

# Opt in to writes (single instance only)
docker compose -f docker-compose.yml -f docker-compose.writable.yml up -d --build
```

The files in `data/` and `secrets/` must be readable by the container user, which runs as
`${MATTSTASH_UID:-1000}:${MATTSTASH_GID:-1000}`. Set those variables (for example in `.env`, see `.env.example`) to
the owner of your files; `./start.sh` uses your own uid/gid.

### 3. Test

```bash
# Liveness: 200 whenever the process runs (never touches the database)
curl http://127.0.0.1:8000/health

# Readiness: 200 only once the database has been opened, otherwise 503
curl http://127.0.0.1:8000/ready

# Get a credential (requires an API key)
curl -H "X-API-Key: $(head -n1 secrets/api_keys.txt)" \
  http://127.0.0.1:8000/api/v1/credentials/my-secret
```

## API Documentation

Unless disabled with `MATTSTASH_DISABLE_DOCS` (the production examples disable it), visit:

- **Swagger UI**: http://localhost:8000/api/v1/docs
- **ReDoc**: http://localhost:8000/api/v1/redoc

### Endpoints

#### Health and readiness

```
GET /health        GET /api/health
GET /ready         GET /api/ready
```

No authentication. `/health` is **liveness**: it answers `200` as long as the process runs and never touches the
database. `/ready` is **readiness**: `200` only if the database was opened successfully, `503` otherwise. Use
`/health` for Docker/Compose health checks and Kubernetes liveness, `/ready` for Kubernetes readiness. Both paths of
each pair behave identically (`/api/...` exists so a single ingress prefix can expose it).

#### Get Credential
```
GET /api/v1/credentials/{name}?show_password=false&version=1
Headers: X-API-Key: <your-key>
```

**Query Parameters:**
- `show_password` (bool): Show actual password instead of `*****` (default: false)
- `version` (int): Specific version to retrieve (optional)

**Response:**
```json
{
  "name": "db-prod",
  "username": "admin",
  "password": "*****",
  "url": "postgres.example.com:5432",
  "notes": "Production database",
  "version": "0000000001"
}
```

#### List Credentials
```
GET /api/v1/credentials?prefix=db-&show_password=false
Headers: X-API-Key: <your-key>
```

**Query Parameters:**
- `prefix` (string): Filter by name prefix (optional)
- `show_password` (bool): Show actual passwords (default: false)

**Response:**
```json
{
  "credentials": [
    {
      "name": "db-prod",
      "username": "admin",
      "password": "*****",
      "url": "postgres.example.com:5432",
      "notes": null,
      "version": "0000000001"
    }
  ],
  "count": 1
}
```

#### List Versions
```
GET /api/v1/credentials/{name}/versions
Headers: X-API-Key: <your-key>
```

**Response:**
```json
{
  "name": "db-prod",
  "versions": ["0000000001", "0000000002", "0000000003"],
  "latest": "0000000003"
}
```

#### Get Database URL
```
GET /api/v1/db-url/{name}?driver=psycopg&database=mydb&mask_password=true
Headers: X-API-Key: <your-key>
```

**Query Parameters:**
- `driver` (string): Database driver (default: psycopg)
- `database` (string): Database name to append (optional)
- `mask_password` (bool): Mask password in URL (default: true)

**Response:**
```json
{
  "url": "postgresql+psycopg://user:*****@host:5432/mydb"
}
```

#### Create / Update and Delete (write mode only)

```
POST   /api/v1/credentials/{name}      body: {"value": "..."}  or  {"username": "...", "password": "...", "url": "...", "notes": "...", "tags": [...]}
DELETE /api/v1/credentials/{name}
Headers: X-API-Key: <your-key>
```

These endpoints exist but are **disabled unless `MATTSTASH_ALLOW_WRITES=true`**; otherwise they return `405`. See
[Read-only and writable mode](#read-only-and-writable-mode) for the deployment rules that go with enabling them.

## Configuration

The full reference (API key policy file format, rate limiting, read-only mode details) is in
[docs/configuration.md](docs/configuration.md). The common settings:

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MATTSTASH_DB_PATH` | Path to the KeePass database (must already exist) | `/data/mattstash.kdbx` | Yes |
| `KDBX_PASSWORD_FILE` | Path to a file containing the master password (preferred) | - | Yes* |
| `KDBX_PASSWORD` | Master password (discouraged: visible in `docker inspect`) | - | Yes* |
| `MATTSTASH_API_KEYS_FILE` | File with API keys: a plain list, or a JSON policy file | - | Yes** |
| `MATTSTASH_API_KEY` | A single API key | - | Yes** |
| `MATTSTASH_ALLOW_WRITES` | `true` enables POST/DELETE; anything else keeps the server read-only | `false` | No |
| `MATTSTASH_HOST` | Server bind address | `0.0.0.0` | No |
| `MATTSTASH_PORT` | Server port | `8000` | No |
| `MATTSTASH_LOG_LEVEL` | Log level (debug/info/warning/error) | `info` | No |
| `MATTSTASH_TLS_CERT_FILE` / `MATTSTASH_TLS_KEY_FILE` | Serve HTTPS from this certificate and key (set both) | unset (plain HTTP) | No |
| `MATTSTASH_TRUSTED_PROXY_HOPS` | Number of trusted reverse-proxy hops in front of the server, used to find the real client IP | `0` | No |
| `MATTSTASH_RATE_LIMIT` | Rate limit (e.g., "100/minute") | `100/minute` | No |
| `MATTSTASH_DB_POLL_INTERVAL` | Seconds between checks for an externally changed database file (`0` disables) | `5` | No |
| `MATTSTASH_MAX_REQUEST_BODY_BYTES` | Maximum request body size | `1048576` | No |
| `MATTSTASH_DISABLE_DOCS` | Do not serve the Swagger/ReDoc/OpenAPI pages | off | No |

\* Either `KDBX_PASSWORD_FILE` or `KDBX_PASSWORD` is required.  
\** Either `MATTSTASH_API_KEYS_FILE` or `MATTSTASH_API_KEY` is required.

The server **never creates a database**: if `MATTSTASH_DB_PATH` does not exist it reports an error. Create it with
`mattstash setup`.

### API keys

Every API key must be **at least 32 characters** and the server refuses to start with a weaker one. Generate keys
with:

```bash
openssl rand -base64 32
```

Never use sample keys, never reuse a key across environments, and issue one key per client so a single client can be
revoked. In its simplest form the keys file has one key per line (lines starting with `#` are ignored):

```
# One key per client; generated with: openssl rand -base64 32
kC1m...43 characters of base64...
q8Zt...43 characters of base64...
```

A JSON policy file can scope each key to operations and name prefixes instead; the format is described in
[docs/configuration.md](docs/configuration.md). Plain-text key lines keep full access.

### Master password

Give the server the master password as a **file in a mount that is separate from the data volume**
(`KDBX_PASSWORD_FILE`, e.g. `/secrets/kdbx_password.txt` or a Docker/Kubernetes secret). Do not store it next to the
database: `mattstash setup --sidecar` writes a `.mattstash.txt` beside the `.kdbx`, which protects only against
someone obtaining the `.kdbx` file alone and not against anyone who can read the directory. It is fine on a
personal workstation and the wrong choice for a service. (The library still honours an existing sidecar as a last
resort, after `KDBX_PASSWORD` and `KDBX_PASSWORD_FILE`.)

### TLS

The server listens on plain HTTP by default. Choose one of:

1. **Terminate TLS in front of it (recommended):** a reverse proxy in Compose (see the commented `proxy` service in
   `docker-compose.prod.yml`) or the Kubernetes Ingress (`k8s/ingress.yaml`). The hop between proxy and server then
   stays on a private network. Set `MATTSTASH_TRUSTED_PROXY_HOPS` to the number of proxies you control (usually `1`)
   so that rate limiting and logs see the real client address instead of the proxy.
2. **In-app TLS:** set `MATTSTASH_TLS_CERT_FILE` and `MATTSTASH_TLS_KEY_FILE` (PEM files, mounted as secrets) and the
   server serves HTTPS itself. Switch health checks to `https` (the image's built-in check does this automatically;
   edit the Compose `healthcheck`, and add `scheme: HTTPS` to the Kubernetes probes).

Clients: the `mattstash` CLI in server mode warns when `MATTSTASH_SERVER_URL` is a plain `http://` URL to a
non-loopback host. It does not refuse, because plain HTTP on a private Compose network is the documented pattern;
set `MATTSTASH_ALLOW_INSECURE_HTTP=1` to silence the warning once you have decided that is acceptable. Use `https://`
whenever traffic crosses hosts.

## Security Best Practices

### Network security

**Do:**
- Keep the server on a private network that only its clients join (a dedicated Docker network, a NetworkPolicy in
  Kubernetes).
- Publish a port only on loopback (`127.0.0.1:8000:8000`) or through a TLS proxy.
- Terminate TLS in a proxy/ingress and put rate limits there too.

**Don't:**
- Expose the server on `0.0.0.0` / the internet without TLS.
- Share one API key between all clients.
- Put API keys in `docker-compose.yml` or in version control.

### Secrets management

**Do:**
- Keep the master password and API keys in files with restricted permissions (`0400`/`0600`), outside the repository
  and outside the data volume. Use Compose `secrets:` (see `docker-compose.prod.yml`) or Kubernetes Secrets.
- Get Kubernetes secrets into the cluster without committing them: `kubectl create secret ... --from-file`, Sealed
  Secrets, SOPS, or External Secrets Operator / Secrets Store CSI (see `k8s/secret.example.yaml`).
- Rotate API keys regularly; mount the data directory read-only unless you run write mode.

**Don't:**
- Commit secrets, databases, `.mattstash.txt` sidecars, `*.kdbx.lock` or `*.bak-*` files (they are git-ignored).
- Log passwords or API keys.
- Share API keys across environments.

### Supply chain

- The image is built from this repository (`docker build -f server/Dockerfile .` from the repository root), so it
  always contains the library code of its own commit.
- Third-party dependencies come from `requirements.lock`, installed with `pip install --require-hashes`.
- Released images carry SLSA build provenance and an SBOM
  (`docker buildx imagetools inspect ghcr.io/cornyhorse/mattstash:vX.Y.Z --format '{{ json .Provenance }}'`).
- Deploy a **pinned version tag or digest**, never `:latest`. The base image (`python:3.14-slim`) can be pinned by
  digest in the Dockerfiles (see the comment there); Dependabot proposes updates for the tag, the digest, the GitHub
  Actions and the Python dependencies.

## Deployment

### Docker Compose

| File | Purpose |
|---|---|
| `docker-compose.yml` | Development / single host. Read-only, publishes `127.0.0.1:8000`. |
| `docker-compose.prod.yml` | Production-oriented: Compose `secrets:`, resource limits, read-only root filesystem, **no published port**. |
| `docker-compose.writable.yml` | Override that turns on write mode (single instance, writable data directory). |

`docker-compose.prod.yml` keeps the API on an `internal: true` network (`backend`): clients attach to that network,
and nothing can reach it from outside. Docker does not publish ports for containers that are attached only to
internal networks, so the file deliberately publishes none; an optional TLS proxy (commented in the file) attaches to
`backend` and a normal `frontend` network and is the only thing that publishes a port.

Build context for all of them is the repository root, so the image contains this checkout's library:

```bash
docker build -f server/Dockerfile -t mattstash-api:local .
docker build -f server/Dockerfile.multistage -t mattstash-api:local .   # same app, slimmer image
```

### Kubernetes

Manifests are in [`k8s/`](k8s/) with a full guide in [k8s/README.md](k8s/README.md): a read-only multi-replica
Deployment (database in a Secret, PodDisruptionBudget) and a separate single-replica writable variant (PVC, setup Job),
both with seccomp, dropped capabilities, read-only root filesystem, no ServiceAccount token, and a NetworkPolicy.
Probes: liveness `/health`, readiness `/ready`.

## Development

### Local development (without Docker)

```bash
# From the repository root: the library from this checkout, then the server's dependencies
pip install -e ".[all,dev]"
pip install -r server/requirements.txt -r server/requirements-dev.txt

# Point the server at an existing database (create one with `mattstash setup`)
export MATTSTASH_DB_PATH=/path/to/database.kdbx
export KDBX_PASSWORD_FILE=/path/to/password.txt
export MATTSTASH_API_KEY="$(openssl rand -base64 32)"

cd server
python -m app          # honours MATTSTASH_HOST / MATTSTASH_PORT / MATTSTASH_LOG_LEVEL / TLS settings
```

### Dependency lockfile

`requirements.in` lists the server's direct dependencies as ranges; `requirements.lock` is the hash-pinned result
that the images and CI install. After editing `requirements.in` or the root `pyproject.toml` dependencies,
regenerate it from the repository root with Python 3.14 (the version the image uses):

```bash
pip install pip-tools
pip-compile --generate-hashes --strip-extras --output-file=server/requirements.lock \
  pyproject.toml server/requirements.in
```

The CI `audit` job runs `pip-audit` against the lockfile on every run.

### Project structure

```
server/
├── Dockerfile                    # Single-stage image (build context: repository root)
├── Dockerfile.multistage         # Multi-stage image (same app, build leftovers stay behind)
├── Dockerfile*.dockerignore      # Keeps secrets and junk out of the build context
├── docker-compose.yml            # Default: read-only, development
├── docker-compose.prod.yml       # Production-oriented (secrets:, internal network, no published port)
├── docker-compose.writable.yml   # Opt-in write mode (override file)
├── requirements.in               # Direct dependencies (ranges)
├── requirements.lock             # Hash-pinned dependency lock used by the images and CI
├── requirements.txt              # Loose ranges for local development
├── requirements-dev.txt          # Test dependencies
├── .env.example                  # Compose interpolation variables + settings reference
├── start.sh                      # Quick start helper (docker compose)
├── app/                          # FastAPI application (start with `python -m app`)
├── tests/                        # Server test suite
├── docs/configuration.md         # Configuration reference (API key policy, rate limiting, read-only mode)
├── k8s/                          # Kubernetes manifests and guide
│   ├── README.md
│   ├── namespace.yaml  serviceaccount.yaml  configmap.yaml  secret.example.yaml
│   ├── deployment.yaml  service.yaml  pdb.yaml  networkpolicy.yaml  ingress.yaml
│   └── writable/                 # pvc.yaml, setup-job.yaml, deployment.yaml
├── data/                         # KeePass database location (git-ignored)
└── secrets/                      # Master password and API keys (git-ignored)
```

## Client Examples

Keep the API key in an environment variable or a secret, never in the source.

### Python

```python
import os

import requests

API_URL = os.environ.get("MATTSTASH_API_URL", "http://mattstash-api:8000/api/v1")
headers = {"X-API-Key": os.environ["MATTSTASH_API_KEY"]}

# Get credential
response = requests.get(
    f"{API_URL}/credentials/db-prod",
    headers=headers,
    params={"show_password": True},
    timeout=10,
)
response.raise_for_status()
cred = response.json()
print(f"Username: {cred['username']}")

# Get database URL
response = requests.get(
    f"{API_URL}/db-url/db-prod",
    headers=headers,
    params={"driver": "psycopg", "database": "mydb", "mask_password": False},
    timeout=10,
)
response.raise_for_status()
db_url = response.json()["url"]
```

### curl

```bash
API_URL="http://mattstash-api:8000/api/v1"
# MATTSTASH_API_KEY comes from your environment / secret store

# List all credentials
curl -H "X-API-Key: $MATTSTASH_API_KEY" "$API_URL/credentials"

# Get specific credential with password
curl -H "X-API-Key: $MATTSTASH_API_KEY" "$API_URL/credentials/db-prod?show_password=true"

# Get database URL
curl -H "X-API-Key: $MATTSTASH_API_KEY" "$API_URL/db-url/db-prod?driver=psycopg&database=mydb"
```

### The `mattstash` CLI in server mode

```bash
export MATTSTASH_SERVER_URL=http://mattstash-api:8000
export MATTSTASH_API_KEY=...            # a key of at least 32 characters
export MATTSTASH_ALLOW_INSECURE_HTTP=1  # plain http on a private network; silences the CLI's warning
mattstash get db-prod
```

### Docker Compose integration

```yaml
services:
  my-app:
    image: myapp:latest
    environment:
      MATTSTASH_SERVER_URL: http://mattstash-api:8000
      MATTSTASH_API_KEY: ${MY_APP_API_KEY:?set MY_APP_API_KEY}
      MATTSTASH_ALLOW_INSECURE_HTTP: "1"
    networks:
      - backend
    depends_on:
      mattstash-api:
        condition: service_healthy

  mattstash-api:
    image: ghcr.io/cornyhorse/mattstash:v0.2.0   # pin a released tag or digest, never :latest
    user: "1000:1000"
    environment:
      MATTSTASH_DB_PATH: /data/mattstash.kdbx
      KDBX_PASSWORD_FILE: /run/secrets/kdbx_password
      MATTSTASH_API_KEYS_FILE: /run/secrets/mattstash_api_keys
      MATTSTASH_ALLOW_WRITES: "false"
    volumes:
      - ./data:/data:ro
    secrets:
      - kdbx_password
      - mattstash_api_keys
    networks:
      - backend

networks:
  backend:
    internal: true   # no outside connectivity; clients join this network

secrets:
  kdbx_password:
    file: ./secrets/kdbx_password.txt
  mattstash_api_keys:
    file: ./secrets/api_keys.txt
```

## Troubleshooting

### Common Issues

**Service won't start:**
- `KDBX_PASSWORD_FILE` / `KDBX_PASSWORD` must be set and correct, and the database must exist at
  `MATTSTASH_DB_PATH` (the server never creates one; run `mattstash setup`).
- At least one API key must be configured, and every key must be at least 32 characters.
- Check file permissions on the mounted data and secrets: the container user (uid/gid `1000` by default) must be able
  to read them. In write mode it must be able to write the data **directory**.

**`/ready` returns 503:** the database could not be opened: wrong master password, missing or corrupt file, or an
unreadable password file. The logs say which; they never contain the password.

**`405` on POST/DELETE:** the server is in read-only mode (the default). See
[Read-only and writable mode](#read-only-and-writable-mode).

**Authentication errors:**
- Verify the API key and that the `X-API-Key` header is sent.
- Make sure the key has no trailing whitespace. Repeated failures from one address are throttled.

**Credential not found:**
- Verify the credential exists in the KeePass database and check the spelling (names are case-sensitive).

**Writes fail with a lock-file or permission error (write mode):** the data directory is not writable by the
container user. Fix ownership or set `MATTSTASH_UID`/`MATTSTASH_GID`.

### Logs

```bash
# Docker Compose
docker compose logs -f mattstash-api

# Docker
docker logs -f mattstash-api

# Kubernetes
kubectl logs -f deployment/mattstash-api -n mattstash
```

## Testing

The server has its own test suite in `tests/` with a coverage gate (`pytest.ini`, currently 90%):

```bash
# From the repository root: library + test tooling + server dependencies
pip install -e ".[all,dev]" -r server/requirements.txt -r server/requirements-dev.txt

cd server
python -m pytest                 # includes the coverage gate
python -m pytest --no-cov -q     # faster, no coverage
```

CI (`.github/workflows/ci.yml`) runs the library tests across the supported Python versions, the server tests, the
integration tests (which skip themselves without Docker), `ruff check` and `ruff format --check` for `server/app` and
`server/tests`, and `pip-audit` against the server lockfile and the library dependencies.

## License

This server application uses the MattStash library, which is licensed under the MIT License.

## Support

For issues and questions:
- GitHub Issues: https://github.com/cornyhorse/mattstash/issues
- Documentation: See the main project README and [docs/configuration.md](docs/configuration.md)
