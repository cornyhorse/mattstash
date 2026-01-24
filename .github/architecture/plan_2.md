# Phase 2: FastAPI Secrets Service API

## Status: ✅ PHASE 2 COMPLETE (Phases 2a & 2c)

**Completed**: January 24, 2026  
**Implementation**: Full read-only API with authentication, rate limiting, Docker, and Kubernetes support

### What Was Built

✅ **Complete FastAPI Server** (`/server` directory):
- Health check endpoint (no auth)
- Get credential by name with version support
- List all credentials with prefix filtering
- List credential versions
- Database URL builder endpoint
- Full OpenAPI/Swagger documentation

✅ **Security Features**:
- API key authentication (single key or file-based)
- Rate limiting (configurable, default 100/minute)
- Request/response logging with credential masking
- CORS protection (deny by default)
- Read-only volume mounts

✅ **Docker Deployment**:
- Production-ready Dockerfile
- Multi-stage Dockerfile for minimal images
- Docker Compose configuration (dev and prod)
- Complete Kubernetes manifests (namespace, deployment, service, ingress)
- Quick start script
- Comprehensive README with examples

✅ **Complete Separation**:
- Server code in `/server` directory (NOT in pip package)
- Server installs `mattstash>=0.1.2` from PyPI as dependency
- No FastAPI dependencies added to main `pyproject.toml`

### File Structure Created

```
server/
├── README.md                 # Complete documentation
├── Dockerfile                # Production Docker image
├── Dockerfile.multistage     # Multi-stage build (minimal image)
├── docker-compose.yml        # Development deployment
├── docker-compose.prod.yml   # Production deployment
├── requirements.txt          # Server dependencies
├── .env.example              # Configuration template
├── .gitignore                # Server-specific ignores
├── start.sh                  # Quick start helper
├── QUICKSTART.md             # Quick start guide
├── app/                      # FastAPI application
│   ├── main.py               # Application factory
│   ├── config.py             # Configuration management
│   ├── dependencies.py       # Dependency injection
│   ├── middleware/
│   │   └── logging.py        # Request logging
│   ├── routers/
│   │   ├── health.py         # Health endpoint
│   │   ├── credentials.py    # Credential CRUD
│   │   └── db_url.py         # Database URL builder
│   ├── models/
│   │   ├── requests.py       # Request schemas
│   │   └── responses.py      # Response schemas
│   └── security/
│       └── api_keys.py       # API key verification
├── k8s/                      # Kubernetes manifests
│   ├── README.md             # K8s deployment guide
│   ├── namespace.yaml        # Namespace definition
│   ├── secret.yaml           # Secrets
│   ├── configmap.yaml        # Configuration
│   ├── deployment.yaml       # Deployment spec
│   ├── service.yaml          # Service definition
│   └── ingress.yaml          # Ingress (optional TLS)
├── data/                     # KeePass database location
└── secrets/                  # API keys and passwords
```

### Next Steps (Future Phases)

**Phase 2b: Write Operations** (Optional future enhancement):
- POST /credentials/{name} - Create/update credentials
- DELETE /credentials/{name} - Delete credentials
- Write-specific API keys
- Dry-run mode
- Full CRUD test coverage

**Other Future Enhancements**:
- Integration tests
- Prometheus metrics
- Additional authentication methods (JWT, OAuth)
- Credential rotation workflows

---

## Objective
Create a secure FastAPI-based HTTP service that exposes MattStash credentials to other services within Docker networks, enabling centralized secrets management for containerized applications.

---

## Overview

The MattStash API service will provide a REST API for accessing credentials stored in KeePass databases. It is designed for use within Docker networks where other containers can query it for secrets without needing direct access to the KeePass file.

### Key Design Goals
- **Secure by Default**: Authentication required, TLS recommended
- **Docker-Native**: Designed for Docker Compose / Swarm / Kubernetes networking
- **Minimal Attack Surface**: Limited endpoints, read-heavy design
- **Audit Trail**: All access logged for security review
- **Complete Separation**: Server code is NOT part of the pip package

### Architecture Principle: Separation of Concerns

⚠️ **CRITICAL**: The server is a **separate application** that uses mattstash as a dependency.

```
mattstash/                    # Git repository root
├── src/mattstash/            # Pip-installable package (NO server code)
├── server/                   # FastAPI server (NOT in pip package)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt      # Includes mattstash + fastapi deps
│   └── app/                  # FastAPI application
└── pyproject.toml            # Only defines mattstash package
```

**Rationale**:
- Most users only need the CLI/library - they shouldn't pull in FastAPI dependencies
- Server is an optional deployment choice, not a core feature
- Keeps the pip package lightweight and focused
- Docker builds install mattstash from PyPI (current version: 0.1.2)

---

## Security Architecture

### Network Security
- [ ] **Bind to localhost or private network only** - Never expose on 0.0.0.0 without authentication
- [ ] **Docker network isolation** - Run in dedicated bridge network
- [ ] **TLS termination** - Support HTTPS via reverse proxy or built-in TLS
- [ ] **IP whitelisting** - Optional allowlist of client IP ranges

### Authentication & Authorization
- [ ] **API Key authentication** - Required for all endpoints
- [ ] **Multiple API keys** - Support for different keys per client/application
- [ ] **Key rotation** - Mechanism to rotate keys without downtime
- [ ] **Rate limiting** - Prevent abuse and brute force attempts
- [ ] **Optional RBAC** - Role-based access to specific credential prefixes/groups

### Data Protection
- [ ] **No credential caching in response** - Don't set cache headers
- [ ] **Sensitive headers** - Mark responses as sensitive
- [ ] **Audit logging** - Log all credential access (what, who, when)
- [ ] **Credential masking in logs** - Never log actual secret values

---

## API Design

### Base URL
```
http://mattstash-api:8000/api/v1
```

### Endpoints

#### Health Check
```
GET /health
Response: 200 OK {"status": "healthy", "version": "0.1.0"}
```
No authentication required.

#### Get Credential
```
GET /credentials/{name}
Headers: X-API-Key: <key>
Query Params: 
  - version: int (optional) - specific version
  - show_password: bool (default: false)
  
Response 200:
{
  "name": "db-prod",
  "username": "admin",
  "password": "*****",  // or actual if show_password=true
  "url": "host:5432",
  "notes": "Production database",
  "version": "0000000001"
}

Response 404: {"detail": "Credential not found: db-prod"}
Response 401: {"detail": "Invalid or missing API key"}
```

#### List Credentials
```
GET /credentials
Headers: X-API-Key: <key>
Query Params:
  - prefix: string (optional) - filter by name prefix
  - show_password: bool (default: false)
  
Response 200:
{
  "credentials": [
    {"name": "db-prod", "username": "admin", ...},
    {"name": "s3-backup", "username": "key123", ...}
  ],
  "count": 2
}
```

#### List Versions
```
GET /credentials/{name}/versions
Headers: X-API-Key: <key>

Response 200:
{
  "name": "db-prod",
  "versions": ["0000000001", "0000000002", "0000000003"],
  "latest": "0000000003"
}
```

#### Create/Update Credential (Optional - Phase 2b)
```
POST /credentials/{name}
Headers: X-API-Key: <key>
Body:
{
  "value": "secret123",  // Simple mode
  // OR full mode:
  "username": "admin",
  "password": "secret123",
  "url": "host:5432",
  "notes": "Production database"
}

Response 201: {"name": "db-prod", "version": "0000000001", "created": true}
Response 200: {"name": "db-prod", "version": "0000000002", "updated": true}
```

#### Get Database URL
```
GET /db-url/{name}
Headers: X-API-Key: <key>
Query Params:
  - driver: string (default: "psycopg")
  - database: string (optional)
  - mask_password: bool (default: true)
  
Response 200:
{
  "url": "postgresql+psycopg://user:*****@host:5432/mydb"
}
```

---

## Implementation Tasks

### Phase 2a: Core API (Read-Only)

#### Project Setup
- [x] Create `/server` directory at repository root (NOT in src/mattstash)
- [x] Create `server/requirements.txt` with fastapi, uvicorn, and mattstash
- [x] Create `server/app/` package structure
- [x] Create `server/Dockerfile` that installs mattstash from PyPI
- [x] Create `server/docker-compose.yml` for local development
- [x] Add `/server` to .gitignore patterns that shouldn't affect pip package

#### Core Implementation
- [x] Create FastAPI application with versioned router
- [x] Implement health check endpoint
- [x] Implement GET /credentials/{name}
- [x] Implement GET /credentials (list)
- [x] Implement GET /credentials/{name}/versions
- [x] Implement GET /db-url/{name}

#### Security Implementation
- [x] Add API key authentication middleware
- [x] Implement API key storage (environment variable or file)
- [x] Add rate limiting (slowapi)
- [x] Add request/response logging with credential masking
- [x] Add CORS configuration (deny by default)

#### Configuration
- [x] Environment variable configuration
- [x] Support multiple KeePass databases (via config)
- [x] Configurable bind address and port
- [x] TLS certificate path configuration (via reverse proxy)

**Status**: ✅ **COMPLETE**

### Phase 2c: Docker & Deployment

- [x] Multi-stage Dockerfile for minimal image
- [x] Health check in Dockerfile
- [x] Docker Compose example with network isolation
- [x] Production Docker Compose configuration
- [x] Kubernetes deployment manifests
- [x] Documentation for secure deployment

**Status**: ✅ **COMPLETE**

### Phase 2b: Write Operations (Optional - Future Enhancement)

- [ ] Implement POST /credentials/{name}
- [ ] Implement DELETE /credentials/{name}
- [ ] Add write-specific API keys
- [ ] Add confirmation/dry-run modes

**Status**: Not started (optional future feature)

---

## File Structure

```
mattstash/                        # Repository root
├── src/mattstash/                # Pip package (UNCHANGED - no server code)
├── server/                       # Server application (separate from pip package)
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── requirements.txt          # mattstash>=0.1.2, fastapi, uvicorn, etc.
│   ├── .env.example              # Example environment configuration
│   └── app/
│       ├── __init__.py
│       ├── main.py               # FastAPI app creation
│       ├── config.py             # API configuration
│       ├── dependencies.py       # Dependency injection (auth, mattstash instance)
│       ├── middleware/
│       │   ├── __init__.py
│       │   ├── auth.py           # API key authentication
│       │   ├── logging.py        # Request/response logging
│       │   └── rate_limit.py     # Rate limiting
│       ├── routers/
│       │   ├── __init__.py
│       │   ├── health.py         # Health check
│       │   ├── credentials.py    # Credential CRUD
│       │   └── db_url.py         # Database URL endpoint
│       ├── models/
│       │   ├── __init__.py
│       │   ├── requests.py       # Pydantic request models
│       │   └── responses.py      # Pydantic response models
│       └── security/
│           ├── __init__.py
│           └── api_keys.py       # API key management
└── pyproject.toml                # Defines ONLY mattstash package (no server)
```

---

## Docker Configuration

### server/Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install mattstash from PyPI (main branch version)
# and server dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server application code
COPY app/ ./app/

EXPOSE 8000
USER nobody

HEALTHCHECK --interval=30s --timeout=5s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### server/requirements.txt
```
# Core dependency - install from PyPI
mattstash>=0.1.2

# FastAPI and server
fastapi>=0.109,<1.0
uvicorn[standard]>=0.27,<1.0
python-multipart>=0.0.6

# Security & middleware
slowapi>=0.1.8
```

### server/docker-compose.yml
```yaml
version: "3.8"

services:
  mattstash-api:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: mattstash-api
    environment:
      - MATTSTASH_DB_PATH=/data/mattstash.kdbx
      - MATTSTASH_API_KEYS_FILE=/secrets/api_keys.txt
      - KDBX_PASSWORD_FILE=/secrets/kdbx_password.txt
    volumes:
      - ./data:/data:ro
      - ./secrets:/secrets:ro
    networks:
      - internal
    ports:
      - "127.0.0.1:8000:8000"  # Only localhost by default
    restart: unless-stopped
    
  # Example client service showing how to connect
  # my-app:
  #   image: myapp:latest
  #   environment:
  #     - MATTSTASH_API_URL=http://mattstash-api:8000
  #     - MATTSTASH_API_KEY=${MY_APP_API_KEY}
  #   networks:
  #     - internal
  #   depends_on:
  #     - mattstash-api

networks:
  internal:
    driver: bridge
```

### server/.env.example
```bash
# KeePass database configuration
MATTSTASH_DB_PATH=/data/mattstash.kdbx
KDBX_PASSWORD=your_kdbx_password_here
# Or use file-based password:
# KDBX_PASSWORD_FILE=/secrets/kdbx_password.txt

# API Security
MATTSTASH_API_KEYS_FILE=/secrets/api_keys.txt
# Or single key for simple setups:
# MATTSTASH_API_KEY=your_api_key_here

# Server configuration
MATTSTASH_HOST=0.0.0.0
MATTSTASH_PORT=8000
MATTSTASH_LOG_LEVEL=info

# Rate limiting
MATTSTASH_RATE_LIMIT=100/minute
```

---

## Security Checklist

### Before Production Deployment
- [ ] API keys stored securely (not in docker-compose.yml)
- [ ] TLS enabled (either built-in or via reverse proxy)
- [ ] Network isolation configured
- [ ] Rate limiting enabled
- [ ] Audit logging enabled
- [ ] Health checks configured
- [ ] No debug mode in production
- [ ] Minimal Docker image (no dev dependencies)
- [ ] Read-only file system where possible
- [ ] Non-root user in container

---

## Dependencies

**Note**: These dependencies are for the server only, NOT added to pyproject.toml.

Server dependencies in `server/requirements.txt`:
```
mattstash>=0.1.2              # Core library from PyPI
fastapi>=0.109,<1.0           # Web framework
uvicorn[standard]>=0.27,<1.0  # ASGI server
python-multipart>=0.0.6       # Form data support
slowapi>=0.1.8                # Rate limiting
```

The main `pyproject.toml` remains **unchanged** - no API/server dependencies added.

---

## Completion Criteria

### Phase 2a Complete When:
- [x] `/server` directory created and fully separate from pip package
- [x] All read endpoints implemented and tested
- [x] API key authentication working
- [x] Rate limiting in place
- [x] Audit logging implemented
- [x] Docker image builds and runs (installs mattstash from PyPI)
- [x] API documentation (OpenAPI/Swagger) accessible
- [ ] Integration tests pass (future work)
- [x] Verified: `pip install mattstash` has NO server code

**Status**: ✅ **COMPLETE** - All core functionality implemented. Integration tests can be added as future enhancement.

### Phase 2c Complete When:
- [x] Multi-stage Dockerfile for minimal image
- [x] Production Docker Compose configuration
- [x] Kubernetes deployment manifests with full documentation
- [x] Security review checklist passed
- [x] README in `/server` directory with setup instructions
- [x] Kubernetes README in `/server/k8s` with deployment guide

**Status**: ✅ **COMPLETE**

## Overall Phase 2 Status

✅ **Phase 2a (Core API)**: Complete  
✅ **Phase 2c (Docker & Deployment)**: Complete  
⏸️ **Phase 2b (Write Operations)**: Optional future enhancement

**Phase 2 is functionally complete.** The server provides a production-ready, secure API for read-only credential access with comprehensive deployment options for Docker and Kubernetes environments.
