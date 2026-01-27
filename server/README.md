# MattStash API Server

A secure FastAPI-based HTTP service that exposes MattStash credentials to other services within Docker networks, enabling centralized secrets management for containerized applications.

## Overview

The MattStash API service provides a REST API for accessing credentials stored in KeePass databases. It is designed for use within Docker networks where other containers can query it for secrets without needing direct access to the KeePass file.

**Key Features:**
- 🔒 **Secure by Default**: API key authentication required, TLS support
- 🐳 **Docker-Native**: Designed for Docker Compose / Swarm / Kubernetes
- 🎯 **Minimal Attack Surface**: Limited endpoints, read-heavy design
- 📝 **Audit Trail**: All access logged for security review
- 🔌 **Complete Separation**: Server code is NOT part of the pip package

## Quick Start

### Prerequisites

- Docker and Docker Compose
- A KeePass database (`.kdbx` file)
- API keys for authentication

### 1. Setup Configuration

```bash
# Copy example environment file
cp .env.example .env

# Edit .env with your configuration
vim .env
```

### 2. Prepare Secrets

```bash
# Create API keys file
echo "your-api-key-here" > secrets/api_keys.txt

# Create KeePass password file
echo "your-kdbx-password" > secrets/kdbx_password.txt

# Copy your KeePass database
cp /path/to/your/database.kdbx data/mattstash.kdbx
```

### 3. Start the Service

```bash
# Development (basic setup)
docker-compose up -d

# Production (enhanced security)
docker-compose -f docker-compose.prod.yml up -d
```

### 4. Test the Service

```bash
# Health check (no auth required)
curl http://localhost:8000/health

# Get a credential (requires API key)
curl -H "X-API-Key: your-api-key-here" \
  http://localhost:8000/api/v1/credentials/my-secret
```

## API Documentation

Once running, visit:
- **Swagger UI**: http://localhost:8000/api/v1/docs
- **ReDoc**: http://localhost:8000/api/v1/redoc

### Endpoints

#### Health Check
```
GET /health
```
No authentication required. Returns service status.

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

## Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `MATTSTASH_DB_PATH` | Path to KeePass database | `/data/mattstash.kdbx` | Yes |
| `KDBX_PASSWORD` | KeePass database password | - | Yes* |
| `KDBX_PASSWORD_FILE` | Path to file containing password | - | Yes* |
| `MATTSTASH_API_KEY` | Single API key | - | Yes* |
| `MATTSTASH_API_KEYS_FILE` | Path to file with multiple keys | `/secrets/api_keys.txt` | Yes* |
| `MATTSTASH_HOST` | Server bind address | `0.0.0.0` | No |
| `MATTSTASH_PORT` | Server port | `8000` | No |
| `MATTSTASH_LOG_LEVEL` | Log level (debug/info/warning/error) | `info` | No |
| `MATTSTASH_RATE_LIMIT` | Rate limit (e.g., "100/minute") | `100/minute` | No |

\* Either `KDBX_PASSWORD` or `KDBX_PASSWORD_FILE` is required  
\* Either `MATTSTASH_API_KEY` or `MATTSTASH_API_KEYS_FILE` is required

### API Keys File Format

Create a file with one API key per line. Lines starting with `#` are ignored.

```
# Production API keys
prod-api-key-abc123
backup-api-key-xyz789

# Development key
dev-api-key-test
```

## Security Best Practices

### Network Security

✅ **DO:**
- Run in a dedicated Docker network
- Use `127.0.0.1:8000:8000` for localhost-only access
- Deploy behind a reverse proxy with TLS
- Implement IP whitelisting in production

❌ **DON'T:**
- Expose on `0.0.0.0` without authentication
- Use the same API key for all clients
- Store API keys in docker-compose.yml

### Secrets Management

✅ **DO:**
- Store secrets in files with restricted permissions
- Rotate API keys regularly
- Use Docker secrets or Kubernetes secrets in production
- Set volumes to read-only (`:ro`)

❌ **DON'T:**
- Commit secrets to version control
- Log passwords or API keys
- Share API keys across environments

### Example: Docker Secrets (Swarm/Compose v3.1+)

```yaml
version: "3.8"

services:
  mattstash-api:
    image: mattstash-api:latest
    secrets:
      - kdbx_password
      - api_keys
    environment:
      - KDBX_PASSWORD_FILE=/run/secrets/kdbx_password
      - MATTSTASH_API_KEYS_FILE=/run/secrets/api_keys

secrets:
  kdbx_password:
    file: ./secrets/kdbx_password.txt
  api_keys:
    file: ./secrets/api_keys.txt
```

## Development

### Local Development (without Docker)

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export MATTSTASH_DB_PATH=/path/to/database.kdbx
export KDBX_PASSWORD=your-password
export MATTSTASH_API_KEY=dev-api-key

# Run server
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### Project Structure

```
server/
├── Dockerfile                 # Basic Docker image
├── Dockerfile.multistage      # Production multi-stage build (smaller image)
├── docker-compose.yml         # Development Docker Compose
├── docker-compose.prod.yml    # Production Docker Compose (enhanced security)
├── requirements.txt           # Python dependencies
├── .env.example               # Example environment variables
├── start.sh                   # Quick start helper script
├── app/                       # FastAPI application
│   ├── __init__.py
│   ├── main.py                # Application factory
│   ├── config.py              # Configuration management
│   ├── dependencies.py        # Dependency injection
│   ├── middleware/            # Custom middleware
│   │   ├── logging.py         # Request/response logging
│   │   └── __init__.py
│   ├── routers/               # API routes
│   │   ├── health.py          # Health check
│   │   ├── credentials.py     # Credential endpoints
│   │   ├── db_url.py          # Database URL builder
│   │   └── __init__.py
│   ├── models/                # Pydantic models
│   │   ├── requests.py        # Request schemas
│   │   ├── responses.py       # Response schemas
│   │   └── __init__.py
│   └── security/              # Security utilities
│       ├── api_keys.py        # API key management
│       └── __init__.py
├── k8s/                       # Kubernetes deployment manifests
│   ├── README.md              # Kubernetes deployment guide
│   ├── namespace.yaml
│   ├── secret.yaml
│   ├── configmap.yaml
│   ├── deployment.yaml
│   ├── service.yaml
│   └── ingress.yaml
├── data/                      # KeePass database location
│   └── .gitkeep
└── secrets/                   # Secrets storage
    └── .gitkeep
```

## Client Examples

### Python

```python
import requests

API_URL = "http://mattstash-api:8000/api/v1"
API_KEY = "your-api-key"

headers = {"X-API-Key": API_KEY}

# Get credential
response = requests.get(
    f"{API_URL}/credentials/db-prod",
    headers=headers,
    params={"show_password": True}
)
cred = response.json()
print(f"Username: {cred['username']}, Password: {cred['password']}")

# Get database URL
response = requests.get(
    f"{API_URL}/db-url/db-prod",
    headers=headers,
    params={"driver": "psycopg", "database": "mydb", "mask_password": False}
)
db_url = response.json()["url"]
print(f"Database URL: {db_url}")
```

### curl

```bash
API_URL="http://mattstash-api:8000/api/v1"
API_KEY="your-api-key"

# List all credentials
curl -H "X-API-Key: $API_KEY" "$API_URL/credentials"

# Get specific credential with password
curl -H "X-API-Key: $API_KEY" "$API_URL/credentials/db-prod?show_password=true"

# Get database URL
curl -H "X-API-Key: $API_KEY" "$API_URL/db-url/db-prod?driver=psycopg&database=mydb"
```

### Docker Compose Integration

```yaml
version: "3.8"

services:
  my-app:
    image: myapp:latest
    environment:
      - MATTSTASH_API_URL=http://mattstash-api:8000/api/v1
      - MATTSTASH_API_KEY=${MY_APP_API_KEY}
    networks:
      - internal
    depends_on:
      - mattstash-api
    command: >
      sh -c "
        DB_URL=$$(curl -s -H 'X-API-Key: $${MATTSTASH_API_KEY}' 
          $${MATTSTASH_API_URL}/db-url/db-prod?mask_password=false | 
          jq -r '.url')
        export DATABASE_URL=$$DB_URL
        python app.py
      "

  mattstash-api:
    image: mattstash-api:latest
    volumes:
      - ./data:/data:ro
      - ./secrets:/secrets:ro
    networks:
      - internal

networks:
  internal:
    driver: bridge
```

## Production Deployment

### Docker Production Build

For production, use the multi-stage Dockerfile for a smaller, more secure image:

```bash
# Build production image
docker build -f Dockerfile.multistage -t mattstash-api:prod .

# Run with production compose file
docker-compose -f docker-compose.prod.yml up -d
```

The production configuration includes:
- Multi-stage build (smaller image size)
- Read-only root filesystem
- Resource limits
- Enhanced security options
- Non-root user execution

### Kubernetes Deployment

Complete Kubernetes manifests are provided in the `k8s/` directory. See [k8s/README.md](k8s/README.md) for detailed deployment instructions.

Quick start:
```bash
# Create namespace and deploy
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Optional: External access with Ingress
kubectl apply -f k8s/ingress.yaml
```

### Example Kubernetes Manifests (Simplified)

Full manifests are in the `k8s/` directory. Here's a simplified example:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mattstash-secrets
type: Opaque
stringData:
  kdbx-password: "your-kdbx-password"
  api-keys: |
    prod-key-1
    prod-key-2

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: mattstash-db
binaryData:
  mattstash.kdbx: <base64-encoded-kdbx-file>

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mattstash-api
spec:
  replicas: 2
  selector:
    matchLabels:
      app: mattstash-api
  template:
    metadata:
      labels:
        app: mattstash-api
    spec:
      containers:
      - name: mattstash-api
        image: mattstash-api:latest
        ports:
        - containerPort: 8000
        env:
        - name: MATTSTASH_DB_PATH
          value: /data/mattstash.kdbx
        - name: KDBX_PASSWORD_FILE
          value: /secrets/kdbx-password
        - name: MATTSTASH_API_KEYS_FILE
          value: /secrets/api-keys
        volumeMounts:
        - name: db
          mountPath: /data
          readOnly: true
        - name: secrets
          mountPath: /secrets
          readOnly: true
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 10
      volumes:
      - name: db
        configMap:
          name: mattstash-db
      - name: secrets
        secret:
          secretName: mattstash-secrets

---
apiVersion: v1
kind: Service
metadata:
  name: mattstash-api
spec:
  type: ClusterIP
  ports:
  - port: 8000
    targetPort: 8000
  selector:
    app: mattstash-api
```

## Troubleshooting

### Common Issues

**Service won't start:**
- Check that `KDBX_PASSWORD` or `KDBX_PASSWORD_FILE` is set
- Verify KeePass database path is correct
- Ensure at least one API key is configured
- Check file permissions on mounted volumes

**Authentication errors:**
- Verify API key is correct
- Check that `X-API-Key` header is included
- Ensure API key doesn't have trailing whitespace

**Credential not found:**
- Verify credential exists in KeePass database
- Check credential name spelling (case-sensitive)
- Ensure MattStash is looking in the correct entry path

### Logs

```bash
# Docker Compose
docker-compose logs -f mattstash-api

# Docker
docker logs -f mattstash-api

# Kubernetes
kubectl logs -f deployment/mattstash-api
```

## License

This server application uses the MattStash library, which is licensed under the MIT License.

## Support

For issues and questions:
- GitHub Issues: https://github.com/yourusername/mattstash/issues
- Documentation: See main project README
