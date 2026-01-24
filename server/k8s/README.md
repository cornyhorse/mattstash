# Kubernetes Deployment Guide

## Prerequisites

- Kubernetes cluster (1.19+)
- kubectl configured to access your cluster
- Docker image built and available to your cluster

## Quick Deploy

### 1. Build and Push Image

```bash
# Build the multi-stage image
docker build -f Dockerfile.multistage -t mattstash-api:latest .

# Tag for your registry
docker tag mattstash-api:latest your-registry.com/mattstash-api:latest

# Push to registry
docker push your-registry.com/mattstash-api:latest
```

### 2. Create Database ConfigMap

```bash
# Create ConfigMap from your KeePass database
kubectl create configmap mattstash-db \
  --from-file=mattstash.kdbx=/path/to/your/database.kdbx \
  -n mattstash
```

### 3. Update Secrets

Edit `k8s/secret.yaml` and replace placeholder values:
- `REPLACE_WITH_YOUR_KDBX_PASSWORD`
- `REPLACE_WITH_API_KEY_1`, etc.

### 4. Deploy

```bash
# Create namespace
kubectl apply -f k8s/namespace.yaml

# Deploy secrets and config
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/configmap.yaml

# Deploy application
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Optional: Deploy ingress for external access
kubectl apply -f k8s/ingress.yaml
```

## Verification

```bash
# Check pods are running
kubectl get pods -n mattstash

# Check service
kubectl get svc -n mattstash

# View logs
kubectl logs -f deployment/mattstash-api -n mattstash

# Test health endpoint
kubectl port-forward svc/mattstash-api 8000:8000 -n mattstash
curl http://localhost:8000/health
```

## Accessing the API

### From within the cluster

Other pods can access the API at:
```
http://mattstash-api.mattstash.svc.cluster.local:8000
```

Example pod configuration:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: my-namespace
spec:
  containers:
  - name: app
    image: myapp:latest
    env:
    - name: MATTSTASH_API_URL
      value: "http://mattstash-api.mattstash.svc.cluster.local:8000"
    - name: MATTSTASH_API_KEY
      valueFrom:
        secretKeyRef:
          name: my-app-secrets
          key: mattstash-api-key
```

### From outside the cluster (with Ingress)

If you deployed the ingress, access at:
```
https://mattstash.example.com
```

## Security Considerations

1. **Secrets Management**: Use Sealed Secrets or external secret managers (Vault, AWS Secrets Manager)
2. **Network Policies**: Restrict which pods can access the API
3. **RBAC**: Limit access to the mattstash namespace
4. **Image Security**: Scan images for vulnerabilities
5. **TLS**: Always use TLS for external access
6. **Audit Logging**: Enable Kubernetes audit logging

## Scaling

```bash
# Scale replicas
kubectl scale deployment mattstash-api --replicas=3 -n mattstash

# Autoscaling (optional)
kubectl autoscale deployment mattstash-api \
  --min=2 --max=5 \
  --cpu-percent=70 \
  -n mattstash
```

## Updating

```bash
# Update image
kubectl set image deployment/mattstash-api \
  mattstash-api=your-registry.com/mattstash-api:v2 \
  -n mattstash

# Watch rollout
kubectl rollout status deployment/mattstash-api -n mattstash

# Rollback if needed
kubectl rollout undo deployment/mattstash-api -n mattstash
```

## Troubleshooting

```bash
# Describe pod for issues
kubectl describe pod <pod-name> -n mattstash

# View logs
kubectl logs <pod-name> -n mattstash

# Get into pod for debugging (if shell available)
kubectl exec -it <pod-name> -n mattstash -- /bin/sh

# Check events
kubectl get events -n mattstash --sort-by='.lastTimestamp'
```

## Network Policy Example

Restrict access to only specific namespaces:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: mattstash-api-policy
  namespace: mattstash
spec:
  podSelector:
    matchLabels:
      app: mattstash-api
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          allowed-to-mattstash: "true"
    ports:
    - protocol: TCP
      port: 8000
```

Apply to allowed namespaces:
```bash
kubectl label namespace my-app-namespace allowed-to-mattstash=true
```
