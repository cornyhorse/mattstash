# Kubernetes Deployment Guide

Manifests for running the MattStash API server in a cluster. Two modes, deliberately separate:

| | **Read-only (default)** | **Writable (opt-in)** |
|---|---|---|
| Manifests | `deployment.yaml`, `pdb.yaml` | `writable/deployment.yaml`, `writable/pvc.yaml`, `writable/setup-job.yaml` |
| `MATTSTASH_ALLOW_WRITES` | `false` (POST/DELETE answer `405`) | `true` |
| Database lives in | a **Secret** (`mattstash-db`), mounted read-only | a **PersistentVolumeClaim**, mounted read-write |
| Replicas | 2 or more (rolling updates) | **exactly 1**, `strategy: Recreate` |
| Updating the database | replace the Secret; the pods pick it up | write through the API |

Use **one** of the two Deployments, never both. The database is a single KeePass file: two writers lose
updates, so write mode never runs with more than one replica (no HPA, no `kubectl scale`, no PDB).

Everything else (Namespace, ServiceAccount, ConfigMap, Service, NetworkPolicy, Ingress) is shared.

## Files

| File | Purpose |
|---|---|
| `namespace.yaml` | Namespace `mattstash`, Pod Security Admission `restricted` enforced |
| `serviceaccount.yaml` | Dedicated ServiceAccount, no API token (`automountServiceAccountToken: false`) |
| `configmap.yaml` | Non-secret settings (paths, log level, rate limit, ...). **No database in here** |
| `secret.example.yaml` | Template + instructions for the Secrets. Do not commit a filled-in copy |
| `deployment.yaml` | Read-only server, 2 replicas, probes `/health` + `/ready` |
| `pdb.yaml` | PodDisruptionBudget for the multi-replica read-only case |
| `service.yaml` | ClusterIP Service on port 8000 |
| `networkpolicy.yaml` | Default-deny ingress, allow labelled client namespaces, deny egress |
| `ingress.yaml` | Optional TLS ingress (ingress-nginx annotations) |
| `writable/` | The opt-in write mode: PVC, one-off `setup` Job, single-replica Deployment |

## Prerequisites

- Kubernetes 1.25+ (`policy/v1` PDB, Pod Security Admission). The manifests were schema-checked against
  1.29 and 1.36.
- `kubectl` access to the cluster.
- A CNI that **enforces** NetworkPolicy (Calico, Cilium, Antrea, ...). Without one the policies are accepted
  and do nothing.
- A KeePass database created with `mattstash setup` (the server never creates one) and its master password.

Commands below are run from the `server/` directory (paths are written as `k8s/...`).

## 1. Pick the image

Use a **published, pinned** image. The manifests reference `ghcr.io/cornyhorse/mattstash:v0.2.0`, the first
release with the read-only mode and the `/ready` endpoint; use the newest release tag.

- Never deploy `:latest`: a restart or a new node can silently pull different code.
- Prefer a digest: `image: ghcr.io/cornyhorse/mattstash@sha256:<digest>` (`docker buildx imagetools inspect
  ghcr.io/cornyhorse/mattstash:vX.Y.Z` prints it). Release images carry build provenance and an SBOM.
- Building yourself? The build context is the **repository root** (the image installs this checkout's library):

  ```bash
  docker build -f server/Dockerfile -t your-registry.example/mattstash-api:vX.Y.Z .
  docker push your-registry.example/mattstash-api:vX.Y.Z
  ```

  Then edit `image:` in the Deployment (and the setup Job).

## 2. Namespace, ServiceAccount, configuration

```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/serviceaccount.yaml
kubectl apply -f k8s/configmap.yaml
```

## 3. Secrets ("secret zero")

Two Secrets, mounted at two different paths so the data volume alone never opens the database:

| Secret | Contents | Mounted at |
|---|---|---|
| `mattstash-secrets` | `kdbx-password` (master password), `api-keys` | `/secrets` |
| `mattstash-db` | `mattstash.kdbx` (read-only mode only) | `/data` |

Create them from files that live **outside** the repository:

```bash
# API keys: at least 32 characters each, one per line (or a JSON policy file; see docs/configuration.md)
openssl rand -base64 32 > api_keys.txt

kubectl -n mattstash create secret generic mattstash-secrets \
  --from-file=kdbx-password=./kdbx_password.txt \
  --from-file=api-keys=./api_keys.txt

# Read-only mode only: the database itself
kubectl -n mattstash create secret generic mattstash-db \
  --from-file=mattstash.kdbx=./mattstash.kdbx
```

Notes:

- **Never commit real secrets.** `secret.example.yaml` is a template with deliberately invalid placeholders
  (`CHANGE-ME` is shorter than the 32-character key minimum, so an unedited copy refuses to start). A copy named
  `secret.yaml` is git-ignored. Keep any filled-in manifest out of git, or keep only an *encrypted* form:
  [Sealed Secrets](https://github.com/bitnami-labs/sealed-secrets), [SOPS](https://github.com/getsops/sops), or sync
  from a vault with [External Secrets Operator](https://external-secrets.io/) or the Secrets Store CSI driver
  (Vault, AWS/GCP/Azure secret managers).
- **A Secret is base64, not encryption.** Enable encryption at rest for Secrets in etcd, and use RBAC to limit who
  can `get`/`list`/`watch` secrets in this namespace and who can `exec` into the pods; either can read your master
  password and API keys.
- **Size limit.** A Secret holds at most 1 MiB including base64 overhead, i.e. roughly 700 KiB of `.kdbx`: ample for
  thousands of entries. A larger database, or write mode, uses the PVC instead.
- **API keys** must be at least 32 characters; the server refuses to start with weaker ones. Never reuse the sample
  placeholders, never share one key between all clients; use a scoped key policy (`docs/configuration.md`).
- **File modes.** Secret volumes use `defaultMode: 0400`. Because the pod sets `fsGroup`, the kubelet makes the files
  group-readable by that group (0440) so the non-root user can read them; the library may log a one-line
  "insecure permissions" warning about the database file. This is expected for Secret volumes.

## 4a. Deploy: read-only (default)

```bash
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/pdb.yaml
kubectl apply -f k8s/networkpolicy.yaml
```

**Updating the database** (new or changed entries): re-create the Secret,

```bash
kubectl -n mattstash create secret generic mattstash-db \
  --from-file=mattstash.kdbx=./mattstash.kdbx --dry-run=client -o yaml | kubectl apply -f -
```

The kubelet swaps the file in every pod within about a minute, and the server notices the changed file at its next
poll (`MATTSTASH_DB_POLL_INTERVAL`, default 5 s) and reloads it. No restart is needed. (Do not mount the Secret with
`subPath`: those mounts are never updated.)

## 4b. Deploy: writable (opt-in)

For when clients must create, update or delete secrets through the API. One replica, one writer:

```bash
kubectl apply -f k8s/writable/pvc.yaml

# Create the empty database on the volume, once. The server never creates one.
kubectl apply -f k8s/writable/setup-job.yaml
kubectl -n mattstash wait --for=condition=complete job/mattstash-setup --timeout=120s
kubectl -n mattstash delete job mattstash-setup

kubectl apply -f k8s/writable/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/networkpolicy.yaml
```

(Skip the Job and place an existing database on the volume instead if you prefer; see the comments in
`setup-job.yaml`.) Do **not** apply `pdb.yaml`: with one replica it would block node drains. Do not create the
`mattstash-db` Secret.

Things to know about write mode:

- **The directory must be writable by uid/gid 1000**, not just the `.kdbx`: each write creates `<db>.lock` and a
  temporary file next to the database. `fsGroup: 1000` takes care of this on most storage drivers; if yours ignores
  `fsGroup`, fix ownership with an initContainer or the storage class.
- Use `ReadWriteOncePod` in `pvc.yaml` where your storage driver supports it; the storage layer then refuses a
  second pod.
- `strategy: Recreate` means a brief outage during updates. That is the price of a single writer.
- **Back up the volume** (VolumeSnapshot, Velero, ...). The database is the only copy of your secrets.
- Any API key that may write can change or delete secrets. Use scoped keys.

## 5. Allow clients (NetworkPolicy)

`networkpolicy.yaml` denies all ingress in the namespace and allows port 8000 from namespaces labelled
`allowed-to-mattstash=true`. Grant access per client namespace:

```bash
kubectl label namespace my-app-namespace allowed-to-mattstash=true
```

The file also shows how to restrict to labelled pods only and how to allow an ingress controller. It additionally
denies **all egress** from the API pods: the server only reads local files and needs no DNS or outbound traffic.
Verify the policy from a pod in a namespace that is *not* labelled; it must time out.

## 6. Optional: Ingress with TLS

```bash
kubectl apply -f k8s/ingress.yaml
```

Edit the host and the TLS Secret name first. Remember to allow the ingress controller's namespace in
`networkpolicy.yaml`. The ingress exposes only `/api` (the v1 API, `/api/health`, `/api/ready`); the bare
`/health` and `/ready` stay cluster-internal.

**TLS and rate limiting.** The recommended setup is to terminate TLS at the ingress (as shipped); the hop from the
controller to the pod is plain HTTP on the cluster network. The server can also serve TLS itself
(`MATTSTASH_TLS_CERT_FILE` + `MATTSTASH_TLS_KEY_FILE`); if you enable that, add `scheme: HTTPS` to the three probes.

The server throttles repeated failed logins per client IP. Behind an ingress controller every request would appear
to come from the controller, so all clients would share one bucket. Set `MATTSTASH_TRUSTED_PROXY_HOPS` in the
ConfigMap to the number of proxy hops you control (typically `1`: the ingress controller). Leave it at the default
`0` if clients can reach the pods directly, otherwise they can forge `X-Forwarded-For` and evade the limits. Add
edge limits too (the shipped annotations use `limit-rps` and `proxy-body-size`).

## Verification

```bash
kubectl -n mattstash get pods,svc
kubectl -n mattstash logs -f deployment/mattstash-api

kubectl -n mattstash port-forward svc/mattstash-api 8000:8000 &
curl -s http://localhost:8000/health   # liveness: 200 whenever the process runs, never touches the database
curl -s http://localhost:8000/ready    # readiness: 200 only when the database opened, otherwise 503
curl -s -H "X-API-Key: $(head -n1 api_keys.txt)" http://localhost:8000/api/v1/credentials
```

Probes: **liveness `/health`** (so a database problem can never get healthy processes killed), **readiness `/ready`**
(a pod whose database cannot be opened is kept out of the Service), and a **startup probe on `/ready`** that allows up
to a minute for the database to open. Docker/compose health checks use `/health`.

## Using the API from another pod

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-app
  namespace: my-namespace          # must carry the allowed-to-mattstash=true label
spec:
  containers:
  - name: app
    image: myapp:latest
    env:
    - name: MATTSTASH_SERVER_URL
      value: "http://mattstash-api.mattstash.svc.cluster.local:8000"
    - name: MATTSTASH_ALLOW_INSECURE_HTTP   # in-cluster plain http is the documented pattern;
      value: "1"                            # the CLI warns about http:// to non-loopback hosts otherwise
    - name: MATTSTASH_API_KEY
      valueFrom:
        secretKeyRef:
          name: my-app-secrets
          key: mattstash-api-key
```

## Hardening applied by the manifests

- Pod Security Admission `restricted` on the namespace; pods run as non-root (uid 1000), `RuntimeDefault` seccomp,
  all capabilities dropped, no privilege escalation, read-only root filesystem (writable `/tmp` is a small emptyDir).
- Dedicated ServiceAccount with no token and no RBAC bindings; `enableServiceLinks: false`.
- Secret volumes `defaultMode: 0400`; master password and API keys in a different mount from the database.
- Resource requests and limits; topology spread for the replicas; PodDisruptionBudget (read-only).
- NetworkPolicy: default-deny ingress, allow-list of client namespaces, no egress.
- Pinned image tag/digest (never `:latest`).

## Scaling

- **Read-only:** scale freely (`kubectl scale deployment mattstash-api --replicas=3 -n mattstash`, or an HPA). All
  replicas serve identical, read-only data.
- **Writable:** never. One replica, `Recreate`.

## Troubleshooting

```bash
kubectl -n mattstash describe pod <pod-name>
kubectl -n mattstash logs <pod-name>
kubectl -n mattstash get events --sort-by='.lastTimestamp'
```

| Symptom | Likely cause |
|---|---|
| Pod never Ready, `/ready` returns 503 | Wrong master password, database missing/corrupt, or the `mattstash-db` Secret not mounted. The logs name the problem (never the password). |
| Pod crash-loops at start | Config invalid: API key shorter than 32 characters (e.g. the `CHANGE-ME` placeholder), unreadable `KDBX_PASSWORD_FILE`, missing database. |
| `405` on POST/DELETE | Read-only mode is on (the default). Use the writable deployment if you really need writes. |
| Writes fail in write mode ("cannot create lock file", permission denied) | The volume's directory is not writable by uid 1000; see section 4b. |
| Clients time out | The client namespace lacks the `allowed-to-mattstash=true` label (or the pod label, if you use the stricter rule); or the ingress controller's namespace is not allowed. |
| All clients rate-limited together | `MATTSTASH_TRUSTED_PROXY_HOPS` is not set while traffic arrives through the ingress. |
| New database not picked up | Check the Secret was updated (`kubectl get secret mattstash-db -o jsonpath='{.metadata.resourceVersion}'`), allow ~1 minute for the kubelet, and make sure the Secret is not mounted with `subPath`. |
