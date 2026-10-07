#
# MattStash API server - single-stage image.
#
# BUILD CONTEXT = THE REPOSITORY ROOT (not server/). The image installs the mattstash library
# from this checkout, so an image always contains the library code of its own commit rather
# than whatever release happens to be on PyPI:
#
#     docker build -f server/Dockerfile -t mattstash-api .
#
# (Use server/Dockerfile.multistage for the slimmer variant that keeps build leftovers out of
# the final image; both run exactly the same application.)
#
# Base image: pinned to the python:3.12-slim tag. For fully reproducible builds also pin the
# digest, e.g.  FROM python:3.12-slim@sha256:<digest>  (`docker buildx imagetools inspect
# python:3.12-slim` prints it). Dependabot's "docker" ecosystem (.github/dependabot.yml)
# proposes updates for the tag and the digest.
FROM python:3.12-slim

# Unbuffered stdout/stderr so logs reach `docker logs` / `kubectl logs` immediately;
# no .pyc files (the root filesystem is meant to be mounted read-only at runtime).
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Non-root runtime user. The numeric uid/gid (1000) is what the compose and Kubernetes
# examples assume; override at runtime (`user:` / `runAsUser`) to match the owner of your
# bind-mounted files. /data exists and is owned by that user so a NAMED volume mounted there
# is writable in the (opt-in) write mode; read-only deployments never write to it.
RUN groupadd --gid 1000 mattstash \
 && useradd --uid 1000 --gid 1000 --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin mattstash \
 && mkdir /data \
 && chown mattstash:mattstash /data

WORKDIR /build

# 1) Third-party dependencies: hash-pinned lockfile, wheels only. pip refuses any file whose
#    hash is not listed, so a tampered or substituted package fails the build.
#    (Regenerate the lock with the command in its header when requirements.in changes.)
COPY server/requirements.lock server/requirements.lock
RUN pip install --no-cache-dir --disable-pip-version-check \
        --require-hashes --only-binary=:all: -r server/requirements.lock

# 2) The mattstash library + CLI, from this repository. Its dependencies were installed (and
#    hash-verified) above, hence --no-deps; `pip check` then proves the lock still satisfies
#    the ranges in pyproject.toml. The build backend (hatchling) is resolved by pip's isolated
#    build environment and is NOT hash-pinned; it is build-time only and never in the image.
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/
RUN pip install --no-cache-dir --disable-pip-version-check --no-deps . \
 && pip check \
 && rm -rf /build

# 3) The server application (root-owned, so the runtime user cannot modify its own code).
WORKDIR /app
COPY server/app/ ./app/

# Numeric user so Kubernetes `runAsNonRoot` can verify it without guessing.
USER 1000:1000
EXPOSE 8000

# Liveness only: /health never touches the database. (Readiness, i.e. "the database opened",
# is /ready; orchestrators with a readiness concept should probe that one instead.)
# If you enable in-app TLS (MATTSTASH_TLS_CERT_FILE) the probe switches to https and skips
# certificate verification, because it talks to 127.0.0.1.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD ["python", "-c", "import os, ssl, urllib.request as u; tls = bool(os.environ.get('MATTSTASH_TLS_CERT_FILE')); u.urlopen(('https' if tls else 'http') + '://127.0.0.1:' + os.environ.get('MATTSTASH_PORT', '8000') + '/health', timeout=3, context=ssl._create_unverified_context() if tls else None)"]

# Starts uvicorn via the app's own entrypoint (app/__main__.py). Honours MATTSTASH_HOST,
# MATTSTASH_PORT, MATTSTASH_LOG_LEVEL and optional TLS (MATTSTASH_TLS_CERT_FILE +
# MATTSTASH_TLS_KEY_FILE). Do not set `command:` in compose / `command:` in Kubernetes.
CMD ["python", "-m", "app"]
