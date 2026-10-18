#!/usr/bin/env bash
# Quick start for the MattStash API server with Docker Compose.
#
#   ./start.sh              start the default stack (READ-ONLY server, docker-compose.yml)
#   ./start.sh --writable   additionally enable write mode (docker-compose.writable.yml)
#   ./start.sh --prod       use docker-compose.prod.yml (hardened; publishes no port, see that file)
#   ./start.sh --down       stop the stack started with the same flags
#
# What it does:
#   * creates data/, secrets/, policy/ and tokens/ (mode 0700) if they are missing;
#   * creates a policy file (policy/policy.json) with one admin principal and writes its token to
#     tokens/admin.token if there is no policy file (needs the `mattstash` CLI: pip install mattstash);
#   * checks that the master password file and the database exist;
#   * starts the stack and waits until the container reports healthy.
#
# What it deliberately does NOT do: create the database or invent the master password. Only
# `mattstash setup` creates a database, and you decide where the master password lives. If those
# files are missing the script tells you what to run and stops.

set -euo pipefail

cd "$(dirname "$0")"

die() {
    echo "error: $*" >&2
    exit 1
}

# ---- arguments --------------------------------------------------------------------------------
COMPOSE_FILES=(-f docker-compose.yml)
BASE=default
WRITABLE=false
DOWN=false
for arg in "$@"; do
    case "$arg" in
        --prod) BASE=prod ;;
        --writable) WRITABLE=true ;;
        --down) DOWN=true ;;
        -h | --help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) die "unknown option: $arg (try --help)" ;;
    esac
done
if [ "$BASE" = prod ]; then
    COMPOSE_FILES=(-f docker-compose.prod.yml)
fi
if [ "$WRITABLE" = true ]; then
    COMPOSE_FILES+=(-f docker-compose.writable.yml)
fi

# ---- docker compose (v2 plugin; the old docker-compose v1 binary only as a fallback) -----------
if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
    echo "warning: using the legacy docker-compose binary (v1, end of life); install the Docker Compose plugin" >&2
    COMPOSE=(docker-compose)
else
    die "Docker Compose not found. Install Docker with the compose plugin (https://docs.docker.com/compose/install/)."
fi

# The container user must be able to read data/ and secrets/ (and write data/ in write mode), so run
# it as the invoking user. Never default to root.
MATTSTASH_UID="${MATTSTASH_UID:-$(id -u)}"
MATTSTASH_GID="${MATTSTASH_GID:-$(id -g)}"
if [ "$MATTSTASH_UID" = 0 ]; then
    echo "warning: running as root; the container will run as uid/gid 1000 - make sure it can read data/ and secrets/" >&2
    MATTSTASH_UID=1000
    MATTSTASH_GID=1000
fi
export MATTSTASH_UID MATTSTASH_GID

if [ "$DOWN" = true ]; then
    "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" down
    exit 0
fi

# ---- directories and policy file ---------------------------------------------------------------
umask 077
mkdir -p data secrets policy tokens

# The server needs a policy file: principals, the HASHES of their tokens, and their grants. Without one it does not
# start. An admin principal (no access to any secret by itself) is enough to begin with; its token goes to
# tokens/admin.token, which is NOT mounted into the container. Add one principal per client yourself, e.g.
#   mattstash admin --policy-file policy/policy.json principal add myapp --kind agent
#   mattstash admin --policy-file policy/policy.json grant add myapp --key 'myapp.*'
#   mattstash admin --policy-file policy/policy.json token issue myapp --output-file tokens/myapp.token
if [ ! -s policy/policy.json ]; then
    if [ -e secrets/api_keys.txt ]; then
        echo "note: secrets/api_keys.txt is no longer read (API keys were removed in 0.3). To keep your clients working" >&2
        echo "      without downtime, import their keys into the policy file: see docs/upgrading-to-0.3.md." >&2
    fi
    command -v mattstash >/dev/null 2>&1 ||
        die "policy/policy.json is missing and the mattstash CLI is not installed to create it (pip install mattstash)."
    mattstash admin --policy-file policy/policy.json principal add admin --kind human-device --admin \
        --description "created by start.sh" >/dev/null
    mattstash admin --policy-file policy/policy.json token issue admin --output-file tokens/admin.token --expires 365d
    echo "Created policy/policy.json with an admin principal; its token is in tokens/admin.token (valid 365 days)."
fi

# ---- master password and database (never created here) -----------------------------------------
missing=false
if [ ! -s secrets/kdbx_password.txt ]; then
    missing=true
    echo "Missing secrets/kdbx_password.txt (the KeePass master password)." >&2
fi
if [ ! -f data/mattstash.kdbx ]; then
    missing=true
    echo "Missing data/mattstash.kdbx (the KeePass database)." >&2
fi
if [ "$missing" = true ]; then
    cat >&2 <<'EOF'

To create a new database with a fresh random master password (needs the mattstash CLI: pip install mattstash):

    (umask 077; openssl rand -base64 32 > secrets/kdbx_password.txt)
    mattstash --db data/mattstash.kdbx setup --password-file secrets/kdbx_password.txt

To use an existing database instead, copy it to data/mattstash.kdbx and put its master password in
secrets/kdbx_password.txt. Keep the password OUT of data/: do not use `mattstash setup --sidecar`
for a service, because a .mattstash.txt next to the database defeats the separate secrets mount.
EOF
    exit 1
fi
if [ -e data/.mattstash.txt ]; then
    echo "warning: data/.mattstash.txt exists. A password file next to the database lets anyone who can read data/ open it; remove it and rely on secrets/kdbx_password.txt." >&2
fi

# ---- start --------------------------------------------------------------------------------------
echo "Starting with: ${COMPOSE[*]} ${COMPOSE_FILES[*]} up -d --build"
"${COMPOSE[@]}" "${COMPOSE_FILES[@]}" up -d --build

echo "Waiting for the container to become healthy..."
status=unknown
for _ in $(seq 1 60); do
    status="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' mattstash-api 2>/dev/null || echo unknown)"
    [ "$status" = healthy ] && break
    sleep 2
done
if [ "$status" != healthy ]; then
    echo "error: container is '$status' after 120s. Recent logs:" >&2
    "${COMPOSE[@]}" "${COMPOSE_FILES[@]}" logs --tail 30 >&2 || true
    exit 1
fi

echo
if [ "$WRITABLE" = true ]; then
    echo "Server is up in WRITE mode (single instance; back up data/ regularly)."
else
    echo "Server is up in READ-ONLY mode (POST/DELETE return 405). Use --writable to enable writes."
fi
echo

if [ "$BASE" = prod ]; then
    echo "The production file publishes no port; clients join the 'backend' network (see docker-compose.prod.yml)."
    echo "Check status with:  ${COMPOSE[*]} ${COMPOSE_FILES[*]} ps"
else
    # /health = liveness (always 200 while the process runs); /ready = the database opened.
    if command -v curl >/dev/null 2>&1; then
        if curl -fsS http://127.0.0.1:8000/ready >/dev/null 2>&1; then
            echo "Readiness: OK (database opened)."
        else
            echo "warning: /ready did not return 200 - check the logs: ${COMPOSE[*]} ${COMPOSE_FILES[*]} logs" >&2
        fi
    fi
    echo "Liveness:   curl http://127.0.0.1:8000/health"
    echo "Readiness:  curl http://127.0.0.1:8000/ready"
    # Not `-H "X-API-Key: $(cat ...)"`: that would put the token in curl's argument list, which every local user can
    # read with `ps`. A header file (mode 0600, written with the shell builtin printf) keeps it out of argv.
    if [ -s tokens/admin.token ]; then
        (umask 077; printf 'X-API-Key: %s\n' "$(cat tokens/admin.token)" >tokens/admin.header)
        echo "Try it:     curl -H @tokens/admin.header http://127.0.0.1:8000/api/v1/admin/principals"
        echo "            (tokens/admin.header holds the token for curl -H @file; delete it when you are done.)"
    else
        echo "Try it:     mattstash --server-url http://127.0.0.1:8000 --api-key-file <token file> admin principal list"
    fi
    echo "            (the admin token manages principals and grants; it reads no secret. Issue a token per client.)"
    echo "API docs (unless disabled with MATTSTASH_DISABLE_DOCS): http://127.0.0.1:8000/api/v1/docs"
fi
echo "Logs:       ${COMPOSE[*]} ${COMPOSE_FILES[*]} logs -f"
echo "Stop:       ./start.sh $* --down"
