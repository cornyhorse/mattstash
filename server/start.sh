#!/usr/bin/env bash
# Quick start for the MattStash API server with Docker Compose.
#
#   ./start.sh              start the default stack (READ-ONLY server, docker-compose.yml)
#   ./start.sh --writable   additionally enable write mode (docker-compose.writable.yml)
#   ./start.sh --prod       use docker-compose.prod.yml (hardened; publishes no port, see that file)
#   ./start.sh --down       stop the stack started with the same flags
#
# What it does:
#   * creates data/ and secrets/ (mode 0700) if they are missing;
#   * generates a strong random API key in secrets/api_keys.txt if there is none;
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

# ---- directories and API key -------------------------------------------------------------------
umask 077
mkdir -p data secrets

generate_key() {
    # 32 random bytes, base64 -> 43/44 characters (the server requires at least 32).
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -base64 32
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import secrets; print(secrets.token_urlsafe(32))'
    else
        head -c 32 /dev/urandom | base64 | tr -d '\n'
        echo
    fi
}

if [ ! -s secrets/api_keys.txt ]; then
    key="$(generate_key)"
    [ "${#key}" -ge 32 ] || die "could not generate a strong API key"
    printf '%s\n' "$key" >secrets/api_keys.txt
    chmod 0600 secrets/api_keys.txt
    echo "Generated a new API key in secrets/api_keys.txt (read it with: head -n1 secrets/api_keys.txt)."
    unset key
elif ! head -c 4096 secrets/api_keys.txt | grep -Eq '^[[:space:]]*[{[]'; then
    # Plain one-key-per-line file (a JSON policy file is validated by the server instead).
    weak=false
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line//[[:space:]]/}"
        case "$line" in '' | '#'*) continue ;; esac
        if [ "${#line}" -lt 32 ]; then weak=true; fi
    done <secrets/api_keys.txt
    if [ "$weak" = true ]; then
        die "secrets/api_keys.txt contains a key shorter than 32 characters; the server will refuse to start. Replace it (openssl rand -base64 32)."
    fi
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
    echo "Try it:     curl -H \"X-API-Key: \$(head -n1 secrets/api_keys.txt)\" http://127.0.0.1:8000/api/v1/credentials"
    echo "API docs (unless disabled with MATTSTASH_DISABLE_DOCS): http://127.0.0.1:8000/api/v1/docs"
fi
echo "Logs:       ${COMPOSE[*]} ${COMPOSE_FILES[*]} logs -f"
echo "Stop:       ./start.sh $* --down"
