"""Run the server: ``python -m app``.

Honours MATTSTASH_HOST, MATTSTASH_PORT, MATTSTASH_LOG_LEVEL and, for TLS, MATTSTASH_TLS_CERT_FILE +
MATTSTASH_TLS_KEY_FILE (both or neither). Prefer terminating TLS at a reverse proxy/ingress when you have one;
use this when clients talk to the container directly.
"""

import sys

import uvicorn

from .config import config
from .logging_setup import uvicorn_level
from .security.api_keys import check_removed_settings, load_auth_state


def main() -> None:
    try:
        check_removed_settings()
        load_auth_state()  # the policy file: missing, unreadable, invalid or without a usable credential
    except (ValueError, FileNotFoundError) as exc:  # PolicyError is a ValueError; a message and exit 1, no traceback
        sys.exit(f"mattstash-server: {exc}")
    tls = config.validate_tls()
    uvicorn.run(
        "app.main:app",
        host=config.HOST,
        port=config.PORT,
        log_level=uvicorn_level(),
        ssl_certfile=config.TLS_CERT_FILE if tls else None,
        ssl_keyfile=config.TLS_KEY_FILE if tls else None,
        access_log=False,  # the app's own access log (client address + key id) replaces uvicorn's anonymous one
        server_header=False,  # do not advertise the server software
        proxy_headers=False,  # client IPs come from MATTSTASH_TRUSTED_PROXY_HOPS, not from uvicorn
    )


if __name__ == "__main__":
    main()
