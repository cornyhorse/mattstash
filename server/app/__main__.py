"""Run the server: ``python -m app``.

Honours MATTSTASH_HOST, MATTSTASH_PORT, MATTSTASH_LOG_LEVEL and, for TLS, MATTSTASH_TLS_CERT_FILE +
MATTSTASH_TLS_KEY_FILE (both or neither). Prefer terminating TLS at a reverse proxy/ingress when you have one;
use this when clients talk to the container directly.
"""

import uvicorn

from .config import config


def main() -> None:
    tls = config.validate_tls()
    uvicorn.run(
        "app.main:app",
        host=config.HOST,
        port=config.PORT,
        log_level=config.LOG_LEVEL.lower(),
        ssl_certfile=config.TLS_CERT_FILE if tls else None,
        ssl_keyfile=config.TLS_KEY_FILE if tls else None,
        server_header=False,  # do not advertise the server software
        proxy_headers=False,  # client IPs come from MATTSTASH_TRUSTED_PROXY_HOPS, not from uvicorn
    )


if __name__ == "__main__":
    main()
