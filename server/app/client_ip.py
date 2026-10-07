"""Client address resolution (optionally behind trusted reverse proxies)."""

import ipaddress
from typing import Any, MutableMapping

from .config import config


def client_ip(scope: MutableMapping[str, Any]) -> str:
    """Return the client address for an ASGI ``scope``.

    By default this is the TCP peer, which cannot be spoofed. With ``MATTSTASH_TRUSTED_PROXY_HOPS=N`` the
    address is taken from ``X-Forwarded-For``, counting N entries from the *right* (the entries appended by
    your own proxies); anything left of that is client-controlled and ignored. If the header is missing, too
    short or not an IP address we fall back to the peer address.
    """
    peer = scope.get("client")
    host = peer[0] if peer else "unknown"
    hops = config.TRUSTED_PROXY_HOPS
    if hops <= 0:
        return str(host)

    forwarded: list[str] = []
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            forwarded.extend(part.strip() for part in value.decode("latin-1").split(","))
    forwarded = [part for part in forwarded if part]
    index = len(forwarded) - hops
    if index < 0:
        return str(host)
    candidate = forwarded[index]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return str(host)
