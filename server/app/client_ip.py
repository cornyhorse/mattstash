"""Client address resolution (optionally behind trusted reverse proxies).

Two views of the same address are provided:

* :func:`client_ip` - the normalised address, for logs and the audit trail;
* :func:`client_bucket` - the *throttling identity*: IPv4 addresses as they are, IPv6 addresses collapsed to
  their /64 network (a single subscriber normally controls a whole /64, so per-address buckets would give an
  attacker billions of fresh budgets). IPv4-mapped IPv6 addresses are treated as the IPv4 address.
"""

import ipaddress
import re
from typing import Any, MutableMapping, Optional

from .config import config

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
_PORT = re.compile(r"\d{1,5}")


def parse_address(text: str) -> Optional[IPAddress]:
    """Parse an address as it appears in ``X-Forwarded-For`` or as the ASGI peer.

    Accepts plain IPv4/IPv6, ``ip:port``, ``[ipv6]`` and ``[ipv6]:port``, with an optional IPv6 scope id which is
    discarded. IPv4-mapped IPv6 addresses are returned as IPv4. Returns None for anything else.
    """
    value = text.strip()
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return None
        host, rest = value[1:end], value[end + 1 :]
        if rest and not (rest.startswith(":") and _PORT.fullmatch(rest[1:])):
            return None
    elif value.count(":") == 1:  # ipv4:port (a bare IPv6 address has more than one colon)
        host, _, port = value.partition(":")
        if not _PORT.fullmatch(port):
            return None
    else:
        host = value
    host = host.split("%", 1)[0]  # scope id ("fe80::1%eth0")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _resolve(scope: MutableMapping[str, Any]) -> Optional[IPAddress]:
    peer = scope.get("client")
    peer_ip = parse_address(str(peer[0])) if peer else None
    hops = config.TRUSTED_PROXY_HOPS
    if hops <= 0:
        return peer_ip

    forwarded: list[str] = []
    for name, value in scope.get("headers", []):
        if name == b"x-forwarded-for":
            forwarded.extend(part.strip() for part in value.decode("latin-1").split(","))
    forwarded = [part for part in forwarded if part]
    index = len(forwarded) - hops
    if index < 0:
        return peer_ip
    return parse_address(forwarded[index]) or peer_ip


def client_ip(scope: MutableMapping[str, Any]) -> str:
    """Normalised client address for an ASGI ``scope``.

    By default this is the TCP peer, which cannot be spoofed. With ``MATTSTASH_TRUSTED_PROXY_HOPS=N`` the
    address is taken from ``X-Forwarded-For``, counting N entries from the *right* (the entries appended by your
    own proxies); anything left of that is client-controlled and ignored. If the header is missing, too short or
    not an address we fall back to the peer address.
    """
    ip = _resolve(scope)
    return str(ip) if ip is not None else "unknown"


def client_bucket(scope: MutableMapping[str, Any]) -> str:
    """Throttling identity of the client: the IPv4 address or the IPv6 /64 network."""
    ip = _resolve(scope)
    if ip is None:
        return "unknown"
    if isinstance(ip, ipaddress.IPv6Address):
        return str(ipaddress.ip_network(f"{ip}/64", strict=False))
    return str(ip)
