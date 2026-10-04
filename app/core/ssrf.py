"""SSRF protection: resolve DNS and reject private / reserved addresses.

Validates every hop in a redirect chain (IPv4 + IPv6).
DNS rebinding is documented as a residual risk — see docs/security.md.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class SSRFError(Exception):
    """Raised when a URL resolves to a blocked address or scheme."""


BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),  # carrier-grade NAT
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),  # IPv4-mapped — checked via mapped v4
]


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return _is_blocked_ip(ip.ipv4_mapped)
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
        return True
    if ip.is_multicast or ip.is_unspecified:
        return True
    for net in BLOCKED_NETWORKS:
        if ip in net:
            return True
    return False


def validate_hostname_resolved(hostname: str) -> list[str]:
    """Resolve hostname and ensure every address is publicly routable.

    Returns the list of resolved IP strings.
    """
    if not hostname:
        raise SSRFError("Empty hostname")

    host = hostname.strip("[]").lower()
    if host in {"localhost", "metadata.google.internal"}:
        raise SSRFError(f"Blocked hostname: {host}")

    # Literal IP in URL
    try:
        literal = ipaddress.ip_address(host)
        if _is_blocked_ip(literal):
            raise SSRFError(f"Blocked IP address: {host}")
        return [str(literal)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"DNS resolution failed for {host}: {exc}") from exc

    if not infos:
        raise SSRFError(f"No addresses resolved for {host}")

    resolved: list[str] = []
    for info in infos:
        addr = info[4][0]
        ip = ipaddress.ip_address(addr)
        if _is_blocked_ip(ip):
            raise SSRFError(f"Blocked resolved address {addr} for host {host}")
        resolved.append(addr)
    return resolved


def validate_url_for_ssrf(url: str) -> tuple[str, str, list[str]]:
    """Parse URL, require http(s), resolve host, validate IPs.

    Returns (scheme, hostname, resolved_ips).
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise SSRFError(f"Unsupported scheme: {scheme or '(none)'}")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFError("URL missing hostname")

    # Disallow credentials in URL (obscure phishing / SSRF tricks)
    if parsed.username or parsed.password:
        raise SSRFError("URLs with embedded credentials are not allowed")

    resolved = validate_hostname_resolved(hostname)
    return scheme, hostname, resolved


def is_obviously_blocked_target(url: str) -> bool:
    """Fast reject for literal private IPs / localhost without requiring DNS success."""
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return True
    if parsed.username or parsed.password:
        return True
    hostname = parsed.hostname
    if not hostname:
        return True
    host = hostname.strip("[]").lower()
    if host in {"localhost", "metadata.google.internal"}:
        return True
    try:
        literal = ipaddress.ip_address(host)
        return _is_blocked_ip(literal)
    except ValueError:
        return False
