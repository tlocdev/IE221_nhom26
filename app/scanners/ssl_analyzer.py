"""TLS / certificate analysis using hostname (SAN) validation — not CN-centric."""

from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from urllib.parse import urlparse

import certifi


@dataclass
class SslAnalysis:
    has_https: int
    tls_ok: int
    hostname_match: int
    cert_expired: int
    days_until_expiry: int | None
    issuer: str | None
    subject_cn: str | None  # stored for diagnostics; UI uses hostname_match
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_ssl(url: str) -> SslAnalysis:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    hostname = parsed.hostname
    if not hostname:
        return SslAnalysis(
            has_https=0,
            tls_ok=0,
            hostname_match=0,
            cert_expired=0,
            days_until_expiry=None,
            issuer=None,
            subject_cn=None,
            error="missing hostname",
        )

    if parsed.scheme.lower() != "https":
        return SslAnalysis(
            has_https=0,
            tls_ok=0,
            hostname_match=0,
            cert_expired=0,
            days_until_expiry=None,
            issuer=None,
            subject_cn=None,
            error=None,
        )

    port = parsed.port or 443
    # Use Mozilla CA bundle (certifi) so Windows/Python local trust-store gaps
    # do not falsely flag publicly trusted certs as invalid.
    context = ssl.create_default_context(cafile=certifi.where())

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        # Handshake may still expose mismatch / expiry reasons
        reason = str(exc).lower()
        hostname_match = 0 if "hostname" in reason or "mismatch" in reason else 0
        expired = 1 if "expire" in reason else 0
        return SslAnalysis(
            has_https=1,
            tls_ok=0,
            hostname_match=hostname_match,
            cert_expired=expired,
            days_until_expiry=None,
            issuer=None,
            subject_cn=None,
            error=str(exc),
        )
    except OSError as exc:
        return SslAnalysis(
            has_https=1,
            tls_ok=0,
            hostname_match=0,
            cert_expired=0,
            days_until_expiry=None,
            issuer=None,
            subject_cn=None,
            error=str(exc),
        )

    # Successful verification ⇒ hostname matched (SAN/CN via OpenSSL match)
    not_after = cert.get("notAfter")
    days_left = None
    expired = 0
    if not_after:
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=timezone.utc
            )
            days_left = (exp - datetime.now(timezone.utc)).days
            expired = 1 if days_left < 0 else 0
        except ValueError:
            pass

    issuer = _name_value(cert.get("issuer"), "organizationName") or _name_value(
        cert.get("issuer"), "commonName"
    )
    subject_cn = _name_value(cert.get("subject"), "commonName")

    return SslAnalysis(
        has_https=1,
        tls_ok=1,
        hostname_match=1,
        cert_expired=expired,
        days_until_expiry=days_left,
        issuer=issuer,
        subject_cn=subject_cn,
        error=None,
    )


def _name_value(name_tuple, key: str) -> str | None:
    if not name_tuple:
        return None
    for rdn in name_tuple:
        for attr, value in rdn:
            if attr == key:
                return value
    return None
