"""URL lexical / structural analysis."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

import tldextract

from app.config import get_settings

SUSPICIOUS_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "verify",
    "account",
    "secure",
    "update",
    "confirm",
    "password",
    "banking",
    "wallet",
    "otp",
    "dang-nhap",
    "xac-minh",
)


@dataclass
class UrlAnalysis:
    url: str
    normalized_url: str
    scheme: str
    hostname: str
    registrable_domain: str
    subdomain: str
    suffix: str
    url_length: int
    domain_length: int
    num_subdomains: int
    has_https: int
    has_ip_address: int
    num_digits: int
    num_hyphens: int
    num_at_signs: int
    num_dots: int
    has_login_keyword: int
    has_verify_keyword: int
    suspicious_tld: int
    path_depth: int
    query_length: int

    def to_dict(self) -> dict:
        return asdict(self)


def normalize_url(url: str) -> str:
    """Normalize URL. If scheme is omitted, prefer https:// (not http://)."""
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    # lowercase scheme + host; drop fragment
    host = (parsed.hostname or "").lower()
    netloc = host
    if parsed.port and parsed.port not in (80, 443):
        netloc = f"{host}:{parsed.port}"
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{parsed.scheme.lower()}://{netloc}{path}{query}"


def _load_suspicious_tlds() -> set[str]:
    path = get_settings().suspicious_tlds_path
    if not path.exists():
        return {"xyz", "top", "club", "work", "click", "link", "tk", "ml", "ga", "cf", "gq"}
    return {
        line.strip().lower().lstrip(".")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


def analyze_url(url: str) -> UrlAnalysis:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    extracted = tldextract.extract(normalized)
    hostname = (parsed.hostname or "").lower()
    registrable = (
        f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain and extracted.suffix
        else hostname
    )
    subdomain = extracted.subdomain or ""
    num_subdomains = len([p for p in subdomain.split(".") if p]) if subdomain else 0

    has_ip = 0
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        has_ip = 1
    except ValueError:
        has_ip = 0

    lower = normalized.lower()
    suspicious_tlds = _load_suspicious_tlds()
    suffix = (extracted.suffix or "").lower()

    return UrlAnalysis(
        url=url,
        normalized_url=normalized,
        scheme=parsed.scheme.lower(),
        hostname=hostname,
        registrable_domain=registrable.lower(),
        subdomain=subdomain.lower(),
        suffix=suffix,
        url_length=len(normalized),
        domain_length=len(hostname),
        num_subdomains=num_subdomains,
        has_https=1 if parsed.scheme.lower() == "https" else 0,
        has_ip_address=has_ip,
        num_digits=sum(c.isdigit() for c in hostname),
        num_hyphens=hostname.count("-"),
        num_at_signs=normalized.count("@"),
        num_dots=hostname.count("."),
        has_login_keyword=1 if any(k in lower for k in ("login", "signin", "sign-in", "dang-nhap")) else 0,
        has_verify_keyword=1 if any(k in lower for k in ("verify", "confirm", "xac-minh", "otp")) else 0,
        suspicious_tld=1 if suffix in suspicious_tlds or suffix.split(".")[-1] in suspicious_tlds else 0,
        path_depth=len([p for p in (parsed.path or "").split("/") if p]),
        query_length=len(parsed.query or ""),
    )
