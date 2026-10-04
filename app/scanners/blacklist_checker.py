"""Threat-intelligence blacklist lookup — NOT used as an ML feature.

Nguồn:
- Local seed: data/blacklist/entries.json
- Feed cache: OpenPhish + URLhaus + Phishing.Database (đồng bộ bằng scripts/sync_blacklist.py)
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlparse

from app.config import get_settings
from app.scanners.blacklist_feeds import domains_path, meta_path, urls_path


@dataclass
class ThreatIntelResult:
    hit: bool
    source: str | None
    matched_value: str | None
    severity: str  # none | high
    detected_at: str | None = None
    feed_stats: dict | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        return data


def clear_blacklist_cache() -> None:
    _load_index.cache_clear()


def _load_local_entries() -> list[dict]:
    path: Path = get_settings().blacklist_path
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return data.get("entries", [])
    return data


def _read_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
        if line.strip() and not line.startswith("#")
    }


@lru_cache(maxsize=1)
def _load_index() -> dict:
    local = _load_local_entries()
    local_urls: dict[str, dict] = {}
    local_domains: dict[str, dict] = {}
    for entry in local:
        e_url = (entry.get("url") or "").strip().lower().rstrip("/")
        e_domain = (entry.get("domain") or "").strip().lower()
        if e_url:
            local_urls[e_url] = entry
        if e_domain:
            local_domains[e_domain] = entry

    feed_urls = _read_lines(urls_path())
    feed_domains = _read_lines(domains_path())

    stats = {}
    if meta_path().exists():
        try:
            stats = json.loads(meta_path().read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            stats = {}

    return {
        "local_urls": local_urls,
        "local_domains": local_domains,
        "feed_urls": feed_urls,
        "feed_domains": feed_domains,
        "stats": stats,
    }


def check_blacklist(url: str, registrable_domain: str) -> ThreatIntelResult:
    index = _load_index()
    normalized = url.strip().lower().rstrip("/")
    domain = registrable_domain.lower()
    host = (urlparse(url).hostname or "").lower()
    stats_summary = {
        "synced_at": index["stats"].get("synced_at"),
        "url_count": index["stats"].get("url_count", len(index["feed_urls"])),
        "domain_count": index["stats"].get("domain_count", len(index["feed_domains"])),
    }

    # 1) Local seed / manual — ưu tiên
    local_urls: dict = index["local_urls"]
    if normalized in local_urls:
        entry = local_urls[normalized]
        return ThreatIntelResult(
            hit=True,
            source=entry.get("source") or "local",
            matched_value=normalized,
            severity="high",
            detected_at=entry.get("detected_at"),
            feed_stats=stats_summary,
        )
    for e_url, entry in local_urls.items():
        if normalized.startswith(e_url + "/"):
            return ThreatIntelResult(
                hit=True,
                source=entry.get("source") or "local",
                matched_value=e_url,
                severity="high",
                detected_at=entry.get("detected_at"),
                feed_stats=stats_summary,
            )

    local_domains: dict = index["local_domains"]
    for e_domain, entry in local_domains.items():
        if domain == e_domain or host == e_domain or host.endswith("." + e_domain):
            return ThreatIntelResult(
                hit=True,
                source=entry.get("source") or "local",
                matched_value=e_domain,
                severity="high",
                detected_at=entry.get("detected_at"),
                feed_stats=stats_summary,
            )

    # 2) Feed URLs — exact match only (tránh quét O(n) trên hàng trăm nghìn URL)
    feed_urls: set[str] = index["feed_urls"]
    if normalized in feed_urls:
        return ThreatIntelResult(
            hit=True,
            source="feed_url",
            matched_value=normalized,
            severity="high",
            detected_at=stats_summary.get("synced_at"),
            feed_stats=stats_summary,
        )

    # 3) Feed domains
    feed_domains: set[str] = index["feed_domains"]
    if domain in feed_domains or host in feed_domains:
        return ThreatIntelResult(
            hit=True,
            source="feed_domain",
            matched_value=domain if domain in feed_domains else host,
            severity="high",
            detected_at=stats_summary.get("synced_at"),
            feed_stats=stats_summary,
        )
    # subdomain of blacklisted registrable domain
    # e.g. login.evil.com when evil.com is listed
    parts = host.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in feed_domains:
            return ThreatIntelResult(
                hit=True,
                source="feed_domain",
                matched_value=candidate,
                severity="high",
                detected_at=stats_summary.get("synced_at"),
                feed_stats=stats_summary,
            )

    return ThreatIntelResult(
        hit=False,
        source=None,
        matched_value=None,
        severity="none",
        feed_stats=stats_summary,
    )


def add_blacklist_entry(
    url: str | None = None, domain: str | None = None, source: str = "manual"
) -> None:
    path = get_settings().blacklist_path
    path.parent.mkdir(parents=True, exist_ok=True)
    entries = _load_local_entries()
    entries.append(
        {
            "url": url,
            "domain": domain,
            "source": source,
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }
    )
    path.write_text(json.dumps({"entries": entries}, indent=2), encoding="utf-8")
    clear_blacklist_cache()
