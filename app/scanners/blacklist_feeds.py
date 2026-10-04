"""Đồng bộ danh sách đen từ các feed công khai.

Threat intelligence tách khỏi ML features (tránh data leakage).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import httpx
import tldextract

from app.config import get_settings

USER_AGENT = "WebsiteScamDetector/1.0 (academic; threat-intel sync)"


def _blacklist_dir() -> Path:
    path = get_settings().blacklist_dir
    path.mkdir(parents=True, exist_ok=True)
    return path


def meta_path() -> Path:
    return _blacklist_dir() / "feed_meta.json"


def urls_path() -> Path:
    return _blacklist_dir() / "feed_urls.txt"


def domains_path() -> Path:
    return _blacklist_dir() / "feed_domains.txt"


def registrable_domain(host_or_url: str) -> str | None:
    host = host_or_url
    if "://" in host_or_url:
        host = urlparse(host_or_url).hostname or ""
    host = host.strip("[]").lower().rstrip(".")
    if not host or host.startswith("#"):
        return None
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}".lower()
    return host or None


def _download_text(url: str, timeout: float) -> str:
    with httpx.Client(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return resp.text


def _parse_url_lines(text: str) -> tuple[set[str], set[str]]:
    urls: set[str] = set()
    domains: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # URLhaus sometimes prefixes with http already
        if not re.match(r"^https?://", line, re.I):
            if "/" in line or "." not in line:
                # might be domain-only
                dom = registrable_domain(line)
                if dom:
                    domains.add(dom)
                continue
            line = "http://" + line
        normalized = line.rstrip("/").lower()
        urls.add(normalized)
        dom = registrable_domain(normalized)
        if dom:
            domains.add(dom)
    return urls, domains


def _parse_domain_lines(text: str) -> set[str]:
    domains: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip().lower()
        if not line or line.startswith("#"):
            continue
        # strip accidental scheme/path
        if "://" in line:
            line = urlparse(line).hostname or line
        line = line.split("/")[0].strip("[]")
        dom = registrable_domain(line)
        if dom:
            domains.add(dom)
    return domains


def fetch_openphish(timeout: float) -> tuple[set[str], set[str], str | None]:
    settings = get_settings()
    try:
        text = _download_text(settings.feed_openphish_url, timeout)
        urls, domains = _parse_url_lines(text)
        return urls, domains, None
    except Exception as exc:  # noqa: BLE001
        return set(), set(), str(exc)


def fetch_urlhaus(timeout: float) -> tuple[set[str], set[str], str | None]:
    settings = get_settings()
    try:
        text = _download_text(settings.feed_urlhaus_url, timeout)
        urls, domains = _parse_url_lines(text)
        return urls, domains, None
    except Exception as exc:  # noqa: BLE001
        return set(), set(), str(exc)


def fetch_phishing_domains(timeout: float) -> tuple[set[str], set[str], str | None]:
    settings = get_settings()
    try:
        text = _download_text(settings.feed_phishing_domains_url, timeout)
        domains = _parse_domain_lines(text)
        return set(), domains, None
    except Exception as exc:  # noqa: BLE001
        return set(), set(), str(exc)


def sync_feeds(*, force: bool = False) -> dict:
    """Tải feed công khai và ghi cache local. Trả về metadata đồng bộ."""
    settings = get_settings()
    meta_file = meta_path()

    if not force and meta_file.exists():
        try:
            old = json.loads(meta_file.read_text(encoding="utf-8"))
            synced_at = old.get("synced_at")
            if synced_at:
                age_h = (
                    datetime.now(timezone.utc) - datetime.fromisoformat(synced_at)
                ).total_seconds() / 3600
                if age_h < settings.blacklist_sync_max_age_hours:
                    old["skipped"] = True
                    old["reason"] = f"cache còn mới ({age_h:.1f}h < {settings.blacklist_sync_max_age_hours}h)"
                    return old
        except Exception:  # noqa: BLE001
            pass

    timeout = settings.blacklist_feed_timeout
    all_urls: set[str] = set()
    all_domains: set[str] = set()
    sources: dict[str, dict] = {}

    for name, fetcher in (
        ("openphish", fetch_openphish),
        ("urlhaus", fetch_urlhaus),
        ("phishing_database", fetch_phishing_domains),
    ):
        urls, domains, err = fetcher(timeout)
        all_urls |= urls
        all_domains |= domains
        sources[name] = {
            "url_count": len(urls),
            "domain_count": len(domains),
            "error": err,
            "ok": err is None,
        }

    # Ghi file text (nhanh khi load, dễ debug)
    urls_path().write_text("\n".join(sorted(all_urls)) + ("\n" if all_urls else ""), encoding="utf-8")
    domains_path().write_text(
        "\n".join(sorted(all_domains)) + ("\n" if all_domains else ""), encoding="utf-8"
    )

    meta = {
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "url_count": len(all_urls),
        "domain_count": len(all_domains),
        "sources": sources,
        "skipped": False,
    }
    meta_file.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")

    # Invalidate in-memory index
    from app.scanners.blacklist_checker import clear_blacklist_cache

    clear_blacklist_cache()
    return meta


def feed_stats() -> dict:
    if not meta_path().exists():
        return {"synced": False, "url_count": 0, "domain_count": 0}
    try:
        return json.loads(meta_path().read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {"synced": False, "url_count": 0, "domain_count": 0}
