"""Domain age / registration via RDAP (preferred) with WHOIS fallback.

Never coerces unknown age to 0 — use domain_age_days=None and domain_age_known=0.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
import tldextract

from app.config import get_settings


@dataclass
class DomainAnalysis:
    registrable_domain: str
    domain_age_days: int | None
    domain_age_known: int
    registrar: str | None
    created_at: str | None
    source: str | None  # rdap | whois | None
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_domain(hostname_or_url: str) -> DomainAnalysis:
    extracted = tldextract.extract(hostname_or_url)
    registrable = (
        f"{extracted.domain}.{extracted.suffix}"
        if extracted.domain and extracted.suffix
        else hostname_or_url.lower()
    ).lower()

    settings = get_settings()
    timeout = httpx.Timeout(settings.connect_timeout + settings.read_timeout)

    # --- RDAP ---
    try:
        rdap = _query_rdap(registrable, timeout)
        if rdap is not None:
            return rdap
    except Exception as exc:  # noqa: BLE001 — fallback path
        rdap_error = str(exc)
    else:
        rdap_error = "RDAP returned no data"

    # --- WHOIS fallback ---
    try:
        return _query_whois(registrable)
    except Exception as exc:  # noqa: BLE001
        return DomainAnalysis(
            registrable_domain=registrable,
            domain_age_days=None,
            domain_age_known=0,
            registrar=None,
            created_at=None,
            source=None,
            error=f"RDAP: {rdap_error}; WHOIS: {exc}",
        )


def _query_rdap(domain: str, timeout: httpx.Timeout) -> DomainAnalysis | None:
    # Bootstrap via rdap.org redirector
    url = f"https://rdap.org/domain/{domain}"
    with httpx.Client(timeout=timeout, follow_redirects=True) as client:
        resp = client.get(url, headers={"Accept": "application/rdap+json, application/json"})
        if resp.status_code != 200:
            return None
        data = resp.json()

    created = _rdap_event_date(data, "registration")
    age_days, known, created_iso = _age_from_datetime(created)
    registrar = _rdap_registrar(data)

    return DomainAnalysis(
        registrable_domain=domain,
        domain_age_days=age_days,
        domain_age_known=known,
        registrar=registrar,
        created_at=created_iso,
        source="rdap",
        error=None if known else "registration date missing in RDAP",
    )


def _rdap_event_date(data: dict[str, Any], action: str) -> datetime | None:
    for event in data.get("events") or []:
        if event.get("eventAction") == action and event.get("eventDate"):
            return _parse_dt(event["eventDate"])
    return None


def _rdap_registrar(data: dict[str, Any]) -> str | None:
    for entity in data.get("entities") or []:
        roles = entity.get("roles") or []
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if isinstance(item, list) and item and item[0] == "fn":
                        return str(item[-1])
            return entity.get("handle")
    return None


def _query_whois(domain: str) -> DomainAnalysis:
    import whois  # lazy import

    w = whois.whois(domain)
    created = w.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    if isinstance(created, datetime):
        dt = created if created.tzinfo else created.replace(tzinfo=timezone.utc)
    else:
        dt = _parse_dt(str(created)) if created else None

    age_days, known, created_iso = _age_from_datetime(dt)
    registrar = w.registrar if isinstance(w.registrar, str) else None

    return DomainAnalysis(
        registrable_domain=domain,
        domain_age_days=age_days,
        domain_age_known=known,
        registrar=registrar,
        created_at=created_iso,
        source="whois",
        error=None if known else "creation date missing in WHOIS",
    )


def _parse_dt(value: str) -> datetime | None:
    value = value.strip()
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ):
        try:
            dt = datetime.strptime(value.replace("+00:00", "Z"), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _age_from_datetime(dt: datetime | None) -> tuple[int | None, int, str | None]:
    if dt is None:
        return None, 0, None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    age = max(0, (now - dt).days)
    return age, 1, dt.isoformat()
