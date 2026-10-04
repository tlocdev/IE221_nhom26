"""Brand / typosquatting detection with official-domain allowlist."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from rapidfuzz import fuzz

from app.config import get_settings


@dataclass
class BrandAnalysis:
    matched_brand: str | None
    brand_similarity: float
    on_official_domain: int
    brand_in_domain: int
    impersonation_likely: int
    severity: str  # none | low | high

    def to_dict(self) -> dict:
        return asdict(self)


def _load_brands() -> list[dict]:
    path: Path = get_settings().brands_path
    if not path.exists():
        return []
    return json.loads(path.read_text(encoding="utf-8"))


def analyze_brand(
    registrable_domain: str,
    hostname: str,
    *,
    has_login_form: int = 0,
    has_login_keyword: int = 0,
    has_password_signals: int = 0,
) -> BrandAnalysis:
    brands = _load_brands()
    host = hostname.lower()
    reg = registrable_domain.lower()
    # label without TLD for fuzzy match
    label = reg.rsplit(".", 1)[0] if "." in reg else reg
    # strip multi-part public suffixes roughly: take first label of domain part
    domain_core = label.split(".")[0] if label else reg

    best_brand = None
    best_score = 0.0
    on_official = 0
    brand_in_domain = 0

    for entry in brands:
        brand = entry.get("brand", "")
        keywords = [k.lower() for k in entry.get("keywords", [])]
        official = [d.lower() for d in entry.get("official_domains", [])]

        if any(reg == o or host.endswith("." + o) or host == o for o in official):
            return BrandAnalysis(
                matched_brand=brand,
                brand_similarity=100.0,
                on_official_domain=1,
                brand_in_domain=1,
                impersonation_likely=0,
                severity="none",
            )

        for kw in keywords:
            if kw in host or kw in reg:
                brand_in_domain = 1
                score = float(fuzz.partial_ratio(kw, domain_core))
                if score > best_score:
                    best_score = score
                    best_brand = brand
            else:
                # typosquat fuzzy on domain core
                score = float(fuzz.ratio(kw, domain_core))
                # also leetspeak-ish: replace 0->o, 1->l
                normalized = domain_core.replace("0", "o").replace("1", "l").replace("3", "e")
                score = max(score, float(fuzz.ratio(kw, normalized)))
                if score >= 75 and score > best_score:
                    best_score = score
                    best_brand = brand
                    brand_in_domain = 1

    combo = brand_in_domain and not on_official and (
        has_login_form or has_login_keyword or has_password_signals
    )
    if combo and best_score >= 70:
        severity = "high"
        impersonation = 1
    elif brand_in_domain and not on_official and best_score >= 80:
        severity = "low"
        impersonation = 0
    else:
        severity = "none"
        impersonation = 0

    return BrandAnalysis(
        matched_brand=best_brand,
        brand_similarity=round(best_score, 2),
        on_official_domain=on_official,
        brand_in_domain=brand_in_domain,
        impersonation_likely=impersonation,
        severity=severity,
    )
