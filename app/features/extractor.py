"""Single FeatureExtractor used by both training and runtime."""

from __future__ import annotations

from typing import Any

from app.features.definitions import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION
from app.features.schema import validate_feature_vector
from app.scanners.brand_detector import BrandAnalysis
from app.scanners.domain_analyzer import DomainAnalysis
from app.scanners.html_analyzer import HtmlAnalysis
from app.scanners.ssl_analyzer import SslAnalysis
from app.scanners.url_analyzer import UrlAnalysis, analyze_url


class FeatureExtractor:
    """Build the schema-v1 feature dict from scanner outputs or URL-only (train)."""

    schema_version = FEATURE_SCHEMA_VERSION

    def extract_from_scanners(
        self,
        url_info: UrlAnalysis,
        domain_info: DomainAnalysis | None = None,
        ssl_info: SslAnalysis | None = None,
        html_info: HtmlAnalysis | None = None,
        brand_info: BrandAnalysis | None = None,
        redirect_count: int = 0,
    ) -> dict[str, float | int]:
        domain_age_days: float
        domain_age_known = 0
        if domain_info and domain_info.domain_age_known and domain_info.domain_age_days is not None:
            domain_age_days = float(domain_info.domain_age_days)
            domain_age_known = 1
        else:
            # Sentinel for ML only — never treat as "0 days old" in heuristics
            domain_age_days = -1.0

        ssl = ssl_info
        html = html_info
        brand = brand_info

        features: dict[str, float | int] = {
            "url_length": url_info.url_length,
            "domain_length": url_info.domain_length,
            "num_subdomains": url_info.num_subdomains,
            "has_https": url_info.has_https,
            "has_ip_address": url_info.has_ip_address,
            "num_digits": url_info.num_digits,
            "num_hyphens": url_info.num_hyphens,
            "num_at_signs": url_info.num_at_signs,
            "num_dots": url_info.num_dots,
            "has_login_keyword": url_info.has_login_keyword,
            "has_verify_keyword": url_info.has_verify_keyword,
            "suspicious_tld": url_info.suspicious_tld,
            "path_depth": url_info.path_depth,
            "query_length": url_info.query_length,
            "domain_age_days": domain_age_days,
            "domain_age_known": domain_age_known,
            "tls_ok": ssl.tls_ok if ssl else 0,
            "hostname_match": ssl.hostname_match if ssl else 0,
            "cert_expired": ssl.cert_expired if ssl else 0,
            "password_input_count": html.password_input_count if html else 0,
            "credit_card_field_count": html.credit_card_field_count if html else 0,
            "form_count": html.form_count if html else 0,
            "iframe_count": html.iframe_count if html else 0,
            "suspicious_word_count": html.suspicious_word_count if html else 0,
            "has_login_form": html.has_login_form if html else 0,
            "external_form_action": html.external_form_action if html else 0,
            "brand_similarity": brand.brand_similarity if brand else 0.0,
            "brand_in_domain": brand.brand_in_domain if brand else 0,
            "impersonation_likely": brand.impersonation_likely if brand else 0,
            "redirect_count": redirect_count,
        }
        # Ensure column order / completeness
        validate_feature_vector(features)
        return features

    def extract_url_only(self, url: str, extras: dict[str, Any] | None = None) -> dict[str, float | int]:
        """Used during offline training when only URL (+ optional columns) are available."""
        url_info = analyze_url(url)
        extras = extras or {}

        def _int(key: str, default: int = 0) -> int:
            val = extras.get(key, default)
            return default if val is None else int(val)

        def _opt_age():
            val = extras.get("domain_age_days")
            return None if val is None else float(val)

        domain = DomainAnalysis(
            registrable_domain=url_info.registrable_domain,
            domain_age_days=_opt_age(),
            domain_age_known=1 if extras.get("domain_age_days") is not None else 0,
            registrar=None,
            created_at=None,
            source=None,
        )
        ssl = SslAnalysis(
            has_https=url_info.has_https,
            tls_ok=_int("tls_ok", url_info.has_https),
            hostname_match=_int("hostname_match", url_info.has_https),
            cert_expired=_int("cert_expired", 0),
            days_until_expiry=None,
            issuer=None,
            subject_cn=None,
        )
        html = HtmlAnalysis(
            fetched=1 if extras else 0,
            password_input_count=_int("password_input_count", 0),
            text_input_count=0,
            email_input_count=0,
            credit_card_field_count=_int("credit_card_field_count", 0),
            form_count=_int("form_count", 0),
            iframe_count=_int("iframe_count", 0),
            suspicious_word_count=_int("suspicious_word_count", 0),
            has_login_form=_int("has_login_form", url_info.has_login_keyword),
            external_form_action=_int("external_form_action", 0),
        )
        from app.scanners.brand_detector import analyze_brand

        brand = analyze_brand(
            url_info.registrable_domain,
            url_info.hostname,
            has_login_form=html.has_login_form,
            has_login_keyword=url_info.has_login_keyword,
            has_password_signals=html.password_input_count,
        )
        return self.extract_from_scanners(
            url_info,
            domain,
            ssl,
            html,
            brand,
            redirect_count=_int("redirect_count", 0),
        )

    def vector(self, features: dict) -> list[float]:
        return validate_feature_vector(features)

    @property
    def columns(self) -> list[str]:
        return list(FEATURE_COLUMNS)
