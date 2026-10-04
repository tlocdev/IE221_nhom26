"""Orchestrates scanners → features → rules/ML/TI → risk → persistence."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.config import get_settings
from app.core.http_client import SafeHttpClient
from app.core.ssrf import SSRFError, is_obviously_blocked_target, validate_url_for_ssrf
from app.features.extractor import FeatureExtractor
from app.ml.predict import ModelPredictor
from app.models.entities import Scan, ScanFeatures, ScanFinding
from app.risk.engine import RiskEngine
from app.scanners.blacklist_checker import check_blacklist
from app.scanners.brand_detector import analyze_brand
from app.scanners.domain_analyzer import analyze_domain
from app.scanners.html_analyzer import analyze_html
from app.scanners.ssl_analyzer import analyze_ssl
from app.scanners.url_analyzer import analyze_url, normalize_url


def _user_forced_scheme(raw_url: str) -> bool:
    return bool(raw_url.strip().lower().startswith(("http://", "https://")))


class ScanService:
    def __init__(self) -> None:
        self.extractor = FeatureExtractor()
        self.risk_engine = RiskEngine()
        self.predictor = ModelPredictor()
        self.http = SafeHttpClient()
        self.settings = get_settings()

    def run_scan(self, db: Session, raw_url: str) -> Scan:
        normalized = normalize_url(raw_url)
        url_info = analyze_url(normalized)

        scan = Scan(
            url=raw_url,
            normalized_url=normalized,
            domain=url_info.registrable_domain,
            status="pending",
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        scan.status = "scanning"
        db.commit()

        partial = False
        error_code = None

        # Hard-block only obvious SSRF targets (localhost / private literals).
        # Unresolvable public hostnames still get URL/heuristic analysis (partial).
        if is_obviously_blocked_target(normalized):
            scan.status = "failed"
            scan.error_code = "ssrf_blocked"
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
            db.refresh(scan)
            return scan

        # Network fetch (HTML) with per-redirect SSRF
        fetch = None
        redirect_count = 0
        effective_url = normalized
        try:
            validate_url_for_ssrf(normalized)
            fetch = self.http.fetch(normalized, accept_html_only=True)
            # If https failed and user did not force a scheme, try http once
            if fetch.error and normalized.startswith("https://") and not _user_forced_scheme(raw_url):
                http_fallback = "http://" + normalized[len("https://") :]
                try:
                    validate_url_for_ssrf(http_fallback)
                    alt = self.http.fetch(http_fallback, accept_html_only=True)
                    if not alt.error or (alt.content and not fetch.content):
                        fetch = alt
                        effective_url = http_fallback
                        partial = True
                        error_code = error_code or "https_fallback_http"
                except SSRFError:
                    pass
            redirect_count = fetch.redirect_count if fetch else 0
            if fetch and fetch.final_url:
                effective_url = fetch.final_url
            if fetch and fetch.error:
                partial = True
        except SSRFError as exc:
            # Redirect into private space → hard fail; initial DNS miss → partial
            msg = str(exc).lower()
            if "blocked" in msg and ("address" in msg or "hostname" in msg or "resolved" in msg):
                if "resolution failed" not in msg and "no addresses" not in msg:
                    scan.status = "failed"
                    scan.error_code = "ssrf_blocked_redirect"
                    scan.completed_at = datetime.now(timezone.utc)
                    db.commit()
                    db.refresh(scan)
                    return scan
            partial = True
            error_code = "ssrf_or_dns"
        except Exception:  # noqa: BLE001
            partial = True
            error_code = "fetch_error"

        # Re-analyze from effective URL (scheme after redirect matters for HTTPS finding)
        url_info = analyze_url(effective_url)
        scan.normalized_url = url_info.normalized_url
        scan.domain = url_info.registrable_domain
        db.commit()

        # Domain
        try:
            domain_info = analyze_domain(url_info.registrable_domain)
            if domain_info.domain_age_known == 0:
                partial = True
        except Exception:  # noqa: BLE001
            from app.scanners.domain_analyzer import DomainAnalysis

            domain_info = DomainAnalysis(
                registrable_domain=url_info.registrable_domain,
                domain_age_days=None,
                domain_age_known=0,
                registrar=None,
                created_at=None,
                source=None,
                error="domain lookup failed",
            )
            partial = True

        # SSL — always prefer probing HTTPS for the host when possible
        ssl_target = url_info.normalized_url
        if not ssl_target.startswith("https://"):
            ssl_target = "https://" + ssl_target.split("://", 1)[-1]
        try:
            ssl_info = analyze_ssl(ssl_target)
            # If TLS is OK, treat site as having HTTPS even if crawl used http fallback
            if ssl_info.tls_ok:
                url_info.has_https = 1
        except Exception:  # noqa: BLE001
            from app.scanners.ssl_analyzer import SslAnalysis

            ssl_info = SslAnalysis(
                has_https=url_info.has_https,
                tls_ok=0,
                hostname_match=0,
                cert_expired=0,
                days_until_expiry=None,
                issuer=None,
                subject_cn=None,
                error="ssl analysis failed",
            )
            partial = True

        html_info = analyze_html(fetch, page_hostname=url_info.hostname)

        brand_info = analyze_brand(
            url_info.registrable_domain,
            url_info.hostname,
            has_login_form=html_info.has_login_form,
            has_login_keyword=url_info.has_login_keyword,
            has_password_signals=html_info.password_input_count,
        )

        threat_intel = check_blacklist(url_info.normalized_url, url_info.registrable_domain)

        features = self.extractor.extract_from_scanners(
            url_info,
            domain_info,
            ssl_info,
            html_info,
            brand_info,
            redirect_count=redirect_count,
        )

        ml_prob = self.predictor.predict_proba(features)
        risk = self.risk_engine.evaluate(
            features,
            ml_phishing_probability=ml_prob,
            threat_intel=threat_intel,
            meta={"matched_brand": brand_info.matched_brand},
        )

        scan.risk_score = risk.risk_score
        scan.risk_level = risk.risk_level
        scan.rule_score = risk.rule_score
        scan.ml_probability = risk.ml_phishing_probability
        scan.model_version = self.predictor.model_version or (
            self.settings.model_version if self.predictor.available else None
        )
        scan.status = "partial" if partial else "completed"
        scan.error_code = error_code
        scan.completed_at = datetime.now(timezone.utc)

        features_with_meta = dict(features)
        features_with_meta["_breakdown"] = risk.breakdown
        features_with_meta["_threat_intel"] = risk.threat_intel
        features_with_meta["_disclaimer"] = risk.disclaimer

        db.add(
            ScanFeatures(
                scan_id=scan.id,
                schema_version=self.extractor.schema_version,
                features=features_with_meta,
            )
        )
        for f in risk.findings:
            db.add(
                ScanFinding(
                    scan_id=scan.id,
                    type=f.type,
                    severity=f.severity,
                    description=f.description,
                    source=f.source,
                )
            )

        db.commit()
        db.refresh(scan)
        return scan

    def to_response_dict(self, scan: Scan) -> dict:
        raw_features = dict(scan.features_row.features) if scan.features_row else {}
        breakdown = raw_features.pop("_breakdown", None)
        threat_intel = raw_features.pop("_threat_intel", None)
        disclaimer = raw_features.pop("_disclaimer", None)

        return {
            "id": scan.id,
            "url": scan.url,
            "normalized_url": scan.normalized_url,
            "domain": scan.domain,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "rule_score": scan.rule_score,
            "ml_phishing_probability": scan.ml_probability,
            "model_version": scan.model_version,
            "threat_intel": threat_intel,
            "findings": [
                {
                    "type": f.type,
                    "severity": f.severity,
                    "description": f.description,
                    "source": f.source,
                    "points": 0,
                }
                for f in scan.findings
            ],
            "features": raw_features,
            "breakdown": breakdown,
            "disclaimer": disclaimer,
            "error_code": scan.error_code,
            "started_at": scan.started_at,
            "completed_at": scan.completed_at,
        }
