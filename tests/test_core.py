"""Unit tests: SSRF, feature extractor, domain-aware split."""

from __future__ import annotations

import ipaddress

import pandas as pd
import pytest

from app.core.ssrf import SSRFError, validate_hostname_resolved, validate_url_for_ssrf
from app.features.extractor import FeatureExtractor
from app.ml.splitting import domain_aware_split, registrable_domain
from app.risk.checklist import build_rule_checklist
from app.risk.engine import RiskEngine
from app.risk.rules import evaluate_rules
from app.scanners.blacklist_checker import ThreatIntelResult
from app.scanners.url_analyzer import analyze_url, normalize_url


def test_ssrf_blocks_localhost():
    with pytest.raises(SSRFError):
        validate_url_for_ssrf("http://127.0.0.1/")
    with pytest.raises(SSRFError):
        validate_url_for_ssrf("http://localhost/")
    from app.core.ssrf import is_obviously_blocked_target

    assert is_obviously_blocked_target("http://127.0.0.1/")
    assert is_obviously_blocked_target("http://192.168.0.1/")
    assert not is_obviously_blocked_target("http://secure-vietcombank-login.xyz/login")


def test_ssrf_blocks_private_ipv4():
    with pytest.raises(SSRFError):
        validate_url_for_ssrf("http://192.168.1.10/")
    with pytest.raises(SSRFError):
        validate_url_for_ssrf("http://10.0.0.5/")
    with pytest.raises(SSRFError):
        validate_url_for_ssrf("http://172.16.5.1/")


def test_ssrf_blocks_link_local_and_metadata():
    with pytest.raises(SSRFError):
        validate_url_for_ssrf("http://169.254.169.254/")


def test_ssrf_blocks_ipv6_loopback():
    with pytest.raises(SSRFError):
        validate_hostname_resolved("::1")


def test_ssrf_allows_public_literal():
    # 8.8.8.8 is public
    scheme, host, ips = validate_url_for_ssrf("https://8.8.8.8/")
    assert scheme == "https"
    assert host == "8.8.8.8"
    assert ips


def test_ssrf_rejects_credentials():
    with pytest.raises(SSRFError):
        validate_url_for_ssrf("https://user:pass@example.com/")


def test_normalize_url_defaults_to_https():
    assert normalize_url("tuyensinh.vaa.edu.vn").startswith("https://")
    assert normalize_url("http://example.com/a").startswith("http://")
    assert normalize_url("https://example.com/a").startswith("https://")


def test_url_analyzer_features():
    info = analyze_url("http://secure-paypal-login.xyz/account/verify?id=1")
    assert info.has_https == 0
    assert info.suspicious_tld == 1
    assert info.has_login_keyword == 1
    assert info.has_verify_keyword == 1


def test_feature_extractor_parity_columns():
    ext = FeatureExtractor()
    a = ext.extract_url_only("https://example.com/login")
    b = ext.extract_url_only("https://example.com/login")
    assert ext.vector(a) == ext.vector(b)
    assert list(a.keys()) == ext.columns


def test_domain_aware_split_no_domain_leakage():
    rows = []
    for i in range(10):
        rows.append({"url": f"https://alpha-unique-domain.test/page/{i}", "label": 1})
    for i in range(10):
        rows.append({"url": f"https://beta-unique-domain.test/page/{i}", "label": 0})
    for i in range(10):
        rows.append({"url": f"https://gamma-unique-domain.test/x/{i}", "label": 1})
    df = pd.DataFrame(rows)
    train, test = domain_aware_split(df, test_size=0.34, random_state=0)
    train_doms = {registrable_domain(u) for u in train["url"]}
    test_doms = {registrable_domain(u) for u in test["url"]}
    assert train_doms.isdisjoint(test_doms)


def test_unknown_domain_age_not_zero_in_features():
    ext = FeatureExtractor()
    feats = ext.extract_url_only("https://brand-new-unknown.example/")
    # unknown → sentinel -1 and known=0
    assert feats["domain_age_known"] == 0
    assert feats["domain_age_days"] == -1.0


def test_risk_engine_threat_intel_floor():
    feats = {
        "url_length": 20,
        "domain_length": 10,
        "num_subdomains": 0,
        "has_https": 1,
        "has_ip_address": 0,
        "num_digits": 0,
        "num_hyphens": 0,
        "num_at_signs": 0,
        "num_dots": 1,
        "has_login_keyword": 0,
        "has_verify_keyword": 0,
        "suspicious_tld": 0,
        "path_depth": 0,
        "query_length": 0,
        "domain_age_days": -1,
        "domain_age_known": 0,
        "tls_ok": 1,
        "hostname_match": 1,
        "cert_expired": 0,
        "password_input_count": 0,
        "credit_card_field_count": 0,
        "form_count": 0,
        "iframe_count": 0,
        "suspicious_word_count": 0,
        "has_login_form": 0,
        "external_form_action": 0,
        "brand_similarity": 0,
        "brand_in_domain": 0,
        "impersonation_likely": 0,
        "redirect_count": 0,
    }
    ti = ThreatIntelResult(hit=True, source="test", matched_value="x", severity="high")
    result = RiskEngine().evaluate(feats, ml_phishing_probability=0.2, threat_intel=ti)
    assert result.risk_score >= 85
    assert any(f.type == "blacklist_hit" for f in result.findings)


from app.risk.checklist import build_rule_checklist


def test_no_https_is_low_weight():
    feats = FeatureExtractor().extract_url_only("http://example.com/")
    rules = evaluate_rules(feats)
    https_findings = [f for f in rules.findings if f.type == "no_https"]
    assert https_findings
    assert https_findings[0].points <= 5
    assert "HTTP" in https_findings[0].description


def test_rule_checklist_marks_https_fail():
    items = build_rule_checklist(
        {"has_https": 0, "tls_ok": 0},
        [{"type": "no_https", "severity": "low"}],
        {"hit": False},
    )
    https = next(i for i in items if i["id"] == "https")
    assert https["ok"] is False
    bl = next(i for i in items if i["id"] == "blacklist")
    assert bl["ok"] is True


def test_rule_checklist_blacklist_from_ti():
    items = build_rule_checklist({}, [], {"hit": True})
    bl = next(i for i in items if i["id"] == "blacklist")
    assert bl["ok"] is False
