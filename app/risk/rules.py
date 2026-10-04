"""Heuristic rule engine — produces rule_score + findings (not final risk)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    type: str
    severity: str  # low | medium | high
    description: str
    source: str = "heuristic"
    points: int = 0

    def to_dict(self) -> dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "description": self.description,
            "source": self.source,
            "points": self.points,
        }


@dataclass
class RuleResult:
    rule_score: int
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule_score": self.rule_score,
            "findings": [f.to_dict() for f in self.findings],
        }


def evaluate_rules(features: dict[str, Any], meta: dict[str, Any] | None = None) -> RuleResult:
    """Score heuristics. Blacklist is NOT applied here — threat intel is separate."""
    meta = meta or {}
    findings: list[Finding] = []
    score = 0

    def add(points: int, ftype: str, severity: str, desc: str) -> None:
        nonlocal score
        score += points
        findings.append(Finding(ftype, severity, desc, points=points))

    age = features.get("domain_age_days", -1)
    known = features.get("domain_age_known", 0)
    if known and age >= 0:
        if age < 7:
            add(30, "new_domain", "high", f"Domain được đăng ký khoảng {int(age)} ngày trước.")
        elif age < 30:
            add(20, "young_domain", "high", f"Domain mới chỉ khoảng {int(age)} ngày tuổi.")
        elif age < 180:
            add(10, "recent_domain", "medium", f"Domain dưới 6 tháng tuổi ({int(age)} ngày).")

    if features.get("suspicious_tld"):
        add(10, "suspicious_tld", "medium", "URL dùng TLD thường xuất hiện trong chiến dịch lừa đảo.")

    if features.get("has_ip_address"):
        add(25, "ip_in_url", "high", "URL dùng địa chỉ IP thô thay vì tên miền.")

    if features.get("num_hyphens", 0) >= 3:
        add(10, "many_hyphens", "medium", "Hostname chứa nhiều dấu gạch ngang.")

    if features.get("num_at_signs", 0) > 0:
        add(20, "at_sign", "high", "URL chứa ký tự '@' — có thể che host thật.")

    if features.get("url_length", 0) > 75:
        add(8, "long_url", "low", "URL dài bất thường.")

    if features.get("has_login_keyword") or features.get("has_verify_keyword"):
        add(8, "sensitive_keywords", "medium", "URL chứa từ khóa kiểu đăng nhập / xác minh.")

    if not features.get("has_https"):
        add(
            5,
            "no_https",
            "low",
            "Website dùng HTTP (không chứng minh lừa đảo, nhưng bảo mật truyền tải yếu hơn).",
        )

    if features.get("cert_expired"):
        add(15, "cert_expired", "high", "Chứng chỉ TLS có vẻ đã hết hạn.")
    elif features.get("has_https") and not features.get("tls_ok"):
        add(18, "tls_invalid", "high", "Xác thực chứng chỉ TLS thất bại.")
    elif features.get("has_https") and not features.get("hostname_match"):
        add(
            20,
            "hostname_mismatch",
            "high",
            "Hostname trên chứng chỉ không khớp (kiểm tra SAN/hostname thất bại).",
        )

    if features.get("password_input_count", 0) > 0:
        pts = 10
        if known and age is not None and 0 <= age < 30:
            pts = 15
            add(pts, "password_on_young_domain", "high", "Có form mật khẩu trên domain mới đăng ký.")
        else:
            add(pts, "password_form", "medium", "Trang có ô nhập mật khẩu.")

    if features.get("credit_card_field_count", 0) > 0:
        add(15, "credit_card_fields", "high", "Trang có dấu hiệu thu thập thông tin thẻ tín dụng.")

    if features.get("suspicious_word_count", 0) >= 3:
        add(10, "urgency_language", "medium", "Nội dung dùng ngôn ngữ thúc ép / đe dọa tài khoản.")

    if features.get("iframe_count", 0) >= 3:
        add(8, "many_iframes", "low", "Trang nhúng nhiều iframe.")

    if features.get("external_form_action"):
        add(12, "external_form", "high", "Form gửi dữ liệu sang domain khác.")

    if features.get("impersonation_likely"):
        brand = meta.get("matched_brand") or "một thương hiệu quen thuộc"
        add(
            20,
            "brand_impersonation",
            "high",
            f"Domain có vẻ giả mạo {brand} và không nằm trong danh sách domain chính thức.",
        )
    elif features.get("brand_in_domain") and features.get("brand_similarity", 0) >= 80:
        brand = meta.get("matched_brand") or "một thương hiệu quen thuộc"
        add(
            5,
            "brand_mention",
            "low",
            f"Domain nhắc đến {brand} nhưng chưa có đủ tín hiệu lừa đảo mạnh.",
        )

    if features.get("redirect_count", 0) >= 2:
        add(
            8,
            "redirects",
            "medium",
            f"Trang chuyển hướng {features['redirect_count']} lần trước khi hiển thị nội dung.",
        )

    score = max(0, min(100, score))
    return RuleResult(rule_score=score, findings=findings)
