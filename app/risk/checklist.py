"""Checklist quy tắc cho sidebar UI (tick / cảnh báo)."""

from __future__ import annotations

from typing import Any


# id, nhãn khi đạt, nhãn khi vi phạm, nhóm finding types liên quan
CHECK_DEFS: list[tuple[str, str, str, set[str]]] = [
    (
        "https",
        "Đang dùng HTTPS",
        "Chưa dùng HTTPS",
        {"no_https"},
    ),
    (
        "tls",
        "Chứng chỉ bảo mật ổn",
        "Chứng chỉ bảo mật có vấn đề",
        {"cert_expired", "tls_invalid", "hostname_mismatch"},
    ),
    (
        "no_ip",
        "Không dùng IP thô trong URL",
        "URL dùng địa chỉ IP thô",
        {"ip_in_url"},
    ),
    (
        "domain_age",
        "Tuổi tên miền ổn / chưa rõ",
        "Tên miền còn mới",
        {"new_domain", "young_domain", "recent_domain"},
    ),
    (
        "tld",
        "Đuôi miền bình thường",
        "Đuôi miền đáng ngờ",
        {"suspicious_tld"},
    ),
    (
        "url_shape",
        "Cấu trúc URL ổn",
        "URL có dấu hiệu bất thường",
        {"many_hyphens", "at_sign", "long_url", "sensitive_keywords"},
    ),
    (
        "brand",
        "Không thấy giả mạo thương hiệu",
        "Có dấu hiệu giả mạo thương hiệu",
        {"brand_impersonation", "brand_mention"},
    ),
    (
        "password",
        "Không có form mật khẩu đáng ngờ",
        "Có form mật khẩu đáng ngờ",
        {"password_form", "password_on_young_domain"},
    ),
    (
        "payment",
        "Không thấy thu thập thẻ",
        "Có dấu hiệu thu thập thẻ",
        {"credit_card_fields"},
    ),
    (
        "content",
        "Nội dung không thúc ép",
        "Nội dung thúc ép / bất thường",
        {"urgency_language", "many_iframes", "external_form"},
    ),
    (
        "redirects",
        "Ít hoặc không chuyển hướng",
        "Nhiều lần chuyển hướng",
        {"redirects"},
    ),
    (
        "blacklist",
        "Không có trong danh sách đen",
        "Có trong danh sách đen",
        {"blacklist_hit"},
    ),
]


def build_rule_checklist(
    features: dict[str, Any] | None,
    findings: list[dict] | None,
    threat_intel: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Trả về danh sách {id, label, ok, severity} cho sidebar."""
    features = features or {}
    findings = findings or []
    threat_intel = threat_intel or {}

    fired: dict[str, str] = {}
    for f in findings:
        ftype = f.get("type") or ""
        sev = f.get("severity") or "medium"
        if ftype and ftype not in fired:
            fired[ftype] = sev

    # Bổ sung blacklist từ threat_intel nếu finding chưa có
    if threat_intel.get("hit") and "blacklist_hit" not in fired:
        fired["blacklist_hit"] = "high"

    items: list[dict[str, Any]] = []
    for cid, label_ok, label_bad, related in CHECK_DEFS:
        hit_types = [t for t in related if t in fired]
        ok = len(hit_types) == 0

        # HTTPS: nếu feature has_https=1 thì luôn ok (trừ khi TLS fail riêng)
        if cid == "https" and features.get("has_https") == 1:
            ok = True
        if cid == "tls":
            if features.get("has_https") == 1 and features.get("tls_ok") == 1:
                ok = True
            elif features.get("has_https") != 1:
                # Không HTTPS → không đánh TLS fail riêng ở đây
                ok = True
                label_ok = "Bỏ qua kiểm tra TLS (không HTTPS)"

        severity = "none"
        if not ok:
            severity = max(
                (fired[t] for t in hit_types),
                key=lambda s: {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0),
                default="medium",
            )

        items.append(
            {
                "id": cid,
                "label": label_ok if ok else label_bad,
                "ok": ok,
                "severity": severity,
            }
        )
    return items
