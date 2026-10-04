"""Nhãn tiếng Việt tự nhiên cho UI (giữ mã kỹ thuật trong DB/API)."""

SEVERITY_VI = {
    "low": "Thấp",
    "medium": "Trung bình",
    "high": "Cao",
    "critical": "Nghiêm trọng",
}

LEVEL_VI = {
    "low": "THẤP",
    "medium": "TRUNG BÌNH",
    "high": "CAO",
    "critical": "NGHIÊM TRỌNG",
}

STATUS_VI = {
    "pending": "Đang chờ",
    "scanning": "Đang quét",
    "completed": "Hoàn tất",
    "partial": "Thiếu một số dữ liệu",
    "failed": "Thất bại",
}

SOURCE_VI = {
    "heuristic": "Quy tắc",
    "threat_intel": "Danh sách đen",
    "ml": "Mô hình",
    "local": "Danh sách cục bộ",
    "seed_local": "Danh sách mẫu",
    "manual": "Thêm thủ công",
    "feed_url": "Feed URL (OpenPhish/URLhaus)",
    "feed_domain": "Feed tên miền (Phishing.Database)",
}

FINDING_TYPE_VI = {
    "new_domain": "Tên miền mới đăng ký",
    "young_domain": "Tên miền còn mới",
    "recent_domain": "Tên miền đăng ký gần đây",
    "suspicious_tld": "Đuôi miền đáng ngờ",
    "ip_in_url": "Dùng địa chỉ IP thay vì tên miền",
    "many_hyphens": "Nhiều dấu gạch ngang trong tên",
    "at_sign": "URL có ký tự @",
    "long_url": "URL dài bất thường",
    "sensitive_keywords": "Có từ khóa đăng nhập / xác minh",
    "no_https": "Chưa dùng HTTPS",
    "cert_expired": "Chứng chỉ bảo mật hết hạn",
    "tls_invalid": "Chứng chỉ bảo mật không hợp lệ",
    "hostname_mismatch": "Chứng chỉ không khớp tên miền",
    "password_on_young_domain": "Form mật khẩu trên tên miền mới",
    "password_form": "Trang có ô nhập mật khẩu",
    "credit_card_fields": "Có dấu hiệu thu thập thẻ",
    "urgency_language": "Nội dung thúc ép / đe dọa",
    "many_iframes": "Trang nhúng nhiều khung ngoài",
    "external_form": "Form gửi dữ liệu ra ngoài",
    "brand_impersonation": "Có dấu hiệu giả mạo thương hiệu",
    "brand_mention": "Tên miền nhắc đến thương hiệu",
    "redirects": "Nhiều lần chuyển hướng",
    "blacklist_hit": "Nằm trong danh sách đen",
}


def severity_vi(value: str | None) -> str:
    if not value:
        return "—"
    return SEVERITY_VI.get(value.lower(), value)


def level_vi(value: str | None) -> str:
    if not value:
        return "—"
    return LEVEL_VI.get(value.lower(), value.upper())


def status_vi(value: str | None) -> str:
    if not value:
        return "—"
    return STATUS_VI.get(value.lower(), value)


def source_vi(value: str | None) -> str:
    if not value:
        return "—"
    return SOURCE_VI.get(value.lower(), value)


def finding_type_vi(value: str | None) -> str:
    if not value:
        return "—"
    return FINDING_TYPE_VI.get(value, value)
