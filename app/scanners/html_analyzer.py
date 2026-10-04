"""HTML content analysis with size / type limits enforced by SafeHttpClient."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from bs4 import BeautifulSoup

from app.core.http_client import FetchResult

URGENCY_PATTERNS = [
    r"verify\s+your\s+account",
    r"account\s+(suspended|locked|limited)",
    r"confirm\s+(your\s+)?(password|identity)",
    r"update\s+(your\s+)?(payment|billing)",
    r"urgent",
    r"immediately",
    r"xác\s*minh",
    r"tài\s*khoản\s*(bị\s*)?(khóa|tạm\s*khóa)",
    r"đăng\s*nhập",
    r"mật\s*khẩu",
    r"otp",
    r"thẻ\s*tín\s*dụng",
    r"credit\s*card",
    r"password",
    r"ssn",
]


@dataclass
class HtmlAnalysis:
    fetched: int
    password_input_count: int
    text_input_count: int
    email_input_count: int
    credit_card_field_count: int
    form_count: int
    iframe_count: int
    suspicious_word_count: int
    has_login_form: int
    external_form_action: int
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def analyze_html(fetch: FetchResult | None, page_hostname: str | None = None) -> HtmlAnalysis:
    if fetch is None or fetch.error or not fetch.content:
        return HtmlAnalysis(
            fetched=0,
            password_input_count=0,
            text_input_count=0,
            email_input_count=0,
            credit_card_field_count=0,
            form_count=0,
            iframe_count=0,
            suspicious_word_count=0,
            has_login_form=0,
            external_form_action=0,
            error=fetch.error if fetch else "no fetch result",
        )

    try:
        html = fetch.content.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return HtmlAnalysis(
            fetched=0,
            password_input_count=0,
            text_input_count=0,
            email_input_count=0,
            credit_card_field_count=0,
            form_count=0,
            iframe_count=0,
            suspicious_word_count=0,
            has_login_form=0,
            external_form_action=0,
            error=str(exc),
        )

    soup = BeautifulSoup(html, "html.parser")
    password_inputs = soup.find_all("input", {"type": re.compile(r"password", re.I)})
    text_inputs = soup.find_all("input", {"type": re.compile(r"^(text|)$", re.I)})
    # also count inputs without type (default text)
    bare_inputs = [
        i
        for i in soup.find_all("input")
        if not i.get("type") or str(i.get("type")).lower() == "text"
    ]
    email_inputs = soup.find_all("input", {"type": re.compile(r"email", re.I)})
    forms = soup.find_all("form")
    iframes = soup.find_all("iframe")

    cc_fields = 0
    for inp in soup.find_all("input"):
        name = f"{inp.get('name', '')} {inp.get('id', '')} {inp.get('placeholder', '')}".lower()
        if any(k in name for k in ("card", "ccnum", "cvv", "cvc", "credit")):
            cc_fields += 1

    text_blob = soup.get_text(" ", strip=True).lower()
    suspicious = sum(1 for p in URGENCY_PATTERNS if re.search(p, text_blob, re.I))

    has_login = 1 if password_inputs and (bare_inputs or email_inputs or text_inputs) else 0

    external_action = 0
    if page_hostname:
        for form in forms:
            action = form.get("action") or ""
            if action.startswith("http") and page_hostname.lower() not in action.lower():
                external_action = 1
                break

    return HtmlAnalysis(
        fetched=1,
        password_input_count=len(password_inputs),
        text_input_count=len(bare_inputs),
        email_input_count=len(email_inputs),
        credit_card_field_count=cc_fields,
        form_count=len(forms),
        iframe_count=len(iframes),
        suspicious_word_count=suspicious,
        has_login_form=has_login,
        external_form_action=external_action,
        error=None,
    )
