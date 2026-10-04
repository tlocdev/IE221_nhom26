"""Jinja web UI routes."""

from __future__ import annotations

from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import BASE_DIR
from app.models.db import get_db
from app.models.entities import Scan
from app.risk.checklist import CHECK_DEFS
from app.risk.checklist import build_rule_checklist
from app.services.scan_service import ScanService
from app.web.i18n import (
    finding_type_vi,
    level_vi,
    severity_vi,
    source_vi,
    status_vi,
)

ANALYZE_STEPS = [
    "Chuẩn bị quét URL…",
    "Kiểm tra an toàn SSRF…",
    "Phân tích cấu trúc URL…",
    "Tra cứu domain / WHOIS…",
    "Kiểm tra chứng chỉ TLS…",
    "Tải và đọc HTML…",
    "Đối chiếu thương hiệu…",
    "Tra cứu danh sách đen…",
    "Chạy rule + mô hình ML…",
    "Tổng hợp điểm rủi ro…",
]

router = APIRouter(tags=["web"])
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))
templates.env.filters["severity_vi"] = severity_vi
templates.env.filters["level_vi"] = level_vi
templates.env.filters["status_vi"] = status_vi
templates.env.filters["source_vi"] = source_vi
templates.env.filters["finding_type_vi"] = finding_type_vi
_service = ScanService()


@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    recent = db.query(Scan).order_by(Scan.id.desc()).limit(5).all()
    return templates.TemplateResponse(
        request,
        "index.html",
        {"recent": recent},
    )


@router.post("/scan", response_class=HTMLResponse)
def scan_form(request: Request, url: str = Form(...), db: Session = Depends(get_db)):
    # Fallback không JS: vẫn chạy sync rồi redirect
    scan = _service.run_scan(db, url)
    return RedirectResponse(url=f"/scans/{scan.id}", status_code=303)


@router.get("/analyze", response_class=HTMLResponse)
def analyze_page(request: Request, url: str = Query(..., min_length=3)) -> HTMLResponse:
    raw = url.strip()
    display = raw
    if "://" not in display:
        display = "https://" + display
    host = urlparse(display).hostname or raw
    pending_rules = [
        {"id": cid, "label": label_ok} for cid, label_ok, _bad, _rel in CHECK_DEFS
    ]
    return templates.TemplateResponse(
        request,
        "analyze.html",
        {
            "target_url": raw,
            "display_host": host,
            "analyze_steps": ANALYZE_STEPS,
            "pending_rules": pending_rules,
        },
    )


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        return templates.TemplateResponse(
            request,
            "error.html",
            {"message": "Scan not found"},
            status_code=404,
        )
    data = _service.to_response_dict(scan)
    checklist = build_rule_checklist(
        data.get("features"),
        data.get("findings"),
        data.get("threat_intel"),
    )
    return templates.TemplateResponse(
        request,
        "result.html",
        {"scan": data, "rule_checklist": checklist},
    )


@router.get("/history", response_class=HTMLResponse)
def history(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    scans = db.query(Scan).order_by(Scan.id.desc()).limit(100).all()
    return templates.TemplateResponse(
        request,
        "history.html",
        {"scans": scans},
    )
