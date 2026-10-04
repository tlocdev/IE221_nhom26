"""REST API routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models.db import get_db
from app.models.entities import Scan
from app.schemas.scan import ScanListItem, ScanRequest, ScanResponse
from app.services.scan_service import ScanService

router = APIRouter(prefix="/api/v1", tags=["scan"])
_service = ScanService()


@router.post("/scan", response_model=ScanResponse)
def create_scan(body: ScanRequest, db: Session = Depends(get_db)) -> dict:
    scan = _service.run_scan(db, body.url)
    if scan.error_code in {"ssrf_blocked", "ssrf_blocked_redirect"}:
        raise HTTPException(status_code=400, detail="URL bị chặn bởi lớp bảo vệ SSRF")
    return _service.to_response_dict(scan)


@router.get("/scans", response_model=list[ScanListItem])
def list_scans(limit: int = 50, db: Session = Depends(get_db)) -> list[Scan]:
    return (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .limit(min(limit, 200))
        .all()
    )


@router.get("/scans/{scan_id}", response_model=ScanResponse)
def get_scan(scan_id: int, db: Session = Depends(get_db)) -> dict:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _service.to_response_dict(scan)


@router.get("/blacklist/status")
def blacklist_status() -> dict:
    from app.scanners.blacklist_feeds import feed_stats

    return feed_stats()


@router.post("/blacklist/sync")
def blacklist_sync(force: bool = False) -> dict:
    """Đồng bộ lại feed danh sách đen (OpenPhish, URLhaus, Phishing.Database)."""
    from app.scanners.blacklist_feeds import sync_feeds

    return sync_feeds(force=force)
