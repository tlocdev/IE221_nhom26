"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import scan_router
from app.config import get_settings
from app.models.db import init_db
from app.web.routes import web_router

settings = get_settings()
logger = logging.getLogger("scam_detector")


def _sync_blacklist_background() -> None:
    try:
        from app.scanners.blacklist_feeds import sync_feeds

        meta = sync_feeds(force=False)
        if meta.get("skipped"):
            logger.info("Blacklist sync skipped: %s", meta.get("reason"))
        else:
            logger.info(
                "Blacklist synced: %s URLs, %s domains",
                meta.get("url_count"),
                meta.get("domain_count"),
            )
    except Exception:  # noqa: BLE001
        logger.exception("Blacklist sync failed")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    url = settings.database_url
    if url.startswith("sqlite:///"):
        db_path = url.removeprefix("sqlite:///")
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    init_db()

    if settings.blacklist_sync_on_startup:
        thread = threading.Thread(
            target=_sync_blacklist_background,
            name="blacklist-sync",
            daemon=True,
        )
        thread.start()

    yield


app = FastAPI(
    title=settings.app_name,
    description=(
        "Phân tích website theo dấu hiệu lừa đảo và trả về điểm rủi ro có giải thích "
        "(không phải phán quyết tuyệt đối)."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

static_dir = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(scan_router)
app.include_router(web_router)


@app.get("/health")
def health() -> dict:
    from app.scanners.blacklist_feeds import feed_stats

    return {
        "status": "ok",
        "app": settings.app_name,
        "blacklist": feed_stats(),
    }
