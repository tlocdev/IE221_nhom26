"""Application settings."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Website Scam Detector"
    debug: bool = True

    # Database — SQLite for local demo; set DATABASE_URL for PostgreSQL
    database_url: str = f"sqlite:///{BASE_DIR / 'data' / 'scans.db'}"

    # HTTP / crawl limits
    connect_timeout: float = 3.0
    read_timeout: float = 5.0
    max_redirects: int = 3
    max_html_bytes: int = 2 * 1024 * 1024  # 2 MB

    # Risk engine weights (heuristic + ML when no threat-intel hit)
    weight_rule: float = 0.55
    weight_ml: float = 0.45
    threat_intel_floor: int = 85

    # Paths
    brands_path: Path = BASE_DIR / "data" / "brands.json"
    suspicious_tlds_path: Path = BASE_DIR / "data" / "suspicious_tlds.txt"
    blacklist_path: Path = BASE_DIR / "data" / "blacklist" / "entries.json"
    blacklist_dir: Path = BASE_DIR / "data" / "blacklist"
    artifacts_dir: Path = BASE_DIR / "artifacts" / "phishing_model_v1"

    # Threat intel feeds (public, no API key)
    blacklist_sync_on_startup: bool = True
    blacklist_sync_max_age_hours: float = 24.0
    blacklist_feed_timeout: float = 25.0
    # OpenPhish community feed
    feed_openphish_url: str = "https://openphish.com/feed.txt"
    # URLhaus recent online malicious URLs
    feed_urlhaus_url: str = "https://urlhaus.abuse.ch/downloads/text_online/"
    # Phishing.Database — active phishing domains
    feed_phishing_domains_url: str = (
        "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/"
        "master/phishing-domains-ACTIVE.txt"
    )

    # Model
    model_version: str = "1.0"
    feature_schema_version: str = "1"


@lru_cache
def get_settings() -> Settings:
    return Settings()
