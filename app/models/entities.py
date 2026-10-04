"""SQLAlchemy models."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_url: Mapped[str] = mapped_column(Text, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    ml_probability: Mapped[float | None] = mapped_column(Float, nullable=True)
    rule_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    model_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)

    features_row: Mapped[ScanFeatures | None] = relationship(back_populates="scan", uselist=False)
    findings: Mapped[list[ScanFinding]] = relationship(back_populates="scan")


class ScanFeatures(Base):
    __tablename__ = "scan_features"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True)
    schema_version: Mapped[str] = mapped_column(String(16), default="1")
    features: Mapped[dict] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="features_row")


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    type: Mapped[str] = mapped_column(String(64))
    severity: Mapped[str] = mapped_column(String(16))
    description: Mapped[str] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(32), default="heuristic")

    scan: Mapped[Scan] = relationship(back_populates="findings")


class BlacklistEntry(Base):
    __tablename__ = "blacklist_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    source: Mapped[str] = mapped_column(String(64), default="local")
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
