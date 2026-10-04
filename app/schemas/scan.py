"""Pydantic API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class FindingOut(BaseModel):
    type: str
    severity: str
    description: str
    source: str = "heuristic"
    points: int = 0


class ScanResponse(BaseModel):
    id: int | None = None
    url: str
    normalized_url: str
    domain: str
    status: str
    risk_score: int | None = None
    risk_level: str | None = None
    rule_score: int | None = None
    ml_phishing_probability: float | None = None
    model_version: str | None = None
    threat_intel: dict[str, Any] | None = None
    findings: list[FindingOut] = []
    features: dict[str, Any] | None = None
    breakdown: dict[str, Any] | None = None
    disclaimer: str | None = None
    error_code: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None


class ScanListItem(BaseModel):
    id: int
    url: str
    domain: str
    status: str
    risk_score: int | None
    risk_level: str | None
    started_at: datetime | None
