"""Feature schema helpers."""

from __future__ import annotations

from app.features.definitions import FEATURE_COLUMNS, FEATURE_SCHEMA_VERSION


def schema_dict() -> dict:
    return {
        "feature_schema_version": FEATURE_SCHEMA_VERSION,
        "columns": FEATURE_COLUMNS,
    }


def validate_feature_vector(features: dict) -> list[float]:
    missing = [c for c in FEATURE_COLUMNS if c not in features]
    if missing:
        raise KeyError(f"Missing features: {missing}")
    return [float(features[c]) for c in FEATURE_COLUMNS]
