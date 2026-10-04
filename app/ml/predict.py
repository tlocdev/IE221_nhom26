"""Load versioned ML artifact and predict phishing probability."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from app.config import get_settings
from app.features.extractor import FeatureExtractor
from app.features.schema import schema_dict


class ModelPredictor:
    def __init__(self, artifacts_dir: Path | None = None) -> None:
        settings = get_settings()
        self.artifacts_dir = artifacts_dir or settings.artifacts_dir
        self.model = None
        self.metadata: dict[str, Any] = {}
        self.feature_columns: list[str] = []
        self._load()

    def _load(self) -> None:
        model_path = self.artifacts_dir / "model.joblib"
        meta_path = self.artifacts_dir / "metadata.json"
        schema_path = self.artifacts_dir / "feature_schema.json"
        if not model_path.exists():
            return
        self.model = joblib.load(model_path)
        if meta_path.exists():
            self.metadata = json.loads(meta_path.read_text(encoding="utf-8"))
        if schema_path.exists():
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            self.feature_columns = schema.get("columns", [])
        else:
            self.feature_columns = schema_dict()["columns"]

    @property
    def available(self) -> bool:
        return self.model is not None

    @property
    def model_version(self) -> str | None:
        return self.metadata.get("model_version")

    def predict_proba(self, features: dict) -> float | None:
        """Return ML phishing probability in [0, 1], or None if model missing."""
        if not self.available:
            return None
        extractor = FeatureExtractor()
        # Reorder / validate
        vector = extractor.vector(features)
        X = np.array([vector], dtype=float)
        proba = self.model.predict_proba(X)[0]
        # Assume class 1 = phishing
        classes = list(getattr(self.model, "classes_", [0, 1]))
        if 1 in classes:
            return float(proba[classes.index(1)])
        return float(proba[-1])
