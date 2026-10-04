# Architecture

## Evidence model

Three independent evidence sources are combined by the Risk Engine:

1. **Heuristic / rule score** — weighted findings from URL, domain age, TLS, HTML, brand combo signals.
2. **ML phishing probability** — `predict_proba` from the model auto-selected at training time, currently XGBoost (not labeled “confidence”).
3. **Threat intelligence** — local blacklist / feeds. Hits go straight to the Risk Engine and are **not** ML features (avoids label leakage when feeds also label training data).

Final **risk score** is a composite risk index in 0–100. It is **not** P(site is phishing).

## Overlap handling

Signals such as young domain age appear in both rules and ML features. The Risk Engine documents this and slightly damps ML weight when both rule score and ML probability are already elevated, instead of naively treating them as independent.

Threat-intel hits apply a high floor (default ≥ 85).

## Feature parity

`app/features/extractor.py` is imported by:

- runtime `ScanService`
- `scripts/train_model.py`

Artifacts live under `artifacts/phishing_model_v1/` with `model.joblib`, `feature_schema.json`, `metadata.json`, `metrics.json`. The actual model type is in `metadata.json` → `model_name`.

## Scan status

`pending` → `scanning` → `completed` | `partial` | `failed`

`partial` is used when some analyzers fail (e.g. WHOIS) but enough signals remain for a score.

## Persistence

- `scans` — status, scores, `ml_probability`, `model_version`
- `scan_features` — JSONB/JSON blob + `schema_version`
- `scan_findings` — explainable findings with `source`
- `blacklist_entries` — optional DB mirror; file-based blacklist used at runtime for TI
