# Machine Learning

## Pipeline

```text
Dataset → normalize URL → drop duplicates
       → group by registrable domain
       → domain-aware train/test split
       → FeatureExtractor (shared with runtime)
       → Logistic Regression / Decision Tree / Random Forest [/ XGBoost]
       → phishing-oriented metrics
       → select model (default `--model auto`: lowest test FNR, tie-break higher phishing F1)
       → save selected model artifact + comparison metrics
```

The currently deployed model is **XGBoost** (auto-selected). The chosen model and the reason are recorded in `artifacts/phishing_model_v1/metadata.json` (`model_name`, `selection_rationale`). Use `--model <Name>` to force a specific model.

If timestamps exist, prefer **time-aware** split (old → train, new → test) via `app.ml.splitting.time_aware_split`.

## Why not random URL split?

URLs sharing a domain (e.g. `/a`, `/b`, `/c` on the same host) would leak identity into both train and test under a random split, inflating metrics.

## Metrics that matter

Report precision / recall / F1 **for the phishing class**, plus false-negative rate. A phishing site predicted as safe is more costly than a false positive.

## What is excluded from ML features

Threat-intelligence blacklist hits are **not** features. They are consumed only by the Risk Engine.

## Runtime wording

UI/API field: `ml_phishing_probability`  
Do **not** call the model's `predict_proba` output “confidence”. Optional future work: probability calibration.
