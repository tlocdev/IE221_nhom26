"""
Train phishing models with domain-aware split.

Uses the SAME FeatureExtractor as runtime to avoid training-serving skew.
Blacklist / threat-intel flags are NEVER included as ML features.

Examples:
  # Dataset synthetic (mặc định nếu không có PhiUSIIL)
  python scripts/train_model.py

  # PhiUSIIL (UCI) — đặt file vào data/datasets/
  python scripts/train_model.py --dataset data/datasets/PhiUSIIL_Phishing_URL_Dataset.csv

  # Lấy mẫu nhanh hơn (khuyến nghị lần đầu)
  python scripts/train_model.py --dataset data/datasets/PhiUSIIL_Phishing_URL_Dataset.csv --max-rows 40000
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.features.extractor import FeatureExtractor  # noqa: E402
from app.features.schema import schema_dict  # noqa: E402
from app.ml.splitting import domain_aware_split  # noqa: E402

DEFAULT_SAMPLE = ROOT / "data" / "datasets" / "urls_sample.csv"
DEFAULT_PHIUSIIL = ROOT / "data" / "datasets" / "PhiUSIIL_Phishing_URL_Dataset.csv"
ARTIFACT_DIR = ROOT / "artifacts" / "phishing_model_v1"


def ensure_sample_dataset() -> Path:
    """Create a synthetic labeled URL set if missing."""
    DEFAULT_SAMPLE.parent.mkdir(parents=True, exist_ok=True)
    if DEFAULT_SAMPLE.exists():
        return DEFAULT_SAMPLE

    rows: list[dict] = []
    legit = [
        ("https://google.com/", 0, 9000),
        ("https://www.facebook.com/login", 0, 8000),
        ("https://microsoft.com/", 0, 10000),
        ("https://apple.com/", 0, 11000),
        ("https://vietcombank.com.vn/", 0, 5000),
        ("https://www.bidv.com.vn/", 0, 4500),
        ("https://momo.vn/", 0, 3000),
        ("https://github.com/login", 0, 4000),
        ("https://wikipedia.org/wiki/Phishing", 0, 7000),
        ("https://stackoverflow.com/questions", 0, 5000),
        ("https://vnexpress.net/", 0, 6000),
        ("https://shopee.vn/", 0, 3500),
        ("https://lazada.vn/", 0, 3200),
        ("https://edu.example-university.edu.vn/", 0, 2000),
        ("http://old-campus.example.edu/", 0, 2500),
    ]
    for url, label, age in legit:
        rows.append(
            {
                "url": url,
                "label": label,
                "domain_age_days": age,
                "tls_ok": 1 if url.startswith("https") else 0,
                "hostname_match": 1 if url.startswith("https") else 0,
                "password_input_count": 1 if "login" in url else 0,
                "has_login_form": 1 if "login" in url else 0,
            }
        )

    phish_templates = [
        "http://secure-{brand}-login.{tld}/account/verify",
        "https://{brand}-support-{n}.xyz/signin",
        "http://{brand}0-security.{tld}/update",
        "https://login-{brand}-confirm.{tld}/otp",
        "http://{brand}-locked-account.{tld}/restore",
    ]
    brands = ["paypal", "vietcombank", "facebook", "apple", "microsoft", "momo", "bidv"]
    tlds = ["xyz", "top", "tk", "club", "click"]
    n = 0
    for brand in brands:
        for tld in tlds:
            for tmpl in phish_templates:
                n += 1
                url = tmpl.format(brand=brand, tld=tld, n=n)
                rows.append(
                    {
                        "url": url,
                        "label": 1,
                        "domain_age_days": n % 25,
                        "tls_ok": 1 if url.startswith("https") else 0,
                        "hostname_match": 1 if url.startswith("https") else 0,
                        "password_input_count": 1,
                        "has_login_form": 1,
                        "suspicious_word_count": 3,
                        "iframe_count": n % 4,
                    }
                )

    for i in range(20):
        rows.append(
            {
                "url": f"https://paypa1-alert-{i}.icu/verify?id={i}",
                "label": 1,
                "domain_age_days": i % 10,
                "tls_ok": 1,
                "hostname_match": 1,
                "password_input_count": 1,
                "has_login_form": 1,
            }
        )
        rows.append(
            {
                "url": f"https://news-portal-{i}.example.com/article/{i}",
                "label": 0,
                "domain_age_days": 1000 + i,
                "tls_ok": 1,
                "hostname_match": 1,
                "password_input_count": 0,
                "has_login_form": 0,
            }
        )

    pd.DataFrame(rows).to_csv(DEFAULT_SAMPLE, index=False)
    return DEFAULT_SAMPLE


def is_phiusiil(df: pd.DataFrame) -> bool:
    cols = {c.lower() for c in df.columns}
    return "urllength" in cols and "label" in cols and ("ishttps" in cols or "ishttps" in cols)


def _col(df: pd.DataFrame, *names: str):
    lower_map = {c.lower(): c for c in df.columns}
    for name in names:
        if name.lower() in lower_map:
            return lower_map[name.lower()]
    return None


def prepare_phiusiil(df: pd.DataFrame) -> pd.DataFrame:
    """Chuẩn hóa PhiUSIIL → schema nội bộ.

    PhiUSIIL: label 1 = legitimate, 0 = phishing
    Hệ thống này: label 1 = phishing, 0 = safe
    """
    url_c = _col(df, "URL")
    label_c = _col(df, "label")
    if not url_c or not label_c:
        raise ValueError("PhiUSIIL CSV thiếu cột URL hoặc label")

    out = pd.DataFrame()
    out["url"] = df[url_c].astype(str)
    # Đảo nhãn
    out["label"] = (1 - df[label_c].astype(int)).astype(int)

    https_c = _col(df, "IsHTTPS")
    out["tls_ok"] = df[https_c].astype(int) if https_c else 0
    # PhiUSIIL không có kết quả verify SAN/hostname thật.
    # Không gán hostname_match = IsHTTPS (hai khái niệm khác nhau).
    # FeatureExtractor sẽ fallback hostname_match theo scheme URL khi thiếu cột này.

    ip_c = _col(df, "IsDomainIP")
    # has_ip sẽ được FeatureExtractor lấy từ URL; giữ thêm nếu cần

    pwd_c = _col(df, "HasPasswordField")
    out["password_input_count"] = df[pwd_c].astype(int) if pwd_c else 0
    out["has_login_form"] = out["password_input_count"]

    pay_c = _col(df, "Pay")
    bank_c = _col(df, "Bank")
    crypto_c = _col(df, "Crypto")
    pay = df[pay_c].astype(int) if pay_c else 0
    bank = df[bank_c].astype(int) if bank_c else 0
    crypto = df[crypto_c].astype(int) if crypto_c else 0
    out["credit_card_field_count"] = (pay + bank + crypto).clip(upper=3)

    iframe_c = _col(df, "NoOfiFrame")
    out["iframe_count"] = df[iframe_c].astype(int) if iframe_c else 0

    submit_c = _col(df, "HasSubmitButton")
    out["form_count"] = df[submit_c].astype(int) if submit_c else 0

    ext_c = _col(df, "HasExternalFormSubmit")
    out["external_form_action"] = df[ext_c].astype(int) if ext_c else 0

    redir_c = _col(df, "NoOfURLRedirect")
    out["redirect_count"] = df[redir_c].astype(int) if redir_c else 0

    # Domain age không có trong PhiUSIIL
    out["domain_age_days"] = np.nan
    out["suspicious_word_count"] = (pay + bank + crypto).astype(int)
    out["cert_expired"] = 0

    out = out.dropna(subset=["url"]).drop_duplicates(subset=["url"]).reset_index(drop=True)
    return out


def prepare_internal(df: pd.DataFrame) -> pd.DataFrame:
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("CSV nội bộ cần cột url, label")
    out = df.copy()
    out["url"] = out["url"].astype(str)
    out["label"] = out["label"].astype(int)
    return out.drop_duplicates(subset=["url"]).reset_index(drop=True)


def load_dataset(path: Path) -> tuple[pd.DataFrame, str]:
    print(f"Reading {path} ...")
    df = pd.read_csv(path, low_memory=False)
    if is_phiusiil(df):
        print("Detected format: PhiUSIIL (UCI) — inverting labels (0 phishing -> 1)")
        return prepare_phiusiil(df), "phiusiil_v1"
    print("Detected format: internal sample schema")
    return prepare_internal(df), "urls_sample_v1"


def stratified_sample(df: pd.DataFrame, max_rows: int, seed: int = 42) -> pd.DataFrame:
    if max_rows <= 0 or len(df) <= max_rows:
        return df
    # Lấy theo tỷ lệ lớp
    parts = []
    for _label, g in df.groupby("label"):
        n = max(1, int(round(len(g) / len(df) * max_rows)))
        parts.append(g.sample(n=min(n, len(g)), random_state=seed))
    sampled = pd.concat(parts, ignore_index=True)
    if len(sampled) > max_rows:
        sampled = sampled.sample(n=max_rows, random_state=seed)
    return sampled.reset_index(drop=True)


def build_feature_matrix(df: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, list[str]]:
    extractor = FeatureExtractor()
    vectors = []
    total = len(df)
    optional_keys = (
        "domain_age_days",
        "tls_ok",
        "hostname_match",
        "cert_expired",
        "password_input_count",
        "credit_card_field_count",
        "form_count",
        "iframe_count",
        "suspicious_word_count",
        "has_login_form",
        "external_form_action",
        "redirect_count",
    )
    for i, (_, row) in enumerate(df.iterrows(), start=1):
        extras = {}
        for key in optional_keys:
            if key not in row.index:
                continue
            val = row.get(key)
            if pd.isna(val):
                continue
            extras[key] = val
        feats = extractor.extract_url_only(str(row["url"]), extras)
        vectors.append(extractor.vector(feats))
        if i % 2000 == 0 or i == total:
            print(f"  features {i}/{total}")
    X = np.array(vectors, dtype=float)
    y = df["label"].astype(int).to_numpy()
    return X, y, extractor.columns


def metrics_for_phishing(y_true, y_pred) -> dict:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_phishing": float(precision_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "recall_phishing": float(recall_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "f1_phishing": float(f1_score(y_true, y_pred, pos_label=1, zero_division=0)),
        "false_negative_rate": float(
            1.0 - recall_score(y_true, y_pred, pos_label=1, zero_division=0)
        ),
        "confusion_matrix": confusion_matrix(y_true, y_pred).tolist(),
    }


def select_model_by_fnr(all_metrics: dict) -> str:
    """Chọn model có FNR thấp nhất; hòa thì ưu tiên F1 phishing cao hơn."""
    def key(name: str):
        m = all_metrics[name]
        return (m["false_negative_rate"], -m["f1_phishing"])

    return min(all_metrics.keys(), key=key)


def main() -> None:
    parser = argparse.ArgumentParser(description="Train phishing detector models")
    parser.add_argument(
        "--dataset",
        type=str,
        default=None,
        help="Path CSV (PhiUSIIL hoặc schema nội bộ). Mặc định: PhiUSIIL nếu có, không thì sample.",
    )
    parser.add_argument(
        "--max-rows",
        type=int,
        default=40000,
        help="Giới hạn số dòng sau khi chuẩn hóa (0 = dùng hết). Mặc định 40000.",
    )
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument(
        "--model",
        type=str,
        default="auto",
        help="Model lưu artifact: auto | RandomForest | XGBoost | DecisionTree | LogisticRegression",
    )
    args = parser.parse_args()

    if args.dataset:
        path = Path(args.dataset)
        if not path.is_absolute():
            path = (ROOT / path).resolve()
    elif DEFAULT_PHIUSIIL.exists():
        path = DEFAULT_PHIUSIIL
    else:
        path = ensure_sample_dataset()

    if not path.exists():
        raise SystemExit(
            f"Khong tim thay dataset: {path}\n"
            f"Hay copy PhiUSIIL_Phishing_URL_Dataset.csv vao:\n  {DEFAULT_PHIUSIIL}"
        )

    df, dataset_version = load_dataset(path)
    print(f"Rows after clean: {len(df)} | labels: {df['label'].value_counts().to_dict()}")
    print("  (label 1 = phishing, 0 = safe)")

    if args.max_rows and args.max_rows > 0:
        before = len(df)
        df = stratified_sample(df, args.max_rows, seed=args.seed)
        print(f"Sampled {len(df)}/{before} rows (--max-rows {args.max_rows})")

    train_df, test_df = domain_aware_split(
        df, test_size=args.test_size, random_state=args.seed
    )
    print(f"Train URLs: {len(train_df)} | Test URLs: {len(test_df)}")
    print(f"Train labels: {train_df['label'].value_counts().to_dict()}")
    print(f"Test labels: {test_df['label'].value_counts().to_dict()}")

    print("Building train features (shared FeatureExtractor)...")
    X_train, y_train, _columns = build_feature_matrix(train_df)
    print("Building test features...")
    X_test, y_test, _ = build_feature_matrix(test_df)

    models = {
        "LogisticRegression": LogisticRegression(max_iter=2000, class_weight="balanced"),
        "DecisionTree": DecisionTreeClassifier(
            max_depth=10, class_weight="balanced", random_state=args.seed
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=250,
            max_depth=16,
            class_weight="balanced",
            random_state=args.seed,
            n_jobs=-1,
        ),
    }

    try:
        from xgboost import XGBClassifier

        models["XGBoost"] = XGBClassifier(
            n_estimators=250,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=args.seed,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"XGBoost skipped: {exc}")

    all_metrics: dict = {}
    fitted = {}
    for name, model in models.items():
        print(f"Training {name}...")
        model.fit(X_train, y_train)
        train_pred = model.predict(X_train)
        test_pred = model.predict(X_test)
        train_m = metrics_for_phishing(y_train, train_pred)
        test_m = metrics_for_phishing(y_test, test_pred)
        all_metrics[name] = {
            "train": train_m,
            "test": test_m,
            # Giữ key phẳng = test để tương thích báo cáo/slide cũ
            **test_m,
            "train_accuracy": train_m["accuracy"],
            "test_accuracy": test_m["accuracy"],
            "accuracy_gap": float(train_m["accuracy"] - test_m["accuracy"]),
        }
        fitted[name] = model
        print(
            f"  TRAIN  Acc={train_m['accuracy']:.3f} P={train_m['precision_phishing']:.3f} "
            f"R={train_m['recall_phishing']:.3f} F1={train_m['f1_phishing']:.3f} "
            f"FNR={train_m['false_negative_rate']:.3f}"
        )
        print(
            f"  TEST   Acc={test_m['accuracy']:.3f} P={test_m['precision_phishing']:.3f} "
            f"R={test_m['recall_phishing']:.3f} F1={test_m['f1_phishing']:.3f} "
            f"FNR={test_m['false_negative_rate']:.3f}"
        )
        print(f"  gap(train-test acc)={all_metrics[name]['accuracy_gap']:.3f}")

    if args.model == "auto":
        selected_name = select_model_by_fnr(
            {n: all_metrics[n]["test"] for n in all_metrics}
        )
        selection_rationale = (
            f"Auto-selected {selected_name} by lowest test FNR "
            f"(tie-break: higher phishing F1)."
        )
    else:
        selected_name = args.model
        if selected_name not in fitted:
            raise SystemExit(f"Unknown --model {selected_name}. Options: {list(fitted)}")
        selection_rationale = f"Forced selection via --model {selected_name}."

    selected = fitted[selected_name]
    print(f"Selected model: {selected_name}")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(selected, ARTIFACT_DIR / "model.joblib")
    (ARTIFACT_DIR / "feature_schema.json").write_text(
        json.dumps(schema_dict(), indent=2), encoding="utf-8"
    )
    try:
        rel = str(path.relative_to(ROOT))
    except ValueError:
        rel = str(path)
    metadata = {
        "model_name": selected_name,
        "model_version": "1.2",
        "feature_schema_version": schema_dict()["feature_schema_version"],
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset_version": dataset_version,
        "dataset_path": rel,
        "rows_used": int(len(df)),
        "split": "domain_aware",
        "label_convention": "1=phishing, 0=safe (PhiUSIIL labels inverted if used)",
        "selection_rationale": selection_rationale,
        "notes": (
            "PhiUSIIL lacks real TLS SAN checks; hostname_match is not copied from IsHTTPS. "
            "metrics include train vs test for overfitting checks. "
            "predict_proba near 1.0 means trees vote phishing, not calibrated certainty."
        ),
    }
    (ARTIFACT_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (ARTIFACT_DIR / "metrics.json").write_text(json.dumps(all_metrics, indent=2), encoding="utf-8")
    print(f"Saved {selected_name} artifacts to artifacts/{ARTIFACT_DIR.name}/")
    print("Restart uvicorn de nap model moi.")


if __name__ == "__main__":
    main()
