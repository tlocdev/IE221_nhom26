# Website Scam / Phishing Detector

Đồ án: phân tích và phát hiện **dấu hiệu** website lừa đảo bằng Python.

Hệ thống trả về **risk score** (mức độ rủi ro) kèm giải thích — **không** khẳng định tuyệt đối một site là lừa đảo.  
**Risk score ≠ xác suất phishing.** Xác suất từ mô hình được hiển thị riêng dưới tên **ML phishing probability**.

## Kiến trúc ngắn

```text
URL → SSRF-safe fetch → URL / Domain(RDAP→WHOIS) / TLS / HTML / Brand
     → FeatureExtractor (chung train+runtime)
     → Evidence: Heuristic | ML | Threat intel
     → Risk Engine → PostgreSQL/SQLite + UI
```

## Chạy nhanh (local, SQLite)

```bash
cd Final_project
python -m venv .venv

# Windows
.venv\Scripts\activate

pip install -r requirements.txt
python scripts/train_model.py
uvicorn app.main:app --reload --port 8000
```

Mở http://127.0.0.1:8000  

API: `POST /api/v1/scan` với JSON `{"url": "https://example.com"}`  
Swagger: http://127.0.0.1:8000/docs

## PostgreSQL (Docker)

```bash
docker compose up --build
```

App: http://localhost:8000 — DB `postgresql+psycopg2://scam:scam@db:5432/scam_detector`

Hoặc chỉ chạy Postgres rồi set:

```bash
set DATABASE_URL=postgresql+psycopg2://scam:scam@localhost:5432/scam_detector
uvicorn app.main:app --reload
```

## Tests

```bash
pytest -q
```

## Train / so sánh model

```bash
python scripts/train_model.py
```

- Split **theo registrable domain** (tránh leakage URL cùng domain)
- So sánh Logistic Regression, Decision Tree, Random Forest (+ XGBoost nếu cài được)
- Model runtime được **tự động chọn** theo FNR thấp nhất trên tập test (hòa thì ưu tiên F1 phishing cao hơn); hiện tại là **XGBoost** (xem `artifacts/phishing_model_v1/metadata.json`)
- Cố định một model: `python scripts/train_model.py --model XGBoost` (hoặc `RandomForest`, `DecisionTree`, `LogisticRegression`)
- Blacklist **không** đưa vào feature ML

## Danh sách đen (threat intel)

```bash
python scripts/sync_blacklist.py --force
```

Tự động đồng bộ khi khởi động app (OpenPhish + URLhaus + Phishing.Database). Chi tiết: [docs/threat_intel.md](docs/threat_intel.md).

## Nguyên tắc an toàn

- SSRF: validate DNS/IP **mỗi redirect** (IPv4 + IPv6 private/loopback)
- HTML: timeout, max redirects, max 2MB, chỉ HTML
- Domain age unknown → `null` / `domain_age_known=0` (không gán age=0)

Xem thêm: [docs/architecture.md](docs/architecture.md), [docs/security.md](docs/security.md), [docs/ml.md](docs/ml.md)

## Cấu trúc chính

- `app/scanners/` — URL, domain, SSL, HTML, brand, blacklist
- `app/features/` — schema + `FeatureExtractor` duy nhất
- `app/risk/` — rules + Risk Engine
- `app/ml/` — split + predict
- `scripts/train_model.py` — train dùng cùng extractor
