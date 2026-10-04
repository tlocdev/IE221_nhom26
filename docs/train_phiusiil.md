# Train với PhiUSIIL

Dataset UCI: [PhiUSIIL Phishing URL Dataset](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)

## 1. Đặt file

Copy file vào:

```text
Final_project/data/datasets/PhiUSIIL_Phishing_URL_Dataset.csv
```

## 2. Chạy train

```powershell
cd "D:\NguyenThanhLoc\UIT\Kỹ thuật lập trình Python\Code\Final_project"
.\.venv\Scripts\activate

# Lần đầu: lấy mẫu 40k dòng (nhanh hơn, đủ cho đồ án)
python scripts/train_model.py --dataset data/datasets/PhiUSIIL_Phishing_URL_Dataset.csv --max-rows 40000

# Dùng toàn bộ (~235k URL) — chậm hơn nhiều
python scripts/train_model.py --dataset data/datasets/PhiUSIIL_Phishing_URL_Dataset.csv --max-rows 0
```

Nếu file đã đúng đường dẫn trên, có thể chỉ cần:

```powershell
python scripts/train_model.py
```

(script ưu tiên PhiUSIIL nếu thấy file).

## 3. Lưu ý quan trọng

- **Nhãn PhiUSIIL:** `1` = hợp lệ, `0` = phishing → script **đảo** thành `1` = phishing (đúng hệ thống).
- Feature dùng **cùng `FeatureExtractor`** với runtime (tránh train-serving skew).
- **Không** đưa blacklist vào feature ML.
- Split **theo domain**.
- Model lưu: `artifacts/phishing_model_v1/` — restart `uvicorn` để nạp model mới.

## 4. Kiểm tra

Xem `artifacts/phishing_model_v1/metadata.json` và `metrics.json` (Precision / Recall / F1 lớp phishing, FNR).
