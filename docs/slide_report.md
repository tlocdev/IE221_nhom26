# Tài liệu làm slide báo cáo đồ án

**Đề tài:** Website Scam / Phishing Detector — Phân tích và phát hiện dấu hiệu website lừa đảo bằng Python

Tài liệu được sắp theo thứ tự slide gợi ý (khoảng 16–18 slide). Mỗi mục gồm **nội dung đưa lên slide** và **ghi chú thuyết trình** (phần nói, không cần đưa lên slide). Số liệu lấy từ lần huấn luyện ngày 28/09/2026 (`artifacts/phishing_model_v1/`).

---

## Slide 1 — Trang bìa

- Tên đề tài: *Website Scam / Phishing Detector*
- Môn: Kỹ thuật lập trình Python — UIT
- Thành viên, MSSV, giảng viên hướng dẫn

---

## Slide 2 — Đặt vấn đề

**Nội dung slide:**
- Website lừa đảo giả mạo ngân hàng, ví điện tử, mạng xã hội để lấy mật khẩu, OTP, thông tin thẻ
- Tên miền lừa đảo được tạo mới liên tục, sống ngắn → danh sách đen luôn đi sau
- Người dùng phổ thông khó tự nhận biết (có HTTPS, giao diện giống thật)

**Ghi chú thuyết trình:** Nêu ví dụ quen thuộc ở Việt Nam: link giả Vietcombank, MoMo gửi qua SMS/Zalo. Nhấn mạnh rằng chỉ dùng blacklist là không đủ, cần phân tích dấu hiệu.

---

## Slide 3 — Mục tiêu đồ án

**Nội dung slide:**
- Nhập một URL → trả về **điểm rủi ro 0–100**, **mức rủi ro** và **giải thích từng dấu hiệu**
- Kết hợp 3 nguồn bằng chứng: **luật heuristic**, **mô hình Machine Learning**, **danh sách đen (threat intelligence)**
- Có giao diện web, REST API, lưu lịch sử quét
- Quét an toàn: không để hệ thống bị lợi dụng tấn công mạng nội bộ (SSRF)

**Ghi chú thuyết trình:** Hệ thống **không khẳng định** một trang chắc chắn là lừa đảo, mà chỉ ra các dấu hiệu đáng ngờ. Điểm rủi ro **không phải** xác suất lừa đảo.

---

## Slide 4 — Công nghệ sử dụng

| Nhóm | Công nghệ |
|---|---|
| Web / API | FastAPI, Uvicorn, Jinja2 |
| Cơ sở dữ liệu | SQLAlchemy, SQLite (demo) / PostgreSQL |
| Thu thập & phân tích | httpx, BeautifulSoup4, tldextract, python-whois, RDAP |
| So khớp thương hiệu | rapidfuzz (fuzzy matching) |
| Machine Learning | scikit-learn, XGBoost, pandas, numpy, joblib |
| Kiểm thử | pytest (16 test, đều pass) |

---

## Slide 5 — Kiến trúc tổng quan

**Sơ đồ (vẽ lại trên slide):**

```text
            URL người dùng nhập
                    │
          Kiểm tra SSRF + tải trang an toàn
                    │
   ┌────────┬───────┼────────┬─────────┬──────────┐
   URL    Domain   TLS/SSL   HTML    Thương hiệu  Danh sách đen
 analyzer (RDAP/   analyzer analyzer  detector    (3 feed + local)
          WHOIS)
   └────────┴───────┬────────┴─────────┘               │
                    │                                   │
        FeatureExtractor (30 thuộc tính)                │
              │                 │                       │
        Luật heuristic    Mô hình XGBoost               │
         (rule score)   (ML probability)                │
              └─────────┬───────┴───────────────────────┘
                        │
                   Risk Engine
                        │
          Điểm rủi ro + mức rủi ro + giải thích
                        │
              Lưu DB → Giao diện web / API
```

**Ghi chú thuyết trình:** Điểm quan trọng: `FeatureExtractor` được dùng **chung** cho cả lúc huấn luyện và lúc chạy thật, tránh lệch dữ liệu giữa hai giai đoạn (training-serving skew). Danh sách đen đi thẳng vào Risk Engine, **không** làm thuộc tính cho mô hình.

---

## Slide 6 — Các bộ phân tích (scanner)

| Scanner | Kiểm tra gì |
|---|---|
| **URL** | Độ dài, số subdomain, dấu `-`, `@`, chữ số, IP thô, từ khoá login/verify, TLD đáng ngờ (28 TLD như `.xyz`, `.top`, `.tk`, `.icu`) |
| **Domain** | Tuổi tên miền qua RDAP, dự phòng bằng WHOIS |
| **TLS/SSL** | Chứng chỉ hợp lệ, khớp hostname, hết hạn |
| **HTML** | Ô mật khẩu, trường thẻ tín dụng, số form, iframe, form gửi ra domain khác, ngôn ngữ thúc ép (tiếng Anh + tiếng Việt: "xác minh", "tài khoản bị khóa", "OTP"…) |
| **Thương hiệu** | So khớp mờ với 12 thương hiệu (Vietcombank, BIDV, MB Bank, Techcombank, MoMo, ZaloPay, Google, Facebook, Microsoft, Apple, PayPal, Amazon); phát hiện typosquatting kiểu `paypa1`, `g00gle` |
| **Danh sách đen** | Tra URL và tên miền trong feed |

---

## Slide 7 — Nguồn 1: Luật heuristic

**Nội dung slide (chọn các luật tiêu biểu):**

| Dấu hiệu | Điểm | Mức |
|---|---|---|
| Domain < 7 ngày tuổi | +30 | Cao |
| Domain < 30 ngày | +20 | Cao |
| URL dùng IP thô | +25 | Cao |
| URL chứa `@` | +20 | Cao |
| Giả mạo thương hiệu (tên giống + có form đăng nhập, không phải domain chính thức) | +20 | Cao |
| Chứng chỉ không khớp hostname | +20 | Cao |
| Thu thập thông tin thẻ | +15 | Cao |
| Form mật khẩu trên domain mới | +15 | Cao |
| Form gửi dữ liệu sang domain khác | +12 | Cao |
| TLD đáng ngờ / ngôn ngữ thúc ép / nhiều dấu `-` | +10 | Trung bình |
| Không dùng HTTPS | +5 | Thấp |

Tổng điểm luật được giới hạn trong 0–100.

**Ghi chú thuyết trình:** Luật có ưu điểm **giải thích được**: mỗi dấu hiệu sinh ra một "finding" hiển thị cho người dùng. Không có HTTPS chỉ +5 điểm vì hiện nay trang lừa đảo cũng thường có HTTPS miễn phí.

---

## Slide 8 — Nguồn 2: Mô hình Machine Learning — Dữ liệu

**Nội dung slide:**
- Bộ dữ liệu: **PhiUSIIL Phishing URL Dataset** (UCI Machine Learning Repository)
- 235.795 URL gốc → **235.370 URL** sau khi loại trùng
- Tỷ lệ: 134.850 hợp lệ (57%) / 100.945 phishing (43%)
- Đảo nhãn cho thống nhất: **1 = phishing, 0 = an toàn**
- Chia **theo tên miền** (domain-aware split): train ≈ 185.954 URL, test 49.416 URL

**Ghi chú thuyết trình:** Nếu chia ngẫu nhiên, nhiều URL cùng một tên miền (`/a`, `/b`, `/c`) sẽ rơi vào cả train và test → mô hình "nhớ" tên miền, kết quả bị thổi phồng. Chia theo tên miền đảm bảo tên miền trong tập test **chưa từng xuất hiện** lúc huấn luyện.

---

## Slide 9 — Thuộc tính đầu vào (30 thuộc tính)

| Nhóm | Số lượng | Ví dụ |
|---|---|---|
| Cấu trúc URL | 14 | `url_length`, `num_subdomains`, `num_hyphens`, `has_https`, `suspicious_tld` |
| Domain & SSL | 5 | `domain_age_days`, `tls_ok`, `hostname_match`, `cert_expired` |
| Nội dung HTML | 7 | `password_input_count`, `form_count`, `iframe_count`, `external_form_action` |
| Thương hiệu | 3 | `brand_similarity`, `brand_in_domain`, `impersonation_likely` |
| Chuyển hướng | 1 | `redirect_count` |

Danh sách đen **không** được đưa vào làm thuộc tính (tránh rò rỉ nhãn — label leakage).

---

## Slide 10 — So sánh 4 mô hình

**Nội dung slide (kết quả trên tập test):**

| Mô hình | FNR (càng thấp càng tốt) | Recall | Precision | F1 | Accuracy |
|---|---|---|---|---|---|
| Logistic Regression | 5,50% | 94,50% | 97,30% | 95,88% | 96,34% |
| Decision Tree | 4,49% | 95,51% | 98,68% | 97,07% | 97,41% |
| Random Forest | 3,56% | 96,44% | 98,51% | 97,47% | 97,74% |
| **XGBoost (được chọn)** | **3,47%** | **96,53%** | 98,66% | **97,58%** | **97,85%** |

Gợi ý: vẽ **biểu đồ cột FNR** của 4 mô hình để thấy rõ XGBoost thấp nhất.

**Ghi chú thuyết trình:**
- FNR (False Negative Rate) = tỷ lệ trang phishing bị bỏ sót.
- Số trang phishing bị bỏ sót trên 22.238 trang phishing của tập test: XGBoost 772, Random Forest 791, Decision Tree 998, Logistic Regression 1.223.
- Chênh lệch accuracy giữa train và test của XGBoost chỉ 0,03% → không overfit.

---

## Slide 11 — Vì sao chọn XGBoost

**Nội dung slide:**
- Tiêu chí chọn: **FNR thấp nhất** trên tập test (hòa thì chọn F1 cao hơn) — script tự chọn (`--model auto`)
- Lý do ưu tiên FNR: bỏ sót trang lừa đảo nguy hiểm hơn cảnh báo nhầm
- XGBoost phù hợp dữ liệu dạng bảng, học được quan hệ phi tuyến giữa các thuộc tính, các cây sau sửa lỗi cây trước

**Confusion matrix của XGBoost (tập test):**

|  | Dự đoán an toàn | Dự đoán phishing |
|---|---|---|
| **Thực tế an toàn** | 26.886 | 292 |
| **Thực tế phishing** | 772 | 21.466 |

**Ghi chú thuyết trình:** Nói trung thực: XGBoost chỉ nhỉnh hơn Random Forest một chút (19 URL). Hai mô hình cho kết quả tương đương.

---

## Slide 12 — Thuộc tính quan trọng nhất của mô hình

**Nội dung slide (mức đóng góp — gain):**

| Thuộc tính | Mức đóng góp |
|---|---|
| `has_https` | 43,2% |
| `hostname_match` | 31,0% |
| `form_count` | 4,7% |
| `path_depth` | 4,2% |
| `url_length` | 4,0% |
| `num_digits` | 3,0% |
| `num_subdomains` | 2,9% |
| `iframe_count` | 2,2% |

Gợi ý: vẽ **biểu đồ thanh ngang** top 8.

**Ghi chú thuyết trình:** Hai thuộc tính đầu đều phản ánh việc URL có HTTPS hay không, chiếm khoảng 74%. Đây là đặc điểm của bộ PhiUSIIL. Xem thêm slide Hạn chế.

---

## Slide 13 — Nguồn 3: Danh sách đen (threat intelligence)

**Nội dung slide:**

| Nguồn | Loại | Số lượng (28/09/2026) |
|---|---|---|
| OpenPhish | URL phishing | 300 URL |
| URLhaus (abuse.ch) | URL độc hại đang hoạt động | 16.542 URL |
| Phishing.Database | Tên miền phishing đang hoạt động | 167.539 tên miền |
| Local seed | Nhập tay | `entries.json` |
| **Tổng** | | **16.842 URL + 169.472 tên miền** |

- Tự đồng bộ khi khởi động server nếu dữ liệu cũ hơn 24 giờ
- Thứ tự tra: local → URL khớp chính xác → tên miền / subdomain

---

## Slide 14 — Risk Engine: tổng hợp điểm

**Nội dung slide:**

- **Có trong danh sách đen:** điểm tối thiểu **85** (floor), có thể cao hơn nếu luật/ML cũng cao
- **Không có trong danh sách đen:**
  `Điểm rủi ro = 0,55 × điểm luật + 0,45 × (xác suất ML × 100)`
- Nếu cả luật (≥ 50) và ML (≥ 0,5) đều cao → giảm nhẹ trọng số ML (× 0,85) để tránh **đếm trùng** dấu hiệu
- Không có mô hình → chỉ dùng điểm luật

**Mức rủi ro:**

| Điểm | Mức |
|---|---|
| 0–39 | Thấp (low) |
| 40–64 | Trung bình (medium) |
| 65–84 | Cao (high) |
| 85–100 | Nghiêm trọng (critical) |

**Ghi chú thuyết trình:** Vì sao giảm trọng số ML: một số dấu hiệu (như tên miền giả thương hiệu) vừa có trong luật vừa là thuộc tính ML. Nếu cộng thẳng sẽ bị tính hai lần.

---

## Slide 15 — Bảo mật khi quét URL

**Nội dung slide:**
- **Chống SSRF:** phân giải DNS và chặn IP nội bộ (10.x, 172.16–31.x, 192.168.x, 127.x, 169.254.x, IPv6 loopback/private), chặn `localhost`, địa chỉ metadata cloud
- **Kiểm tra lại ở mỗi lần chuyển hướng**, tối đa 3 lần
- Chỉ chấp nhận `http`/`https`, không cho URL chứa `user:pass@`
- Giới hạn: timeout kết nối 3 giây, đọc 5 giây, HTML tối đa 2 MB, chỉ tải nội dung HTML (bỏ qua file zip, exe, pdf, ảnh, video)
- Tuổi tên miền không tra được → ghi là "chưa rõ", **không** coi là 0 ngày

**Ghi chú thuyết trình:** SSRF là lỗ hổng khi server bị lợi dụng để gọi vào mạng nội bộ. Kẻ xấu có thể nhập URL trỏ tới `http://192.168.1.1` hoặc một trang chuyển hướng tới đó. Vì vậy phải kiểm tra lại ở từng bước chuyển hướng.

---

## Slide 16 — Demo giao diện

**Nội dung slide (chụp màn hình khi chạy `uvicorn app.main:app --reload --port 8000`):**
1. Trang chủ: ô nhập URL, danh sách lượt quét gần đây
2. Trang phân tích: tiến trình quét (tra domain/WHOIS, TLS, HTML, danh sách đen)
3. Trang kết quả: điểm rủi ro, mức rủi ro, xác suất ML, danh sách dấu hiệu, **checklist 12 mục** (HTTPS, chứng chỉ, IP, tuổi tên miền, TLD, cấu trúc URL, thương hiệu, form mật khẩu, thu thập thẻ, nội dung, chuyển hướng, danh sách đen)
4. Trang lịch sử quét
5. Swagger API tại `/docs`

**Gợi ý URL để demo:**
- Trang hợp lệ: `https://vietcombank.com.vn`, `https://github.com`
- Trang nằm trong danh sách đen: lấy một dòng bất kỳ trong `data/blacklist/feed_urls.txt` (**chỉ quét qua hệ thống, không mở trực tiếp trên trình duyệt**)

**API chính:**

| Phương thức | Đường dẫn | Chức năng |
|---|---|---|
| POST | `/api/v1/scan` | Quét một URL |
| GET | `/api/v1/scans`, `/api/v1/scans/{id}` | Lịch sử, chi tiết lượt quét |
| GET | `/api/v1/blacklist/status` | Thống kê danh sách đen |
| POST | `/api/v1/blacklist/sync` | Đồng bộ lại danh sách đen |
| GET | `/health` | Trạng thái hệ thống |

---

## Slide 17 — Hạn chế

**Nội dung slide:**
- Mô hình phụ thuộc mạnh vào HTTPS (≈ 74% mức đóng góp) do đặc điểm bộ PhiUSIIL; ngoài thực tế nhiều trang lừa đảo đã có HTTPS
- PhiUSIIL không có tuổi tên miền, không có kết quả kiểm tra chứng chỉ thật → mô hình không học được các thuộc tính này (chúng chỉ được dùng trong luật)
- Kết quả 97,85% đo trên PhiUSIIL, trên URL thực tế có thể thấp hơn
- Danh sách thương hiệu mới có 12 thương hiệu
- Chưa xử lý trang dựng bằng JavaScript (chỉ đọc HTML tĩnh)
- Tra WHOIS/RDAP có thể chậm hoặc thất bại → kết quả "partial"

**Ghi chú thuyết trình:** Nêu hạn chế thẳng thắn cho thấy nhóm hiểu rõ hệ thống. Đây là điểm cộng khi bảo vệ.

---

## Slide 18 — Hướng phát triển

- Huấn luyện lại trên dữ liệu có tuổi tên miền và kết quả TLS thật; thử bỏ nhóm thuộc tính HTTPS để giảm phụ thuộc
- Hiệu chỉnh xác suất (probability calibration) để xác suất ML có ý nghĩa hơn
- Dùng trình duyệt headless để phân tích trang JavaScript, chụp ảnh so sánh giao diện với trang thật
- Mở rộng danh sách thương hiệu Việt Nam (ngân hàng, sàn thương mại điện tử, cơ quan nhà nước)
- Tiện ích trình duyệt (browser extension) cảnh báo ngay khi người dùng mở trang

---

## Slide 19 — Kết luận

- Xây dựng được hệ thống phát hiện dấu hiệu website lừa đảo kết hợp **luật + ML + danh sách đen**
- Mô hình XGBoost đạt **FNR 3,47%**, **F1 97,58%** trên tập test chia theo tên miền
- Kết quả **giải thích được** cho người dùng, quét URL **an toàn** (chống SSRF)
- Có web, API, lưu lịch sử, kiểm thử tự động

---

## Phụ lục — Câu hỏi hội đồng có thể hỏi

**Vì sao không dùng accuracy để chọn mô hình?**
Vì bỏ sót trang lừa đảo (false negative) gây hại lớn hơn cảnh báo nhầm. FNR đo trực tiếp tỷ lệ bỏ sót.

**Điểm rủi ro 80 có nghĩa là 80% khả năng lừa đảo không?**
Không. Điểm rủi ro là chỉ số tổng hợp từ luật, ML và danh sách đen. Xác suất ML được hiển thị riêng.

**Vì sao không đưa danh sách đen vào mô hình?**
Nhãn của dữ liệu huấn luyện có thể cũng lấy từ các feed này. Nếu dùng làm thuộc tính, mô hình sẽ "học vẹt" danh sách đen (label leakage), và không nhận ra trang lừa đảo mới.

**Vì sao chia train/test theo tên miền?**
Để tránh URL cùng tên miền xuất hiện ở cả hai tập, làm kết quả kiểm thử bị thổi phồng.

**Tuổi tên miền có được mô hình dùng không?**
Có được tra khi quét thật, nhưng mô hình không học được vì PhiUSIIL không có cột này. Tuổi tên miền được dùng trong phần luật (domain dưới 7 ngày +30 điểm).

**Nếu WHOIS thất bại thì sao?**
Tuổi tên miền ghi là "chưa rõ" (không coi là 0 ngày), lượt quét được đánh dấu `partial`, các nguồn bằng chứng khác vẫn tính điểm bình thường.

---

## Nguồn số liệu trong dự án

| Số liệu | File |
|---|---|
| Kết quả 4 mô hình, confusion matrix | `artifacts/phishing_model_v1/metrics.json` |
| Mô hình được chọn, số dòng dữ liệu | `artifacts/phishing_model_v1/metadata.json` |
| Danh sách 30 thuộc tính | `app/features/definitions.py` |
| Điểm của từng luật | `app/risk/rules.py` |
| Trọng số tổng hợp, ngưỡng mức rủi ro | `app/config.py`, `app/risk/engine.py` |
| Số lượng danh sách đen | `data/blacklist/feed_meta.json` |
| Checklist trên giao diện | `app/risk/checklist.py` |
