# Danh sách đen (Threat intelligence)

Threat intel **không** đưa vào feature ML (tránh data leakage khi nhãn dataset cũng lấy từ feed).

## Nguồn dữ liệu

| Nguồn | Loại | URL |
|-------|------|-----|
| **Local seed** | URL/domain thủ công | `data/blacklist/entries.json` |
| **OpenPhish** | URL phishing | https://openphish.com/feed.txt |
| **URLhaus** | URL độc hại online | https://urlhaus.abuse.ch/downloads/text_online/ |
| **Phishing.Database** | Domain phishing active | GitHub `phishing-domains-ACTIVE.txt` |

## Đồng bộ

```bash
# Lần đầu / cập nhật thủ công
python scripts/sync_blacklist.py --force
```

Khi chạy app, nếu `BLACKLIST_SYNC_ON_STARTUP=true` và cache cũ hơn `BLACKLIST_SYNC_MAX_AGE_HOURS` (mặc định 24h), server tự đồng bộ nền.

File cache (không commit):

- `data/blacklist/feed_urls.txt`
- `data/blacklist/feed_domains.txt`
- `data/blacklist/feed_meta.json`

## API

- `GET /api/v1/blacklist/status` — thống kê cache
- `POST /api/v1/blacklist/sync?force=true` — đồng bộ lại
- `GET /health` — gồm khối `blacklist`

## Tra cứu khi scan

Thứ tự: local seed → feed URL (khớp exact) → feed domain (tên miền / subdomain).

Hit → Risk Engine áp floor điểm cao; **không** đưa `is_blacklisted` vào mô hình ML (làm feature).
