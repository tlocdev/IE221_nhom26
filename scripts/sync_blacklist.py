"""Đồng bộ danh sách đen từ OpenPhish, URLhaus, Phishing.Database."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.scanners.blacklist_feeds import sync_feeds  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync public phishing blacklist feeds")
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bỏ qua cache tuổi tối đa, luôn tải lại",
    )
    args = parser.parse_args()
    print("Dang dong bo danh sach den...")
    meta = sync_feeds(force=args.force)
    print(json.dumps(meta, indent=2, ensure_ascii=False))
    if meta.get("skipped"):
        print("Bo qua: cache con moi. Dung --force de tai lai.")
    else:
        print(
            f"Xong: {meta.get('url_count', 0)} URL, "
            f"{meta.get('domain_count', 0)} domain."
        )


if __name__ == "__main__":
    main()
