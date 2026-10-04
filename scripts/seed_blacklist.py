"""Seed / extend local blacklist JSON (threat intel — not ML features)."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.scanners.blacklist_checker import add_blacklist_entry  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Add blacklist entry")
    parser.add_argument("--url", default=None)
    parser.add_argument("--domain", default=None)
    parser.add_argument("--source", default="manual")
    args = parser.parse_args()
    if not args.url and not args.domain:
        parser.error("Provide --url and/or --domain")
    add_blacklist_entry(url=args.url, domain=args.domain, source=args.source)
    print("Added.")


if __name__ == "__main__":
    main()
