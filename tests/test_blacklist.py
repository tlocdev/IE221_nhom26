"""Tests for threat-intel blacklist index (local + feed cache)."""

from __future__ import annotations

from pathlib import Path

from app.config import get_settings
from app.scanners.blacklist_checker import check_blacklist, clear_blacklist_cache


def test_local_seed_hit(tmp_path, monkeypatch):
    bl_dir = tmp_path / "blacklist"
    bl_dir.mkdir()
    entries = bl_dir / "entries.json"
    entries.write_text(
        '{"entries":[{"url":null,"domain":"evil-test-blacklist.xyz","source":"seed_local","detected_at":"2026-01-01T00:00:00+00:00"}]}',
        encoding="utf-8",
    )
    monkeypatch.setenv("BLACKLIST_PATH", str(entries))
    # pydantic settings already cached — patch get_settings fields via object
    settings = get_settings()
    monkeypatch.setattr(settings, "blacklist_path", entries)
    monkeypatch.setattr(settings, "blacklist_dir", bl_dir)
    clear_blacklist_cache()

    hit = check_blacklist("https://login.evil-test-blacklist.xyz/a", "evil-test-blacklist.xyz")
    assert hit.hit is True
    assert hit.source == "seed_local"

    miss = check_blacklist("https://example.com/", "example.com")
    assert miss.hit is False
