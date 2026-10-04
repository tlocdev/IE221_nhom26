"""Safe HTTP fetch with per-redirect SSRF validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import certifi
import httpx

from app.config import get_settings
from app.core.ssrf import SSRFError, validate_url_for_ssrf


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    content_type: str
    redirect_count: int
    redirect_chain: list[str] = field(default_factory=list)
    error: str | None = None


class SafeHttpClient:
    def __init__(self) -> None:
        self.settings = get_settings()

    def fetch(self, url: str, *, accept_html_only: bool = True) -> FetchResult:
        chain: list[str] = []
        current = url.strip()
        redirects = 0

        timeout = httpx.Timeout(
            connect=self.settings.connect_timeout,
            read=self.settings.read_timeout,
            write=self.settings.read_timeout,
            pool=self.settings.connect_timeout,
        )

        try:
            with httpx.Client(
                timeout=timeout,
                follow_redirects=False,
                verify=certifi.where(),
                headers={"User-Agent": "WebsiteScamDetector/1.0 (academic research)"},
            ) as client:
                while True:
                    validate_url_for_ssrf(current)
                    chain.append(current)

                    response = client.request("GET", current)

                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise SSRFError("Redirect without Location header")
                        next_url = str(httpx.URL(current).join(location))
                        redirects += 1
                        if redirects > self.settings.max_redirects:
                            raise SSRFError(
                                f"Exceeded max redirects ({self.settings.max_redirects})"
                            )
                        # Re-validate every hop
                        validate_url_for_ssrf(next_url)
                        current = next_url
                        continue

                    content_type = response.headers.get("content-type", "")
                    if accept_html_only and not _looks_like_html(content_type, response.content):
                        return FetchResult(
                            final_url=str(response.url),
                            status_code=response.status_code,
                            headers=dict(response.headers),
                            content=b"",
                            content_type=content_type,
                            redirect_count=redirects,
                            redirect_chain=chain,
                            error=f"Unsupported content-type: {content_type or 'unknown'}",
                        )

                    content = response.content[: self.settings.max_html_bytes]
                    if len(response.content) > self.settings.max_html_bytes:
                        # Truncate but continue analysis on partial HTML
                        pass

                    return FetchResult(
                        final_url=str(response.url),
                        status_code=response.status_code,
                        headers=dict(response.headers),
                        content=content,
                        content_type=content_type,
                        redirect_count=redirects,
                        redirect_chain=chain,
                    )
        except SSRFError:
            raise
        except httpx.HTTPError as exc:
            return FetchResult(
                final_url=current,
                status_code=0,
                headers={},
                content=b"",
                content_type="",
                redirect_count=redirects,
                redirect_chain=chain,
                error=str(exc),
            )


def _looks_like_html(content_type: str, body: bytes) -> bool:
    ct = content_type.lower()
    if any(
        bad in ct
        for bad in (
            "application/zip",
            "application/pdf",
            "application/octet-stream",
            "video/",
            "audio/",
            "image/",
            "application/x-msdownload",
            "application/exe",
        )
    ):
        return False
    if "html" in ct or "text/plain" in ct or ct == "":
        return True
    # Sniff when content-type missing / generic
    head = body[:200].lower()
    return b"<html" in head or b"<!doctype html" in head


def fetch_url(url: str, **kwargs: Any) -> FetchResult:
    return SafeHttpClient().fetch(url, **kwargs)
