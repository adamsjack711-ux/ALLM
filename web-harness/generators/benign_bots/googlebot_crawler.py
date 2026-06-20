"""Googlebot-style crawler.

UA matches Google's documented bot string. Reads robots.txt and visits
each Disallow path once (search-engine crawlers historically *did*
fetch these to verify they were excluded, which is incidentally why a
robots.txt honeypot works at all). Then BFS from `/` to a small max
depth, polite delay between requests.

Expected honeypot interaction:
  - robots_read: YES (fetches /robots.txt).
  - admin_secrets: YES — by visiting the Disallow path. This is the
    correct precision-relevant signal: a real Googlebot DOES request
    Disallow paths to confirm them, so this honeypot's signal against
    *agents specifically* depends on the benign_bot baseline. That's
    what we measure.
  - canary, invisible_field: NO (no JS, no form submission).
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from benign_bots._common import loop, start_session

UA = (
    "Mozilla/5.0 (compatible; Googlebot/2.1; "
    "+http://www.google.com/bot.html)"
)
SEED_PATH = "/"
MAX_PAGES = 12
DELAY_S = 1.0


def _parse_robots(text: str) -> list[str]:
    paths: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            p = line.split(":", 1)[1].strip()
            if p.startswith("/"):
                paths.append(p)
    return paths


def _internal_links(html: str, base_path: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    out: list[str] = []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith("#"):
            continue
        if href.startswith("http://") or href.startswith("https://"):
            # Only follow same-host links (proxy upstream is internal anyway).
            parsed = urlparse(href)
            if parsed.netloc and parsed.netloc not in ("capture", "127.0.0.1", "localhost"):
                continue
            href = parsed.path or "/"
        elif not href.startswith("/"):
            href = urljoin(base_path, href)
        out.append(href)
    return out


def _crawl(client: httpx.Client) -> int:
    n = 0
    # Robots-driven recon (matches the real Googlebot's robots-first pattern).
    try:
        r = client.get("/robots.txt")
        n += 1
        if r.status_code == 200:
            for path in _parse_robots(r.text):
                client.get(path)
                n += 1
    except httpx.HTTPError:
        pass

    # BFS from seed.
    seen: set[str] = set()
    queue: list[str] = [SEED_PATH]
    while queue and n < MAX_PAGES:
        path = queue.pop(0)
        if path in seen:
            continue
        seen.add(path)
        try:
            resp = client.get(path)
            n += 1
        except httpx.HTTPError:
            continue
        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue
        for href in _internal_links(resp.text, path):
            if href not in seen and len(seen) + len(queue) < MAX_PAGES * 2:
                queue.append(href)
    return n


def run_session(target: str) -> int:
    client, _ = start_session(
        target,
        family="googlebot",
        user_agent=UA,
        config={"max_pages": MAX_PAGES, "delay_s": DELAY_S, "seed": SEED_PATH},
    )
    with client:
        return loop(1, 0.0, lambda i: _crawl(client))
