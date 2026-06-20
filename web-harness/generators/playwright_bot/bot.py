"""Playwright agent — rapid, deterministic, no humanlike pauses.

Each session = a fresh BrowserContext (= a new `allm_sid` cookie minted by
the capture proxy). The bot logs in to DVWA, walks a fixed set of
vulnerability categories, and sprays payloads from `payloads.txt` into
the first text input on each page. No mouse jitter, no dwell.

Every request carries `X-Allm-Source: playwright_bot`.
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import time

sys.path.insert(0, "/app/shared")
from target_guard import get_target  # noqa: E402

from playwright.async_api import async_playwright  # noqa: E402

LABEL = "playwright_bot"
TARGET = get_target()
SESSIONS = int(os.environ.get("ALLM_SESSIONS", "10"))
DVWA_USER = os.environ.get("DVWA_USER", "admin")
DVWA_PASS = os.environ.get("DVWA_PASS", "password")

with open("/app/payloads.txt") as _f:
    PAYLOADS = [
        line.strip() for line in _f if line.strip() and not line.strip().startswith("#")
    ]

VULN_PATHS = [
    "/vulnerabilities/sqli/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/xss_s/",
    "/vulnerabilities/exec/",
    "/vulnerabilities/fi/?page=include.php",
]


async def recon(ctx) -> None:
    """Classic robots.txt-driven recon: GET /robots.txt, then visit every
    Disallow path. Real attack tools do this all the time; doing it here
    means the bot trips the /__admin_secrets honeypot organically.
    """
    try:
        resp = await ctx.request.get(f"{TARGET}/robots.txt", timeout=8000)
    except Exception:
        return
    if not resp.ok:
        return
    try:
        text = await resp.text()
    except Exception:
        return
    for line in text.splitlines():
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path.startswith("/"):
                try:
                    await ctx.request.get(f"{TARGET}{path}", timeout=5000)
                except Exception:
                    pass


async def login(page) -> None:
    await page.goto(f"{TARGET}/login.php", wait_until="domcontentloaded")
    await page.fill('input[name="username"]', DVWA_USER)
    await page.fill('input[name="password"]', DVWA_PASS)
    await page.click('input[name="Login"]')
    await page.wait_for_load_state("domcontentloaded")


INPUT_SELECTOR = (
    'input[type="text"]:not([disabled]):not([readonly]), '
    'textarea:not([disabled]):not([readonly])'
)


async def attack_page(page, path: str) -> None:
    try:
        await page.goto(f"{TARGET}{path}", wait_until="domcontentloaded", timeout=10000)
    except Exception:
        return
    inputs = await page.query_selector_all(INPUT_SELECTOR)
    if not inputs:
        return
    picks = random.sample(PAYLOADS, k=min(2, len(PAYLOADS)))
    for payload in picks:
        try:
            # Greedy: fill every text input on the page, including the
            # honeypot's `email_verify`. This is normal spray-fuzzer
            # behavior — and exactly what we want to detect.
            for inp in inputs:
                try:
                    await inp.fill(payload)
                except Exception:
                    pass
            btn = await page.query_selector(
                'input[type="submit"], button[type="submit"]'
            )
            if btn:
                await btn.click()
            else:
                await page.keyboard.press("Enter")
            await page.wait_for_load_state("domcontentloaded", timeout=5000)
            inputs = await page.query_selector_all(INPUT_SELECTOR)
            if not inputs:
                break
        except Exception:
            pass


async def run_one(browser) -> int:
    ctx = await browser.new_context(
        extra_http_headers={"X-Allm-Source": LABEL},
        viewport={"width": 1280, "height": 800},
    )
    page = await ctx.new_page()
    n_pages = 0
    try:
        await recon(ctx)
        await login(page)
        for path in VULN_PATHS:
            await attack_page(page, path)
            n_pages += 1
    finally:
        await ctx.close()
    return n_pages


async def main() -> None:
    print(f"[{LABEL}] target={TARGET} sessions={SESSIONS}", flush=True)
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"]
        )
        try:
            for i in range(SESSIONS):
                t0 = time.time()
                pages = await run_one(browser)
                print(
                    f"[{LABEL}] session {i + 1}/{SESSIONS} pages={pages} "
                    f"took={time.time() - t0:.1f}s",
                    flush=True,
                )
        finally:
            await browser.close()
    print(f"[{LABEL}] done", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
