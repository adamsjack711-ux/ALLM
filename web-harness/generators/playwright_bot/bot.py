"""Playwright agent — rapid, deterministic, no humanlike pauses.

Each session = a fresh BrowserContext (= a new `cernis_sid` cookie minted by
the capture proxy). The bot logs in to DVWA, walks a fixed set of
vulnerability categories, and sprays payloads from `payloads.txt` into
the first text input on each page. No mouse jitter, no dwell.

Every request carries `X-Cernis-Source: playwright_bot`.

Phase 9 stealth mode (CERNIS_STEALTH=true): family stays the same, the
`stealth=true` axis on the manifest distinguishes the run. Stealth
toggles ON:
  - random human-speed delays between actions (5-15s)
  - mouse jitter before form interaction
  - skip the robots.txt recon (no robots/admin_secrets honeypot trip)
  - selective fill (skip hidden/off-screen inputs — avoids the
    invisible_field honeypot)
  - one payload per page instead of spray loops
  - real-browser User-Agent
"""

from __future__ import annotations

import asyncio
import os
import random
import sys
import time

sys.path.insert(0, "/app/shared")
from manifest import (  # noqa: E402
    build_payload, headers_for, record_provenance_playwright,
)
from target_guard import get_target  # noqa: E402

from playwright.async_api import async_playwright  # noqa: E402

LABEL = "playwright_bot"
TARGET = get_target()
TARGET_APP = os.environ.get("CERNIS_TARGET_APP", "dvwa")
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
SESSIONS = int(os.environ.get("CERNIS_SESSIONS", "10"))
DVWA_USER = os.environ.get("DVWA_USER", "admin")
DVWA_PASS = os.environ.get("DVWA_PASS", "password")
STEALTH = os.environ.get("CERNIS_STEALTH", "false").strip().lower() in (
    "1", "true", "yes",
)
STEALTH_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

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


async def _human_pause() -> None:
    """Stealth-mode inter-action sleep — random human-speed delay."""
    if STEALTH:
        await asyncio.sleep(random.uniform(2.5, 6.5))


async def _jitter_mouse(page) -> None:
    if not STEALTH:
        return
    for _ in range(random.randint(2, 4)):
        await page.mouse.move(
            random.randint(60, 1100), random.randint(60, 700),
            steps=random.randint(8, 16),
        )
        await asyncio.sleep(random.uniform(0.1, 0.3))


async def recon(ctx) -> None:
    """Classic robots.txt-driven recon: GET /robots.txt, then visit every
    Disallow path. Real attack tools do this all the time; doing it here
    means the bot trips the /__admin_secrets honeypot organically.

    Stealth mode skips this entirely — the whole point of stealth is to
    avoid the easy honeypot trips, and robots.txt-following bots are
    the easiest signal for the honeypot system to lock onto.
    """
    if STEALTH:
        return
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
    await _jitter_mouse(page)
    if STEALTH:
        await page.keyboard.type(DVWA_USER, delay=random.uniform(100, 200))
        await asyncio.sleep(random.uniform(0.3, 0.8))
        await page.click('input[name="password"]')
        await page.keyboard.type(DVWA_PASS, delay=random.uniform(100, 200))
        await _human_pause()
    else:
        await page.fill('input[name="username"]', DVWA_USER)
        await page.fill('input[name="password"]', DVWA_PASS)
    await page.click('input[name="Login"]')
    await page.wait_for_load_state("domcontentloaded")


INPUT_SELECTOR = (
    'input[type="text"]:not([disabled]):not([readonly]), '
    'textarea:not([disabled]):not([readonly])'
)


async def _visible_inputs(page) -> list:
    """In stealth mode, skip off-screen / aria-hidden inputs so the
    bot doesn't trip the invisible_field honeypot. Non-stealth mode
    keeps the original greedy fill-all."""
    inputs = await page.query_selector_all(INPUT_SELECTOR)
    if not STEALTH:
        return inputs
    visible: list = []
    for inp in inputs:
        try:
            ok = await inp.is_visible()
            if not ok:
                continue
            box = await inp.bounding_box()
            if box is None or box["width"] < 5 or box["height"] < 5:
                continue
            # belt and suspenders against the honeypot's off-screen positioning
            if box["x"] < 0 or box["y"] < 0:
                continue
            visible.append(inp)
        except Exception:
            continue
    return visible


async def attack_page(page, path: str) -> None:
    try:
        await page.goto(f"{TARGET}{path}", wait_until="domcontentloaded", timeout=10000)
    except Exception:
        return
    await _jitter_mouse(page)
    inputs = await _visible_inputs(page)
    if not inputs:
        return
    # Stealth: ONE payload per page, one input per round, with human pauses.
    # Non-stealth: spray two payloads across every input on the page.
    picks = random.sample(PAYLOADS, k=1 if STEALTH else min(2, len(PAYLOADS)))
    for payload in picks:
        try:
            if STEALTH:
                # human-typed payload into a single, plausibly visible input
                inp = inputs[0]
                try:
                    await inp.click()
                    await page.keyboard.type(payload, delay=random.uniform(80, 180))
                except Exception:
                    pass
                await _human_pause()
            else:
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
            inputs = await _visible_inputs(page)
            if not inputs:
                break
        except Exception:
            pass


async def run_one(browser) -> int:
    payload = build_payload(
        klass="agent", family=LABEL, target_app=TARGET_APP,
        security_level=SECURITY_LEVEL, stealth=STEALTH,
        generator="playwright_bot", generator_version="0.2.0",
        generator_config={"stealth": STEALTH, "paths": VULN_PATHS},
    )
    headers = headers_for(payload) | (
        {"User-Agent": STEALTH_UA} if STEALTH else {}
    )
    ctx = await browser.new_context(
        extra_http_headers=headers,
        viewport={"width": 1280, "height": 800},
    )
    page = await ctx.new_page()
    n_pages = 0
    try:
        # Bootstrap the session + write provenance (carries stealth=True
        # so the manifest row reflects the run shape).
        try:
            await page.goto(TARGET, wait_until="domcontentloaded", timeout=10000)
        except Exception:
            pass
        await record_provenance_playwright(ctx.request, TARGET, payload)

        await recon(ctx)
        await login(page)
        for path in VULN_PATHS:
            await attack_page(page, path)
            n_pages += 1
            if STEALTH:
                await _human_pause()
    finally:
        await ctx.close()
    return n_pages


async def main() -> None:
    mode = "stealth" if STEALTH else "fast"
    print(f"[{LABEL}] target={TARGET} mode={mode} sessions={SESSIONS}", flush=True)
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
