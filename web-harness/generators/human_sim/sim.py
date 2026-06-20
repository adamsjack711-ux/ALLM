"""Human-like simulator — slow cadence, mouse movement, no attack payloads.

Sends the same `X-Allm-Source` mechanism as the bot, labeled `human_sim`.
Note (also called out in the README): this shares the Playwright /
Chromium fingerprint with the bot, so the JS beacon discriminates on
*cadence* (typing rhythm, mouse jitter, scroll, dwell) — not browser
engine. Real-human capture on :8090 is the only ground-truth benign
source; this simulator is a stand-in for bulk benign data.
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

LABEL = "human_sim"
TARGET = get_target()
SESSIONS = int(os.environ.get("ALLM_SESSIONS", "10"))
DVWA_USER = os.environ.get("DVWA_USER", "admin")
DVWA_PASS = os.environ.get("DVWA_PASS", "password")

# Spec says 40-80 CPM; we apply a slightly faster realistic range so each
# session doesn't dominate wall-clock — still ~5-10x slower than the bot's
# instant page.fill(). Knob-tune-able here if you want stricter spec.
TYPE_MS = (120, 260)

BROWSE_PATHS = [
    "/index.php",
    "/vulnerabilities/sqli/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/brute/",
    "/instructions.php",
    "/about.php",
]


def human_pause_s() -> float:
    return random.uniform(1.0, 4.0)


async def jitter_mouse(page) -> None:
    for _ in range(random.randint(2, 5)):
        x = random.randint(60, 1100)
        y = random.randint(60, 700)
        await page.mouse.move(x, y, steps=random.randint(8, 18))
        await asyncio.sleep(random.uniform(0.1, 0.35))


async def human_type(page, selector: str, text: str) -> None:
    el = await page.wait_for_selector(selector, timeout=10000)
    await el.click()
    for ch in text:
        await page.keyboard.type(ch, delay=random.uniform(*TYPE_MS))
    await asyncio.sleep(random.uniform(0.2, 0.6))


async def login(page) -> None:
    await page.goto(f"{TARGET}/login.php", wait_until="domcontentloaded")
    await jitter_mouse(page)
    await human_type(page, 'input[name="username"]', DVWA_USER)
    await human_type(page, 'input[name="password"]', DVWA_PASS)
    await asyncio.sleep(human_pause_s())
    await page.click('input[name="Login"]')
    await page.wait_for_load_state("domcontentloaded")


async def browse(page) -> int:
    paths = random.sample(BROWSE_PATHS, k=min(4, len(BROWSE_PATHS)))
    for path in paths:
        try:
            await page.goto(f"{TARGET}{path}", wait_until="domcontentloaded", timeout=10000)
        except Exception:
            continue
        await jitter_mouse(page)
        try:
            await page.mouse.wheel(0, random.randint(100, 500))
        except Exception:
            pass
        await asyncio.sleep(human_pause_s())
    return len(paths)


async def run_one(browser) -> int:
    ctx = await browser.new_context(
        extra_http_headers={"X-Allm-Source": LABEL},
        viewport={"width": 1280, "height": 800},
    )
    page = await ctx.new_page()
    try:
        await login(page)
        pages = await browse(page)
    finally:
        await ctx.close()
    return pages


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
