"""Selenium spray-bot — Chromium driven via chromedriver (not Playwright).

Different fingerprint than playwright_bot/bot.py even though both render
through Chromium: Selenium uses chromedriver (W3C WebDriver protocol)
where Playwright uses CDP directly. The HTTP request stack and timing
characteristics differ in ways that show up in the per-request log
(navigation timing, header set, fetch initiator) — that's the point.

We use Chrome DevTools Protocol via `execute_cdp_cmd` to set the
X-Allm-* labels as extra HTTP headers on every subsequent request, so
the capture proxy keys the session correctly. Provenance is written
via `fetch` from inside the browser, which inherits the same cookie
jar (and therefore the same allm_sid the proxy minted on first nav).
"""

from __future__ import annotations

import json
import os
import random
import sys
import time

import httpx  # noqa: F401  # available for follow-up scripts; not used directly here

sys.path.insert(0, "/app/shared")
from manifest import build_payload, headers_for  # noqa: E402
from target_guard import get_target  # noqa: E402

from selenium import webdriver  # noqa: E402
from selenium.webdriver.chrome.options import Options  # noqa: E402
from selenium.webdriver.chrome.service import Service  # noqa: E402
from selenium.webdriver.common.by import By  # noqa: E402
from selenium.common.exceptions import (  # noqa: E402
    NoSuchElementException, TimeoutException, WebDriverException,
)

LABEL = "selenium_bot"
TARGET = get_target()
TARGET_APP = os.environ.get("ALLM_TARGET_APP", "dvwa").strip().lower()
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
SESSIONS = int(os.environ.get("ALLM_SESSIONS", "3"))
DVWA_USER = os.environ.get("DVWA_USER", "admin")
DVWA_PASS = os.environ.get("DVWA_PASS", "password")

PAYLOADS = [
    "1' OR '1'='1",
    "<script>alert(1)</script>",
    "'; DROP TABLE users--",
    "<img src=x onerror=alert(1)>",
    "1 UNION SELECT user,password FROM users--",
]

VULN_PATHS = [
    "/vulnerabilities/sqli/",
    "/vulnerabilities/xss_r/",
    "/vulnerabilities/xss_s/",
    "/vulnerabilities/exec/",
]


def _make_driver(label_headers: dict) -> webdriver.Chrome:
    opts = Options()
    opts.binary_location = os.environ.get("CHROME_BIN", "/usr/bin/chromium")
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,800")
    service = Service(os.environ.get("CHROMEDRIVER_BIN", "/usr/bin/chromedriver"))
    driver = webdriver.Chrome(service=service, options=opts)
    # set X-Allm-* on every subsequent request via CDP
    driver.execute_cdp_cmd("Network.enable", {})
    driver.execute_cdp_cmd("Network.setExtraHTTPHeaders", {"headers": label_headers})
    return driver


def _record_provenance_in_browser(driver: webdriver.Chrome, payload: dict) -> None:
    """POST /__provenance from inside the page so the allm_sid cookie travels."""
    script = """
    const payload = arguments[0];
    const done = arguments[1];
    fetch('/__provenance', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload),
        credentials: 'include',
    }).then(r => done(r.status)).catch(_ => done(0));
    """
    driver.set_script_timeout(8)
    try:
        driver.execute_async_script(script, payload)
    except (TimeoutException, WebDriverException) as exc:
        print(f"[{LABEL}] provenance write failed (continuing): {exc}", flush=True)


def _login_dvwa(driver: webdriver.Chrome) -> None:
    driver.get(f"{TARGET}/login.php")
    driver.find_element(By.NAME, "username").send_keys(DVWA_USER)
    driver.find_element(By.NAME, "password").send_keys(DVWA_PASS)
    driver.find_element(By.NAME, "Login").click()
    time.sleep(0.5)


def _attack_page(driver: webdriver.Chrome, path: str) -> None:
    try:
        driver.get(f"{TARGET}{path}")
    except WebDriverException:
        return
    selectors = ('input[type="text"]', "textarea")
    payload = random.choice(PAYLOADS)
    for sel in selectors:
        try:
            inputs = driver.find_elements(By.CSS_SELECTOR, sel)
        except NoSuchElementException:
            continue
        for inp in inputs:
            try:
                inp.clear()
                inp.send_keys(payload)
            except WebDriverException:
                pass
    try:
        submit = driver.find_element(
            By.CSS_SELECTOR,
            'input[type="submit"], button[type="submit"]',
        )
        submit.click()
        time.sleep(0.2)
    except (NoSuchElementException, WebDriverException):
        pass


def run_session(i: int) -> int:
    payload = build_payload(
        klass="agent", family=LABEL, target_app=TARGET_APP,
        security_level=SECURITY_LEVEL, stealth=False,
        generator="selenium_bot", generator_version="0.1.0",
        generator_config={"engine": "selenium", "paths": VULN_PATHS},
    )
    label_headers = headers_for(payload)
    driver = _make_driver(label_headers)
    n_pages = 0
    try:
        # nav to root first so the proxy mints allm_sid + provenance writes
        # into a real session
        driver.get(f"{TARGET}/")
        _record_provenance_in_browser(driver, payload)

        if TARGET_APP == "dvwa":
            _login_dvwa(driver)
            for path in VULN_PATHS:
                _attack_page(driver, path)
                n_pages += 1
        else:
            # for non-DVWA targets, just walk a couple of likely-vulnerable
            # endpoints. Phase 2 leaves real per-target attack scripts to
            # the next sweep — this session still produces label-correct
            # negative-class browser traffic that the detector consumes.
            for path in ("/", "/login", "/api"):
                try:
                    driver.get(f"{TARGET}{path}")
                    n_pages += 1
                except WebDriverException:
                    continue
    finally:
        try:
            driver.quit()
        except WebDriverException:
            pass
    return n_pages


def main() -> int:
    print(f"[{LABEL}] target={TARGET} target_app={TARGET_APP} "
          f"sessions={SESSIONS}", flush=True)
    for i in range(SESSIONS):
        t0 = time.time()
        pages = run_session(i)
        print(
            f"[{LABEL}] session {i + 1}/{SESSIONS} pages={pages} "
            f"took={time.time() - t0:.1f}s",
            flush=True,
        )
    print(f"[{LABEL}] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
