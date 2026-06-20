"""sqlmap scanner — non-browser HTTP attacker.

For DVWA: logs in (POSTs login.php with the CSRF token), flips the
security cookie to the configured level, then runs sqlmap against
/vulnerabilities/sqli/ with the captured cookie jar.

For VAmPI: skips login (VAmPI's vulnerable endpoints are unauthenticated)
and points sqlmap at one of the known SQLi-vulnerable paths.

Key properties for the detector:
  - no browser, no JS execution -> the beacon-derived feature block
    goes to zero for these sessions, which is the right negative signal
    for the no-DOM-target class.
  - sqlmap's per-request cadence is machine-fast and structurally
    repetitive — distinct shape from Playwright and Puppeteer.
  - the X-Allm-* labels travel on every request via the `-H` flag, so
    the proxy still keys class / family / target_app correctly.

Provenance is registered by the wrapper (sqlmap itself doesn't speak
our manifest endpoint).
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import httpx

sys.path.insert(0, "/app/shared")
from manifest import build_payload, headers_for, record_provenance_httpx  # noqa: E402
from target_guard import get_target  # noqa: E402

LABEL = "sqlmap"
TARGET = get_target()
TARGET_APP = os.environ.get("ALLM_TARGET_APP", "dvwa").strip().lower()
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
SESSIONS = int(os.environ.get("ALLM_SESSIONS", "2"))
DVWA_USER = os.environ.get("DVWA_USER", "admin")
DVWA_PASS = os.environ.get("DVWA_PASS", "password")
SQLMAP_TIMEOUT_S = int(os.environ.get("SQLMAP_TIMEOUT_S", "300"))
STEALTH = os.environ.get("ALLM_STEALTH", "false").strip().lower() in (
    "1", "true", "yes",
)
# Stealth knobs: real-browser UA, --delay 3 between requests (sub-machine-
# fast cadence), --level=1 --risk=1 (less aggressive payload set), single
# session per generator run.
STEALTH_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


_TOKEN_RE = re.compile(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']')


def _token(html: str) -> str:
    m = _TOKEN_RE.search(html)
    return m.group(1) if m else ""


def _dvwa_login_and_cookies(client: httpx.Client) -> str:
    """Login + security-level set; returns a cookie string sqlmap can use."""
    r = client.get("/login.php")
    client.post("/login.php", data={
        "username": DVWA_USER, "password": DVWA_PASS, "Login": "Login",
        "user_token": _token(r.text),
    })
    r = client.get("/security.php")
    client.post("/security.php", data={
        "security": SECURITY_LEVEL, "seclev_submit": "Submit",
        "user_token": _token(r.text),
    })
    return "; ".join(f"{k}={v}" for k, v in client.cookies.items())


def _target_url(target_app: str) -> str:
    if target_app == "dvwa":
        return f"{TARGET}/vulnerabilities/sqli/?id=1&Submit=Submit"
    if target_app == "vampi":
        return f"{TARGET}/users/v1/_debug"
    if target_app == "juice_shop":
        # juice shop search endpoint is the canonical sqli example
        return f"{TARGET}/rest/products/search?q=apple"
    raise SystemExit(f"[sqlmap] unsupported target_app={target_app!r}")


def _sqlmap_cmd(target_url: str, cookie_hdr: str, label_headers: dict) -> list[str]:
    if STEALTH:
        cmd = [
            "sqlmap",
            "-u", target_url,
            "--batch",
            "--level=1",
            "--risk=1",
            "--threads=1",
            "--delay=3",
            "--timeout=15",
            "--retries=1",
            "--user-agent", STEALTH_UA,
        ]
    else:
        cmd = [
            "sqlmap",
            "-u", target_url,
            "--batch",
            "--level=2",
            "--risk=2",
            "--smart",
            "--threads=4",
            "--timeout=10",
            "--retries=1",
            "--user-agent", "sqlmap/1.7",
        ]
    if cookie_hdr:
        cmd.extend(["--cookie", cookie_hdr])
    for h, v in label_headers.items():
        cmd.extend(["-H", f"{h}: {v}"])
    return cmd


def run_session(i: int) -> int:
    config = (
        {"target_app": TARGET_APP, "level": 1, "risk": 1, "delay_s": 3,
         "threads": 1, "stealth": True}
        if STEALTH else
        {"target_app": TARGET_APP, "level": 2, "risk": 2, "smart": True,
         "threads": 4, "stealth": False}
    )
    payload = build_payload(
        klass="agent", family=LABEL, target_app=TARGET_APP,
        security_level=SECURITY_LEVEL, stealth=STEALTH,
        generator="sqlmap", generator_version="0.2.0",
        generator_config=config,
    )
    label_headers = headers_for(payload)
    request_headers = label_headers | {
        "User-Agent": STEALTH_UA if STEALTH else "sqlmap/1.7"
    }

    with httpx.Client(
        base_url=TARGET, headers=request_headers,
        timeout=15.0, follow_redirects=False,
    ) as client:
        # mint allm_sid + register provenance
        try:
            client.head("/")
        except httpx.HTTPError as exc:
            print(f"[sqlmap] bootstrap HEAD failed: {exc}", flush=True)
        record_provenance_httpx(client, TARGET, payload)

        if TARGET_APP == "dvwa":
            cookie_hdr = _dvwa_login_and_cookies(client)
        else:
            # carry the allm_sid the proxy just minted so sqlmap's requests
            # still land in the same session
            cookie_hdr = "; ".join(f"{k}={v}" for k, v in client.cookies.items())

    target_url = _target_url(TARGET_APP)
    cmd = _sqlmap_cmd(target_url, cookie_hdr, label_headers)
    print(f"[sqlmap] session {i + 1}/{SESSIONS} target={target_url}", flush=True)
    cp = subprocess.run(
        cmd, capture_output=True, text=True, timeout=SQLMAP_TIMEOUT_S,
    )
    print(f"[sqlmap] session {i + 1} exit={cp.returncode}", flush=True)
    if cp.returncode != 0:
        # sqlmap exits non-zero often (no injection found, etc) — that's
        # fine, the request traffic is what we want regardless.
        tail = cp.stdout.splitlines()[-3:] if cp.stdout else []
        for line in tail:
            print(f"[sqlmap]   {line}", flush=True)
    return 1


def main() -> int:
    mode = "stealth" if STEALTH else "fast"
    print(f"[{LABEL}] target={TARGET} target_app={TARGET_APP} "
          f"mode={mode} sessions={SESSIONS}", flush=True)
    for i in range(SESSIONS):
        run_session(i)
    print(f"[{LABEL}] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
