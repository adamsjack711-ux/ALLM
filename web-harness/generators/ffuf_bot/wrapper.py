"""ffuf fuzzer wrapper.

Runs ffuf in path-fuzzing mode against the target. ffuf's `-H` flag
sets headers on every fuzz request, so X-Cernis-* labels travel with the
scan natively (no proxy schema cache needed here).

Two-phase per session:
  1. Bootstrap session via httpx (one request) + write provenance.
  2. Run ffuf with the captured cernis_sid cookie + X-Cernis-* headers +
     a small wordlist. ffuf does the rest.

Stealth mode lowers the rate (-rate 5 instead of -rate 50) and shrinks
the wordlist.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import time

import httpx

sys.path.insert(0, "/app/shared")
from manifest import build_payload, headers_for, record_provenance_httpx  # noqa: E402
from target_guard import get_target  # noqa: E402

LABEL = "ffuf"
TARGET = get_target()
TARGET_APP = os.environ.get("CERNIS_TARGET_APP", "dvwa").strip().lower()
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
SESSIONS = int(os.environ.get("CERNIS_SESSIONS", "2"))
STEALTH = os.environ.get("CERNIS_STEALTH", "false").strip().lower() in (
    "1", "true", "yes",
)
FFUF_TIMEOUT_S = int(os.environ.get("FFUF_TIMEOUT_S", "180"))
WORDLIST = pathlib.Path("/app/ffuf_bot/wordlist.txt")


def _bootstrap_session(payload: dict) -> str:
    """Mint cernis_sid + write provenance; return cookie string for ffuf."""
    headers = headers_for(payload) | {"User-Agent": "ffuf/2.1"}
    with httpx.Client(base_url=TARGET, headers=headers,
                      timeout=10.0, follow_redirects=False) as client:
        try:
            client.head("/")
        except httpx.HTTPError as exc:
            print(f"[ffuf] bootstrap HEAD failed: {exc}", flush=True)
        record_provenance_httpx(client, TARGET, payload)
        return "; ".join(f"{k}={v}" for k, v in client.cookies.items())


def _ffuf_cmd(cookie_hdr: str, label_headers: dict) -> list[str]:
    base = [
        "ffuf",
        "-u", f"{TARGET}/FUZZ",
        "-w", str(WORDLIST),
        "-mc", "200,204,301,302,307,401,403",
        "-t", "1" if STEALTH else "10",
        "-rate", "5" if STEALTH else "50",
        "-timeout", "10",
        "-s",  # silent
    ]
    for h, v in label_headers.items():
        base.extend(["-H", f"{h}: {v}"])
    if cookie_hdr:
        base.extend(["-H", f"Cookie: {cookie_hdr}"])
    base.extend(["-H", "User-Agent: ffuf/2.1"])
    return base


def run_session(i: int) -> int:
    payload = build_payload(
        klass="agent", family=LABEL, target_app=TARGET_APP,
        security_level=SECURITY_LEVEL, stealth=STEALTH,
        generator="ffuf", generator_version="0.1.0",
        generator_config={
            "tool": "ffuf", "rate": (5 if STEALTH else 50),
            "wordlist": "small_30", "stealth": STEALTH,
        },
    )
    cookie_hdr = _bootstrap_session(payload)
    cmd = _ffuf_cmd(cookie_hdr, headers_for(payload))
    print(f"[ffuf] session {i + 1}/{SESSIONS} {' '.join(cmd[:6])}…",
          flush=True)
    cp = subprocess.run(cmd, capture_output=True, text=True,
                        timeout=FFUF_TIMEOUT_S)
    found = sum(1 for line in cp.stdout.splitlines() if line.strip())
    print(f"[ffuf] session {i + 1} exit={cp.returncode} found_lines={found}",
          flush=True)
    return 1


def main() -> int:
    mode = "stealth" if STEALTH else "fast"
    print(f"[{LABEL}] target={TARGET} target_app={TARGET_APP} "
          f"mode={mode} sessions={SESSIONS}", flush=True)
    for i in range(SESSIONS):
        t0 = time.time()
        run_session(i)
        print(f"[{LABEL}] session {i + 1} took={time.time() - t0:.1f}s",
              flush=True)
    print(f"[{LABEL}] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
