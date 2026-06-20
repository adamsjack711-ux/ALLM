"""nikto wrapper — Perl-based web vuln scanner.

nikto can't easily set per-request X-Cernis-* headers (no first-class
"add header to every probe" flag), so we lean on phase 11's capture
proxy schema cache instead:

  1. Wrapper sends ONE labeled httpx request (HEAD /) that mints the
     cernis_sid cookie. The proxy caches the schema (class / family /
     target_app / security_level / stealth) keyed on that sid.
  2. Wrapper POSTs /__provenance with the same labels → sessions.jsonl
     row written.
  3. Wrapper invokes `nikto -host <target> -Save -useragent nikto/X
     -StaticCookies "cernis_sid=<sid>"`. nikto's many subsequent requests
     share the sid, so the proxy inherits the cached schema onto each
     row.

Stealth mode reduces nikto's plugin set (`-Tuning x6`, which skips
the dangerous-by-default checks) and adds `-Pause 2` for a 2s gap
between probes.
"""

from __future__ import annotations

import os
import subprocess
import sys

import httpx

sys.path.insert(0, "/app/shared")
from manifest import build_payload, headers_for, record_provenance_httpx  # noqa: E402
from target_guard import get_target  # noqa: E402

LABEL = "nikto"
TARGET = get_target()
TARGET_APP = os.environ.get("CERNIS_TARGET_APP", "dvwa").strip().lower()
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
SESSIONS = int(os.environ.get("CERNIS_SESSIONS", "1"))
STEALTH = os.environ.get("CERNIS_STEALTH", "false").strip().lower() in (
    "1", "true", "yes",
)
# nikto is slow even on a small site — bound it to keep smokes / sweeps
# tractable. Default 6 min covers a typical DVWA scan; phase 7 sweep
# can override per-cell.
NIKTO_TIMEOUT_S = int(os.environ.get("NIKTO_TIMEOUT_S", "360"))


def _bootstrap_session(payload: dict) -> str:
    headers = headers_for(payload) | {"User-Agent": "nikto/2.5"}
    with httpx.Client(base_url=TARGET, headers=headers,
                      timeout=10.0, follow_redirects=False) as client:
        try:
            client.head("/")
        except httpx.HTTPError as exc:
            print(f"[nikto] bootstrap HEAD failed: {exc}", flush=True)
        record_provenance_httpx(client, TARGET, payload)
        return client.cookies.get("cernis_sid", "")


def _nikto_cmd(cernis_sid: str) -> list[str]:
    cmd = [
        "nikto",
        "-host", TARGET,
        "-ask", "no",
        "-Display", "P",
        "-nointeractive",
        "-useragent", "nikto/2.5",
        "-output", "/tmp/nikto_out.txt",
    ]
    if cernis_sid:
        cmd.extend(["-StaticCookies", f"cernis_sid={cernis_sid}"])
    if STEALTH:
        # Tuning x6 disables the DoS/dangerous-by-default plugins; -Pause
        # adds a 2s gap between probes (sub-machine-fast cadence).
        cmd.extend(["-Tuning", "x6", "-Pause", "2"])
    return cmd


def run_session(i: int) -> int:
    payload = build_payload(
        klass="agent", family=LABEL, target_app=TARGET_APP,
        security_level=SECURITY_LEVEL, stealth=STEALTH,
        generator="nikto", generator_version="0.1.0",
        generator_config={
            "tool": "nikto", "tuning": ("x6" if STEALTH else "default"),
            "pause_s": (2 if STEALTH else 0), "stealth": STEALTH,
        },
    )
    cernis_sid = _bootstrap_session(payload)
    cmd = _nikto_cmd(cernis_sid)
    print(f"[nikto] session {i + 1}/{SESSIONS} cernis_sid={cernis_sid[:8]}…",
          flush=True)
    cp = subprocess.run(cmd, capture_output=True, text=True,
                        timeout=NIKTO_TIMEOUT_S)
    # nikto exits 1 when it finds vulns — same convention as sqlmap.
    print(f"[nikto] session {i + 1} exit={cp.returncode}", flush=True)
    return 1


def main() -> int:
    mode = "stealth" if STEALTH else "fast"
    print(f"[{LABEL}] target={TARGET} target_app={TARGET_APP} "
          f"mode={mode} sessions={SESSIONS}", flush=True)
    for i in range(SESSIONS):
        try:
            run_session(i)
        except subprocess.TimeoutExpired:
            print(f"[nikto] session {i + 1} timed out at "
                  f"{NIKTO_TIMEOUT_S}s — partial scan still went through",
                  flush=True)
    print(f"[{LABEL}] done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
