"""Phase-1 verification gate for the capture proxy.

Assumes `docker compose up -d --build` has already been run. Returns 0 on
success and prints PASSED line; raises SystemExit(non-zero) otherwise.
"""

from __future__ import annotations

import http.cookiejar as cj
import json
import pathlib
import socket
import sys
import time
import urllib.error
import urllib.request as ur

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "requests.jsonl"

CAPTURE_PORT = 8090
LEAK_TOKEN = "Bearer SHOULD-NOT-LEAK-c0ffee"


def wait_for_port(host: str, port: int, timeout: float = 60.0) -> None:
    end = time.time() + timeout
    last_err = None
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=2):
                return
        except OSError as exc:
            last_err = exc
            time.sleep(1)
    raise SystemExit(f"[smoke] port {host}:{port} never opened: {last_err}")


def wait_for_html(opener: ur.OpenerDirector, url: str, timeout: float = 60.0):
    """DVWA's container can take a few seconds to come up; retry until HTML."""
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            req = ur.Request(url, headers={
                "Authorization": LEAK_TOKEN,
                "User-Agent": "allm-smoke/1.0",
            })
            resp = opener.open(req, timeout=10)
            body = resp.read()
            ctype = resp.headers.get("Content-Type", "")
            if "text/html" in ctype.lower() and (b"</body>" in body or b"</BODY>" in body):
                return resp, body
            last = f"status={resp.status} ctype={ctype} len={len(body)}"
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            last = repr(exc)
        time.sleep(1)
    raise SystemExit(f"[smoke] never got HTML from {url}; last={last}")


def read_rows() -> list[dict]:
    if not DATA.exists():
        return []
    return [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]


def main() -> None:
    wait_for_port("127.0.0.1", CAPTURE_PORT)
    DATA.parent.mkdir(parents=True, exist_ok=True)
    DATA.write_text("")

    jar = cj.CookieJar()
    opener = ur.build_opener(ur.HTTPCookieProcessor(jar))
    opener.addheaders = []

    r1, body1 = wait_for_html(opener, f"http://127.0.0.1:{CAPTURE_PORT}/login.php")
    sids = [c.value for c in jar if c.name == "allm_sid"]
    assert sids, f"[smoke] no allm_sid cookie minted; jar={[c.name for c in jar]}"
    sid = sids[0]
    assert b"/__beacon.js" in body1, "[smoke] beacon <script src=/__beacon.js> tag missing from HTML"

    time.sleep(0.2)
    req2 = ur.Request(
        f"http://127.0.0.1:{CAPTURE_PORT}/login.php",
        headers={"Authorization": LEAK_TOKEN, "User-Agent": "allm-smoke/1.0"},
    )
    r2 = opener.open(req2, timeout=10)
    r2.read()

    time.sleep(0.4)
    rows = read_rows()
    same_sid = [r for r in rows if r.get("session_id") == sid]
    assert len(same_sid) >= 2, (
        f"[smoke] expected ≥2 rows for sid {sid[:8]}…, got {len(same_sid)} of {len(rows)}: "
        f"{[r.get('path') for r in rows[-5:]]}"
    )

    first = same_sid[0]
    second = same_sid[1]
    assert first.get("delta_ms") is None, f"[smoke] first row delta_ms should be null: {first}"
    delta2 = second.get("delta_ms")
    assert isinstance(delta2, int) and delta2 > 0, f"[smoke] second row delta_ms should be >0: {second}"

    blob = DATA.read_text()
    assert LEAK_TOKEN not in blob, "[smoke] Authorization header value leaked to log"
    for row in rows:
        for k, v in row.items():
            if isinstance(v, str) and LEAK_TOKEN in v:
                raise AssertionError(f"[smoke] leak token found in field {k}")
            if k.lower() in ("authorization", "cookie", "headers"):
                raise AssertionError(f"[smoke] forbidden raw header field {k} in log row")

    assert first.get("has_auth_header") is True, "has_auth_header should be true (we sent one)"

    n_sessions = len({r["session_id"] for r in rows})
    print(
        f"PHASE 1 SMOKE PASSED ✅  sessions={n_sessions}  rows={len(rows)}  "
        f"sid={sid[:8]}…  delta_ms[2nd]={delta2}"
    )


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
