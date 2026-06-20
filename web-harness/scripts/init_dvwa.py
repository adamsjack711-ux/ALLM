"""Initialise DVWA's database via /setup.php (idempotent).

The official DVWA docker image does not auto-create the DB on first boot;
visiting /setup.php and POSTing `create_db=Create / Reset Database` is
required before login works. This script does that against the bundled
DVWA through the capture proxy (so the init traffic is logged like
everything else). Re-running is safe — it just resets the DB.
"""

from __future__ import annotations

import http.cookiejar as cj
import re
import sys
import time
import urllib.parse
import urllib.request as ur

TARGET = "http://127.0.0.1:8090"
SETUP = f"{TARGET}/setup.php"


def main() -> int:
    jar = cj.CookieJar()
    opener = ur.build_opener(ur.HTTPCookieProcessor(jar))
    opener.addheaders = [("User-Agent", "cernis-init/1.0")]

    end = time.time() + 60
    while time.time() < end:
        try:
            page = opener.open(SETUP, timeout=10).read().decode("utf-8", "replace")
            break
        except Exception as exc:
            print(f"[init] setup.php not ready: {exc}; retrying", file=sys.stderr)
            time.sleep(2)
    else:
        print("[init] timed out waiting for setup.php", file=sys.stderr)
        return 2

    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", page)
    if not m:
        m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", page)
    user_token = m.group(1) if m else ""

    body = urllib.parse.urlencode({
        "create_db": "Create / Reset Database",
        "user_token": user_token,
    }).encode()

    req = ur.Request(
        SETUP,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = opener.open(req, timeout=60).read().decode("utf-8", "replace")
    if "Setup successful" in resp or "Database has been created" in resp:
        print("[init] DVWA DB created ✅", flush=True)
        return 0
    if "Could not connect" in resp or "Access denied" in resp:
        print("[init] DB connection failed; check db service", file=sys.stderr)
        return 3
    print("[init] DB setup response did not include success marker — likely already created", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
