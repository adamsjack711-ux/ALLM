"""Dispatcher for the benign_bot generator family.

Reads `ALLM_BENIGN_BOT` from env and runs one of:
  - googlebot    : crawler that obeys robots.txt and walks Disallow paths
  - uptime       : HEAD+GET / on a fixed cadence
  - rss          : periodic GETs of feed paths
  - unfurl       : Slack/Discord-style single-URL preview
  - ci           : repeated GETs of /health endpoints

Each one:
  1. starts a session against the capture proxy,
  2. POSTs one provenance row keyed on its allm_sid cookie,
  3. sets the X-Allm-* label-schema headers on every request,
  4. loops `ALLM_SESSIONS` times.

These are all non-browser HTTP clients (no JS execution), which is the
honest fingerprint for these benign-bot families in the wild — the
detector's beacon-based features go to zero for these sessions, and
that's exactly the signal the negative class is supposed to expose.
"""

from __future__ import annotations

import os
import sys
import time

from benign_bots import (
    googlebot_crawler,
    uptime_monitor,
    rss_reader,
    link_unfurler,
    ci_health_check,
)

sys.path.insert(0, "/app/shared")  # noqa: E402
from target_guard import get_target  # noqa: E402

BOTS = {
    "googlebot": googlebot_crawler,
    "uptime": uptime_monitor,
    "rss": rss_reader,
    "unfurl": link_unfurler,
    "ci": ci_health_check,
}


def main() -> int:
    name = os.environ.get("ALLM_BENIGN_BOT", "").strip().lower()
    if name not in BOTS:
        print(
            f"[benign_bots] ALLM_BENIGN_BOT must be one of {sorted(BOTS)}, "
            f"got {name!r}",
            file=sys.stderr,
        )
        return 2
    target = get_target()
    sessions = int(os.environ.get("ALLM_SESSIONS", "5"))
    print(f"[benign_bots] family={name} target={target} sessions={sessions}", flush=True)
    bot = BOTS[name]
    for i in range(sessions):
        t0 = time.time()
        n_req = bot.run_session(target)
        print(
            f"[benign_bots] {name} session {i + 1}/{sessions} "
            f"requests={n_req} took={time.time() - t0:.1f}s",
            flush=True,
        )
    print(f"[benign_bots] {name} done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
