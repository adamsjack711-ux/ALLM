"""Uptime monitor — periodic HEAD + GET on the root, single URL.

Realistic uptime services (UptimeRobot, Pingdom) hit one endpoint on a
fixed cadence. We send several samples per session so the per-request
cadence is the dominant feature.
"""

from __future__ import annotations

import httpx

from benign_bots._common import loop, start_session

UA = "Mozilla/5.0 (compatible; UptimeRobot/2.0; +http://www.uptimerobot.com/)"
SAMPLES = 6
INTERVAL_S = 1.5
PATH = "/"


def _ping(client: httpx.Client) -> int:
    n = 0
    try:
        client.head(PATH)
        n += 1
    except httpx.HTTPError:
        pass
    try:
        client.get(PATH)
        n += 1
    except httpx.HTTPError:
        pass
    return n


def run_session(target: str) -> int:
    client, _ = start_session(
        target,
        family="uptime_monitor",
        user_agent=UA,
        config={"path": PATH, "samples": SAMPLES, "interval_s": INTERVAL_S},
    )
    with client:
        return loop(SAMPLES, INTERVAL_S, lambda i: _ping(client))
