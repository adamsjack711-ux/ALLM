"""CI / monitoring health probe.

GitHub webhook checks, GitLab runners, internal CI health pings — same
pattern: a UA like `GitHub-Hookshot/<sha>`, repeated GETs on /health,
/healthz, /ping, sometimes /. Single-URL polling but at a higher
cadence than uptime monitoring.
"""

from __future__ import annotations

import httpx

from benign_bots._common import loop, start_session

UA = "GitHub-Hookshot/abc1234"
HEALTH_PATHS = ["/health", "/healthz", "/ping", "/"]
INTERVAL_S = 0.5
ROUNDS = 5


def _probe(client: httpx.Client) -> int:
    n = 0
    for path in HEALTH_PATHS:
        try:
            client.get(path)
            n += 1
        except httpx.HTTPError:
            continue
    return n


def run_session(target: str) -> int:
    client, _ = start_session(
        target,
        family="ci_health_check",
        user_agent=UA,
        config={"paths": HEALTH_PATHS, "interval_s": INTERVAL_S, "rounds": ROUNDS},
    )
    with client:
        return loop(ROUNDS, INTERVAL_S, lambda i: _probe(client))
