"""RSS reader — polls a handful of feed paths on a slow cadence.

Most of these 404 on DVWA. That's the correct behavior: real RSS
readers blindly probe `/feed`, `/rss`, `/atom.xml`, `/index.xml` and
take whatever they find. The 404 ratio is itself a useful negative
feature for the detector — and a notable benign signal that would
otherwise look agent-like (high 4xx rate).
"""

from __future__ import annotations

import httpx

from benign_bots._common import loop, start_session

UA = "Feedfetcher-Google; (+http://www.google.com/feedfetcher.html)"
FEED_PATHS = ["/feed", "/rss", "/atom.xml", "/index.xml", "/feed.xml"]
INTERVAL_S = 2.0


def _poll(client: httpx.Client) -> int:
    n = 0
    for path in FEED_PATHS:
        try:
            client.get(path)
            n += 1
        except httpx.HTTPError:
            continue
    return n


def run_session(target: str) -> int:
    client, _ = start_session(
        target,
        family="rss_reader",
        user_agent=UA,
        config={"paths": FEED_PATHS, "interval_s": INTERVAL_S},
    )
    with client:
        return loop(2, INTERVAL_S, lambda i: _poll(client))
