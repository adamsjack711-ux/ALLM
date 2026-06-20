"""Shared bootstrap for benign_bot families.

Every family follows the same shape:
  - open a fresh httpx.Client (= new cernis_sid cookie when the proxy
    mints one on the first request),
  - make one trivial GET to materialize the cookie,
  - POST /__provenance with the family's labels + config,
  - run the family's traffic pattern.

The bots are intentionally non-stealthy: their User-Agent and X-Cernis-*
headers truthfully identify what they are. Stealth variants land in
phase 2 (and set stealth=true in the manifest).
"""

from __future__ import annotations

import sys
import time
from typing import Callable

import httpx

sys.path.insert(0, "/app/shared")  # noqa: E402
from manifest import (  # noqa: E402
    build_payload,
    headers_for,
    record_provenance_httpx,
)

__version__ = "0.1.0"


def start_session(
    target: str,
    *,
    family: str,
    user_agent: str,
    config: dict,
    target_app: str = "dvwa",
    security_level: str = "na",
    stealth: bool = False,
    generator: str | None = None,
) -> tuple[httpx.Client, dict]:
    payload = build_payload(
        klass="benign_bot",
        family=family,
        target_app=target_app,
        security_level=security_level,
        stealth=stealth,
        generator=generator or family,
        generator_version=__version__,
        generator_config=config,
    )
    headers = headers_for(payload) | {"User-Agent": user_agent}
    client = httpx.Client(
        base_url=target,
        headers=headers,
        timeout=10.0,
        follow_redirects=False,
    )
    # Materialize the cernis_sid cookie before the provenance POST so the
    # proxy can key it correctly. A HEAD on / is the cheapest path.
    try:
        client.head("/")
    except httpx.HTTPError as exc:
        print(f"[benign_bots] bootstrap HEAD failed: {exc}", flush=True)
    record_provenance_httpx(client, target, payload)
    return client, payload


def loop(
    n: int, interval_s: float, fn: Callable[[int], int]
) -> int:
    total = 0
    for i in range(n):
        try:
            total += int(fn(i) or 0)
        except httpx.HTTPError as exc:
            print(f"[benign_bots] iter {i} HTTP error (continuing): {exc}", flush=True)
        if interval_s > 0 and i < n - 1:
            time.sleep(interval_s)
    return total
