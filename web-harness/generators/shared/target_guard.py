"""Loopback-only target guard for traffic generators.

Every generator must call `get_target()` instead of accepting URLs from CLI.
The target is read from the `CERNIS_TARGET` env var and the host must be one
of an allow-list: the docker network aliases for the capture proxies, or
a loopback name (127.0.0.1 / ::1 / localhost). Any non-http(s) scheme or
unlisted host hard-exits the process before any network I/O happens.

The detector lab is intentionally pointed at bundled deliberately-vulnerable
targets (DVWA, Juice Shop, WebGoat, VAmPI, crAPI) only; externally-supplied
targets must be rejected in code, not just by docs.
"""

from __future__ import annotations

import os
import sys
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({
    # phase 1: original DVWA capture (kept for back-compat with existing generators)
    "capture",
    # phase 7: per-target captures — each fronts one intentionally-vulnerable app
    "capture_dvwa", "capture_juiceshop", "capture_webgoat", "capture_vampi",
    # phase 12: crAPI (OWASP API security demo; multi-microservice)
    "capture_crapi",
    # loopback aliases for host-side scripts
    "127.0.0.1", "::1", "localhost",
})


def assert_loopback_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise SystemExit(
            f"[target_guard] disallowed scheme {parsed.scheme!r} in target {url!r}"
        )
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise SystemExit(
            f"[target_guard] target host {host!r} not in allow-list "
            f"{sorted(ALLOWED_HOSTS)}; refusing to send traffic to {url!r}"
        )
    return url.rstrip("/")


def get_target() -> str:
    url = os.environ.get("CERNIS_TARGET", "").strip()
    if not url:
        raise SystemExit("[target_guard] CERNIS_TARGET env var is required")
    target = assert_loopback_target(url)
    print(f"[target_guard] CERNIS_TARGET={target} (allowed)", file=sys.stderr)
    return target


if __name__ == "__main__":
    print(get_target())
