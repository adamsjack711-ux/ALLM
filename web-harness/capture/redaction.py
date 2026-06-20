"""Anonymization helpers for the human-real capture channel.

The capture proxy's :8090 listener writes rows tagged class=human /
family=human_real. Those rows are anonymized at write time so the
benchmark dataset never gains a path back to a specific person:

  - source IP: dropped (set to None)
  - User-Agent: replaced with a coarse browser-family + device-type
    bucket, derived once and discarded

Bodies are already not logged anywhere; auth/cookie are already stored
as has_*_header booleans rather than values. This module handles the
two remaining surfaces (IP + UA) that the per-row writer still touches.

Keeping the bucket coarse is deliberate: a 6-bin UA bucket can't
re-identify a person, but it preserves the only UA-derived feature the
detector cares about (broad browser family vs not-a-browser).
"""

from __future__ import annotations

import re

# Six buckets cover ~all real-world browser/device combinations seen in
# DVWA / Juice Shop / WebGoat / VAmPI sessions. Anything we can't
# classify falls into "other" rather than leaking the raw UA.
BROWSER_BUCKETS = (
    "chrome-desktop", "chrome-mobile",
    "firefox-desktop", "firefox-mobile",
    "safari-desktop", "safari-mobile",
    "other",
)

# Order matters: Edge/Brave/Opera all advertise "Chrome" in their UA,
# so we check the more specific brands first. Mobile detection runs
# before family detection because the device-type axis is independent
# of the browser-engine axis.
_MOBILE_HINTS = re.compile(r"\b(iPhone|iPad|iPod|Android|Mobile|Mobi)\b", re.I)
_FIREFOX = re.compile(r"\bFirefox/", re.I)
_SAFARI = re.compile(r"\bSafari/", re.I)
_CHROMIUM_FAMILY = re.compile(r"\b(Chrome|Chromium|Edg|OPR|Brave|CriOS)/", re.I)


def ua_bucket(ua: str | None) -> str:
    """Map a raw User-Agent string to one of seven coarse buckets.

    The output is the only UA-derived value that may persist to the
    benchmark dataset. The input string is never written anywhere.
    """
    if not ua:
        return "other"
    device = "mobile" if _MOBILE_HINTS.search(ua) else "desktop"
    if _FIREFOX.search(ua):
        return f"firefox-{device}"
    if _CHROMIUM_FAMILY.search(ua):
        return f"chrome-{device}"
    # Safari's UA also contains "Safari/" but Chromium UAs include it
    # too — that's why the Chromium check runs first.
    if _SAFARI.search(ua):
        return f"safari-{device}"
    return "other"


def redact_ip(_ip: str | None) -> None:
    """The human-real channel never stores a source IP.

    Returns None unconditionally so callers don't need to special-case
    the absence (request.remote is occasionally None already).
    """
    return None
