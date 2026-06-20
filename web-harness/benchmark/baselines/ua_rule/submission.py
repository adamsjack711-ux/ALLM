"""Trivial floor baseline: score by the UA bucket recorded per request.

The proxy hashes the User-Agent into a single coarse float (`ua_bucket`
in detector/features.py):
  1.0  Chrome / Chromium
  0.6  Mozilla (Firefox, Safari, anything else with the Mozilla token)
  0.3  curl / python / wget          ← classic tool fingerprints
  0.1  everything else               ← exotic clients

This baseline votes "agent" when the modal UA bucket is one of the two
tool buckets (0.3 / 0.1) — exactly what the rule-based detectors of
ten years ago do. Real browser-driven agents (playwright / selenium /
puppeteer) all advertise Chrome and SHOULD slip past this floor; that
gap is the point of having the baseline. No training.
"""

from __future__ import annotations

import statistics


# Map modal UA bucket → agent score. Picked so that:
#  - Chrome-only sessions score low (would be a real-browser human OR a
#    headless-browser agent; this baseline can't tell)
#  - Mozilla-only sessions score slightly higher (less common today)
#  - curl/python/wget sessions score high (rare for humans)
#  - Other sessions score medium-high (unknown clients lean suspicious)
_BUCKET_TO_SCORE = [
    (0.20, 0.05),   # ≤0.20 (other-low) → low confidence not enough for "agent"
    (0.40, 0.90),   # 0.30 ± 0.10 → curl/python/wget → high agent score
    (0.80, 0.20),   # 0.60 → Mozilla → mild
    (1.10, 0.10),   # 1.00 → Chrome → low (most common across all classes)
]


def _modal_bucket(seq: list[list[float]]) -> float:
    """ua_bucket lives at column 6 of the per-request feature vector
    (see detector/features.py::_req_features). Most-common value wins."""
    if not seq:
        return 1.0  # default to Chrome → low score
    buckets = [round(row[6], 1) for row in seq]
    try:
        return statistics.mode(buckets)
    except statistics.StatisticsError:
        return buckets[0]


def _score_for(bucket: float) -> float:
    for ceiling, score in _BUCKET_TO_SCORE:
        if bucket <= ceiling:
            return score
    return 0.10


def predict(features: list[dict]) -> list[dict]:
    return [
        {
            "session_id": f["session_id"],
            "agent_score": _score_for(_modal_bucket(f["seq"])),
        }
        for f in features
    ]
