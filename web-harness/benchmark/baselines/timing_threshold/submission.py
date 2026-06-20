"""Trivial floor baseline: score by median inter-request cadence.

Bots that don't bother with stealth click ~10× faster than humans. This
baseline takes the median delta_ms across the session's request sequence
and applies a sigmoid centered around the human/bot boundary (≈ 500 ms).

This is the second classic non-ML rule (after "is the UA suspicious").
It collapses on the stealth variants of every agent (the whole point of
stealth is to slow cadence into the human range), which is why we want
it as a floor — to show the gap. No training.
"""

from __future__ import annotations

import math
import statistics


# Median delta_ms below this → leaning agent. Boundary is the human-vs-
# bot inflection observed in the seed-0 capture.
_BOUNDARY_MS = 500.0
# Steepness of the sigmoid in log-space. log1p(500) ≈ 6.21.
_LOG_BOUNDARY = math.log1p(_BOUNDARY_MS)
_SCALE = 1.5


def _median_delta_ms(seq: list[list[float]]) -> float:
    """Column 0 of the per-request vector is `log1p(delta_ms)` (see
    detector/features.py::_req_features). We work in log-space so a
    single fast burst doesn't drag the median into the agent bin."""
    if not seq:
        return _LOG_BOUNDARY
    return float(statistics.median(row[0] for row in seq))


def _score_for(median_log_delta: float) -> float:
    # Logistic centered at the boundary: faster cadence → higher score.
    return float(1.0 / (1.0 + math.exp((median_log_delta - _LOG_BOUNDARY) / _SCALE)))


def predict(features: list[dict]) -> list[dict]:
    return [
        {
            "session_id": f["session_id"],
            "agent_score": _score_for(_median_delta_ms(f["seq"])),
        }
        for f in features
    ]
