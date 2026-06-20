"""Trivial floor baseline: score = 1 if any honeypot tripped, else 0.

The capture proxy has four honeypot routes (canary, invisible_field,
admin_secrets, robots_read). This baseline says "if you tripped any of
them, you're an agent; otherwise you're not." Its precision is whatever
the trip-precision is; its recall is bounded by honeypot coverage.

Useful as a floor: it's exactly what a 5-line ops rule would do without
any model at all. No training.
"""

from __future__ import annotations


def _hp_score(hp: list[float]) -> float:
    if not hp:
        return 0.0
    return 0.95 if max(hp) > 0.0 else 0.05


def predict(features: list[dict]) -> list[dict]:
    return [
        {"session_id": f["session_id"], "agent_score": _hp_score(f["hp"])}
        for f in features
    ]
