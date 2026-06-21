"""Reference container submission — a trivial floor baseline.

Mirrors the Python-entrypoint `benchmark/baselines/ua_rule/submission.py`
contract so a submitter can see how the in-process flavor maps to the
container flavor without any code changes. The actual model logic
(scoring by modal UA bucket) lives here; the runner.py wrapper handles
I/O to the bind-mounted /in and /out directories.

Replace this with your real model. The only requirement is that
`predict(features) -> list[{session_id, agent_score}]` matches the
contract documented in `benchmark/SUBMISSION.md`.

`train()` is optional. When you do implement it, write all state to
module-level variables (or attributes on an object stashed there) —
the runner imports this module once per container run.
"""

from __future__ import annotations

import statistics


_BUCKET_TO_SCORE = [
    (0.20, 0.05),
    (0.40, 0.90),
    (0.80, 0.20),
    (1.10, 0.10),
]


def _modal_bucket(seq: list[list[float]]) -> float:
    if not seq:
        return 1.0
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
