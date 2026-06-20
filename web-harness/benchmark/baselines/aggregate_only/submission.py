"""Aggregate-only baseline: sklearn LogisticRegression on the 12-dim
session aggregate vector.

No sequence model, no honeypot signal — just the session-level summary
features (request volume, cadence stats, path breadth, error rates,
beacon-derived timings). Tests the hypothesis "is the session-level
summary alone enough to separate agents from humans / benign bots?"

This is the simplest baseline that actually fits a model. Useful for
isolating how much lift the GRU + honeypot inputs add on top of the
aggregates.
"""

from __future__ import annotations

from typing import Optional

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler


_model: Optional[LogisticRegression] = None
_scaler: Optional[StandardScaler] = None


def _stack_agg(rows: list[dict]) -> np.ndarray:
    return np.array([r["agg"] for r in rows], dtype=np.float32)


def train(train_features: list[dict], dev_features: list[dict]) -> None:
    global _model, _scaler
    X = _stack_agg(train_features)
    y = np.array([int(r["y"]) for r in train_features])

    if y.sum() == 0 or y.sum() == y.size:
        # Single-class train (smoke can land here on tiny synth data).
        # Fit a no-op model that always predicts the majority class.
        _scaler = None
        _model = None
        return

    _scaler = StandardScaler().fit(X)
    Xs = _scaler.transform(X)
    _model = LogisticRegression(
        max_iter=1000, C=1.0, solver="lbfgs", random_state=0,
    )
    _model.fit(Xs, y)


def predict(features: list[dict]) -> list[dict]:
    if _model is None or _scaler is None:
        # Untrained / degenerate-fit fallback: emit 0.5 for everything.
        return [
            {"session_id": f["session_id"], "agent_score": 0.5}
            for f in features
        ]
    X = _stack_agg(features)
    Xs = _scaler.transform(X)
    probs = _model.predict_proba(Xs)[:, 1]
    return [
        {"session_id": f["session_id"], "agent_score": float(p)}
        for f, p in zip(features, probs)
    ]
