"""Hybrid baseline: the in-repo `detector.model.Detector` with
honeypot inputs ON (= `with_hp.pt` in normal training runs).

This is the champion model the host detector ships. Wrapping it as a
submission proves the contract supports the full-stack model and gives
researchers a strong "ceiling" baseline to beat.

Training mirrors `detector/train.py` but trains a single head (no
ml_only ablation) and pulls features straight from the submission
input rather than from `detector.features.build_sessions`.
"""

from __future__ import annotations

import pathlib
import sys
from typing import Optional

import numpy as np
import torch
import torch.nn as nn

# detector/model.py + detector/features.py live two dirs up from a
# baselines/<name>/ submission. Walk up the filesystem to find the
# repo root, then add `detector/` to sys.path so we can reuse the
# Detector class verbatim.
_THIS = pathlib.Path(__file__).resolve()
_REPO_ROOT = _THIS.parent.parent.parent.parent  # web-harness/
sys.path.insert(0, str(_REPO_ROOT / "detector"))

from features import F_HP, F_REQ, F_SESS  # type: ignore  # noqa: E402
from model import Detector, pad_batch as _detector_pad_batch  # type: ignore  # noqa: E402


_model: Optional[Detector] = None
_norm_mean: Optional[np.ndarray] = None
_norm_std: Optional[np.ndarray] = None


class _RowSession:
    """Adapter so the in-repo `pad_batch` (which expects Session-like
    objects) can consume our public-feature dicts."""

    def __init__(self, row: dict, y: int = 0) -> None:
        self.seq = np.array(row["seq"], dtype=np.float32) if row["seq"] else np.zeros((1, F_REQ), dtype=np.float32)
        self.agg = np.array(row["agg"], dtype=np.float32)
        self.hp = np.array(row["hp"], dtype=np.float32)
        self.y = y


def _fit_scaler(rows: list[dict]) -> tuple[np.ndarray, np.ndarray]:
    X = np.stack([np.array(r["agg"], dtype=np.float32) for r in rows], axis=0)
    mean = X.mean(axis=0)
    std = X.std(axis=0)
    std = np.where(std < 1e-6, 1.0, std)
    return mean.astype(np.float32), std.astype(np.float32)


def _normalize(rows: list[dict], mean: np.ndarray, std: np.ndarray) -> list[_RowSession]:
    out: list[_RowSession] = []
    for r in rows:
        adapted = _RowSession(r, y=int(r.get("y", 0)))
        adapted.agg = ((adapted.agg - mean) / std).astype(np.float32)
        out.append(adapted)
    return out


def train(train_features: list[dict], dev_features: list[dict]) -> None:
    global _model, _norm_mean, _norm_std
    torch.manual_seed(0)
    np.random.seed(0)
    if not train_features:
        return

    y_train = np.array([int(r["y"]) for r in train_features])
    if y_train.sum() == 0 or y_train.sum() == y_train.size:
        _model = None
        return

    _norm_mean, _norm_std = _fit_scaler(train_features)
    tr = _normalize(train_features, _norm_mean, _norm_std)
    dv = _normalize(dev_features, _norm_mean, _norm_std) if dev_features else tr

    _model = Detector(
        req_dim=F_REQ, sess_dim=F_SESS, hp_dim=F_HP,
        hidden=64, ablate_hp=False,
    )
    opt = torch.optim.AdamW(_model.parameters(), lr=1e-3)
    loss_fn = nn.BCEWithLogitsLoss()

    best_dev = -1.0
    best_state = None
    bad = 0
    for _ in range(150):
        _model.train()
        seq, lengths, sess, hp, y = _detector_pad_batch(tr)
        opt.zero_grad()
        logits = _model(seq, lengths, sess, hp)
        loss = loss_fn(logits, y)
        loss.backward(); opt.step()

        _model.eval()
        with torch.no_grad():
            vseq, vlen, vsess, vhp, vy = _detector_pad_batch(dv)
            vlog = _model(vseq, vlen, vsess, vhp)
            vscores = torch.sigmoid(vlog).numpy()
        y_dev = np.array([int(r["y"]) for r in dev_features]) if dev_features else y_train
        if y_dev.sum() == 0 or y_dev.sum() == y_dev.size:
            continue
        try:
            from sklearn.metrics import average_precision_score
            dev_auc = float(average_precision_score(y_dev, vscores))
        except Exception:
            continue
        if dev_auc > best_dev + 1e-4:
            best_dev = dev_auc
            best_state = {k: v.detach().clone() for k, v in _model.state_dict().items()}
            bad = 0
        else:
            bad += 1
            if bad >= 15:
                break
    if best_state is not None:
        _model.load_state_dict(best_state)


def predict(features: list[dict]) -> list[dict]:
    if _model is None or _norm_mean is None or _norm_std is None:
        return [
            {"session_id": f["session_id"], "agent_score": 0.5}
            for f in features
        ]
    _model.eval()
    eval_rows = _normalize(features, _norm_mean, _norm_std)
    with torch.no_grad():
        seq, lengths, sess, hp, _ = _detector_pad_batch(eval_rows)
        logits = _model(seq, lengths, sess, hp)
        probs = torch.sigmoid(logits).numpy()
    return [
        {"session_id": f["session_id"], "agent_score": float(p)}
        for f, p in zip(features, probs)
    ]
