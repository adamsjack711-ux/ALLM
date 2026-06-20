"""GRU-only baseline: a small PyTorch GRU over the per-request sequence,
no session-aggregate input, no honeypot input.

Isolates the lift the sequence channel contributes by itself. The
existing detector.model.Detector requires sess_dim ≥ 0; this is its
own model so the baseline stays self-contained and the contract is
exercised end-to-end (load module → train → score).
"""

from __future__ import annotations

from typing import Optional

import numpy as np
import torch
import torch.nn as nn
from torch.nn.utils.rnn import pack_padded_sequence


F_REQ = 9


class _GruOnly(nn.Module):
    def __init__(self, hidden: int = 32) -> None:
        super().__init__()
        self.gru = nn.GRU(F_REQ, hidden, batch_first=True)
        self.head = nn.Sequential(
            nn.Linear(hidden, hidden), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(hidden, 1),
        )

    def forward(self, seq: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        packed = pack_padded_sequence(
            seq, lengths.cpu(), batch_first=True, enforce_sorted=False,
        )
        _, h_n = self.gru(packed)
        return self.head(h_n.squeeze(0)).squeeze(-1)


_model: Optional[_GruOnly] = None


def _pad(rows: list[dict]) -> tuple[torch.Tensor, torch.Tensor]:
    lengths = torch.tensor([len(r["seq"]) for r in rows], dtype=torch.long)
    t_max = int(lengths.max().item()) if rows else 1
    seq = torch.zeros(len(rows), max(t_max, 1), F_REQ, dtype=torch.float32)
    for i, r in enumerate(rows):
        if r["seq"]:
            seq[i, : len(r["seq"]), :] = torch.tensor(r["seq"], dtype=torch.float32)
    return seq, lengths.clamp(min=1)


def train(train_features: list[dict], dev_features: list[dict]) -> None:
    global _model
    torch.manual_seed(0)
    np.random.seed(0)
    y_train = torch.tensor(
        [int(r["y"]) for r in train_features], dtype=torch.float32,
    )
    if y_train.sum() == 0 or y_train.sum() == y_train.size(0):
        _model = None
        return

    seq_train, len_train = _pad(train_features)
    _model = _GruOnly(hidden=32)
    opt = torch.optim.AdamW(_model.parameters(), lr=1e-3)
    loss_fn = nn.BCEWithLogitsLoss()

    best_dev = -1.0
    best_state = None
    bad = 0
    # Tiny dataset → full-batch is fine and deterministic.
    for _ in range(120):
        _model.train()
        logits = _model(seq_train, len_train)
        loss = loss_fn(logits, y_train)
        opt.zero_grad(); loss.backward(); opt.step()

        if not dev_features:
            continue
        _model.eval()
        with torch.no_grad():
            seq_dev, len_dev = _pad(dev_features)
            dev_logits = _model(seq_dev, len_dev)
            dev_scores = torch.sigmoid(dev_logits).numpy()
        y_dev = np.array([int(r["y"]) for r in dev_features])
        if y_dev.sum() == 0 or y_dev.sum() == y_dev.size:
            continue
        try:
            from sklearn.metrics import average_precision_score
            dev_auc = float(average_precision_score(y_dev, dev_scores))
        except Exception:
            continue
        if dev_auc > best_dev + 1e-4:
            best_dev = dev_auc
            best_state = {k: v.detach().clone() for k, v in _model.state_dict().items()}
            bad = 0
        else:
            bad += 1
            if bad >= 12:
                break
    if best_state is not None:
        _model.load_state_dict(best_state)


def predict(features: list[dict]) -> list[dict]:
    if _model is None:
        return [
            {"session_id": f["session_id"], "agent_score": 0.5} for f in features
        ]
    _model.eval()
    seq, lengths = _pad(features)
    with torch.no_grad():
        logits = _model(seq, lengths)
        probs = torch.sigmoid(logits).numpy()
    return [
        {"session_id": f["session_id"], "agent_score": float(p)}
        for f, p in zip(features, probs)
    ]
