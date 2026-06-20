"""Hybrid detector: GRU over per-request sequence ⊕ session aggregates
⊕ (optionally) honeypot flags → MLP → sigmoid.

`ablate_hp=True` trains and runs without honeypot inputs at all so we can
report ML-only PR-AUC and per-source recall alongside the full-stack
numbers. (See plan §Phase 4 eval.)
"""

from __future__ import annotations

import torch
import torch.nn as nn
from torch.nn.utils.rnn import pack_padded_sequence


class Detector(nn.Module):
    def __init__(
        self,
        req_dim: int,
        sess_dim: int,
        hp_dim: int,
        hidden: int = 64,
        ablate_hp: bool = False,
    ) -> None:
        super().__init__()
        self.req_dim = req_dim
        self.sess_dim = sess_dim
        self.hp_dim = hp_dim
        self.ablate_hp = ablate_hp
        self.gru = nn.GRU(req_dim, hidden, batch_first=True)
        ext = sess_dim + (0 if ablate_hp else hp_dim)
        self.head = nn.Sequential(
            nn.Linear(hidden + ext, hidden),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden, 1),
        )

    def forward(
        self,
        seq: torch.Tensor,        # [B, T_max, F_req]
        lengths: torch.Tensor,    # [B]
        sess: torch.Tensor,       # [B, F_sess]
        hp: torch.Tensor,         # [B, F_hp]
    ) -> torch.Tensor:
        packed = pack_padded_sequence(
            seq, lengths.cpu(), batch_first=True, enforce_sorted=False
        )
        _, h_n = self.gru(packed)
        h = h_n.squeeze(0)
        parts = [h, sess]
        if not self.ablate_hp:
            parts.append(hp)
        x = torch.cat(parts, dim=-1)
        return self.head(x).squeeze(-1)


def pad_batch(
    sessions, device=None
) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
    """Pack a list of `features.Session` into a padded batch."""
    import numpy as np

    lengths = torch.tensor([s.seq.shape[0] for s in sessions], dtype=torch.long)
    t_max = int(lengths.max().item())
    req_dim = sessions[0].seq.shape[1]
    seq = torch.zeros(len(sessions), t_max, req_dim, dtype=torch.float32)
    for i, s in enumerate(sessions):
        seq[i, : s.seq.shape[0], :] = torch.from_numpy(s.seq)
    sess = torch.from_numpy(np.stack([s.agg for s in sessions], axis=0)).float()
    hp = torch.from_numpy(np.stack([s.hp for s in sessions], axis=0)).float()
    y = torch.tensor([s.y for s in sessions], dtype=torch.float32)
    if device is not None:
        seq = seq.to(device)
        lengths = lengths.to(device)
        sess = sess.to(device)
        hp = hp.to(device)
        y = y.to(device)
    return seq, lengths, sess, hp, y
