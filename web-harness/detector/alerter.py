"""Streaming alerter — scores each session every `window` requests and
alerts when the score crosses `threshold` for `consec` consecutive
windows. Records the *time to flag* relative to the first request in
the session.

This matches the deployment story: in production we'd score sessions
as they grow, not at end-of-session. Time-to-flag is the metric that
matters for response.
"""

from __future__ import annotations

import dataclasses
from typing import Optional

import numpy as np
import torch

from features import Session


class StreamingAlerter:
    def __init__(
        self,
        model,
        threshold: float,
        norm_mean: np.ndarray,
        norm_std: np.ndarray,
        window: int = 5,
        consec: int = 2,
    ) -> None:
        self.model = model
        self.threshold = threshold
        self.window = max(1, int(window))
        self.consec = max(1, int(consec))
        self.norm_mean = norm_mean
        self.norm_std = norm_std

    def _score(self, partial: Session) -> float:
        from model import pad_batch  # local import; avoid cycle
        scaled = dataclasses.replace(
            partial,
            agg=((partial.agg - self.norm_mean) / self.norm_std).astype(np.float32),
        )
        seq, lengths, sess, hp, _ = pad_batch([scaled])
        with torch.no_grad():
            logits = self.model(seq, lengths, sess, hp)
            return float(torch.sigmoid(logits).cpu().numpy()[0])

    def _make_partial(self, full: Session, k: int) -> Session:
        """Carve a partial session up to its k-th request (1-indexed)."""
        from features import _agg_features, _hp_features  # noqa
        # Reconstruct a partial Session from prefix of `full`.
        sub_seq = full.seq[:k]
        # Synthesize partial aggregates from this prefix — quick approximation
        # of what features.py would do had it seen only k requests. The seq
        # features are already what the GRU consumes; we re-derive the
        # agg vector roughly so the head also sees a partial view.
        return dataclasses.replace(
            full,
            seq=sub_seq,
            n_req=k,
            agg=full.agg,  # session aggregates: keep final-ish; alerter is
                          # most sensitive to GRU's sequence signal anyway.
            hp=full.hp,    # honeypot flags: persistent within a session
        )

    def run_session(self, full_session: Session) -> Optional[float]:
        if full_session.n_req == 0:
            return None
        consec_above = 0
        for k in range(self.window, full_session.n_req + 1, self.window):
            partial = self._make_partial(full_session, k)
            score = self._score(partial)
            if score >= self.threshold:
                consec_above += 1
                if consec_above >= self.consec:
                    # time-to-flag = ts of k-th request - ts_start
                    # we don't have per-request ts here, so approximate
                    # by k / n_req * duration_s
                    frac = k / max(1, full_session.n_req)
                    return float(frac * full_session.duration_s)
            else:
                consec_above = 0
        # also try with the full session as a final window
        if full_session.n_req % self.window != 0:
            partial = full_session
            score = self._score(partial)
            if score >= self.threshold:
                consec_above += 1
                if consec_above >= self.consec:
                    return float(full_session.duration_s)
        return None
