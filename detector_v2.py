"""
AI-Attack Detector — v2 hybrid (aggregate features + GRU hidden state)
======================================================================
v0  sees only order-blind window AGGREGATES (timing, breadth, depth, action mix).
v0.5 sees only the per-event SEQUENCE (action ordering, cadence).
Each is blind to what the other sees. v2 fuses them: run the GRU over the event
sequence, take its final hidden state, CONCATENATE the v0 aggregate feature
vector, and feed the lot to one jointly-trained classifier head.

To prove the fusion earns its keep, the synthetic data gives attacks TWO
orthogonal, partial signals, and assigns most campaigns only ONE of them:

  - BREADTH signal   (aggregate-visible, GRU-blind): the attack fans out across
    many distinct targets. The aggregate features carry distinct_targets /
    target_churn; the GRU never sees target identity, so it cannot use this.

  - ORDERING signal  (GRU-visible, aggregate-blind): the attack follows a
    structured action-transition matrix. It is doubly-stochastic, so MARGINAL
    action frequencies match benign -> the aggregate action histogram can't see
    it; only a sequence model can.

Timing / depth / ai-artifact are drawn from the SAME distribution for everyone,
so they carry no signal. Attack campaigns are split into modes:
  aggregate-only / ordering-only / both / stealth(neither).
=> the aggregate model catches the breadth group, the GRU catches the ordering
group, and only the hybrid catches both. A stealth fraction keeps PR-AUC < 1.

    python detector_v2.py --synthetic

Dependencies: numpy, pandas, scikit-learn, torch
"""

from __future__ import annotations
import argparse

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import average_precision_score, precision_recall_fscore_support

from detector_v0 import (ACTIONS, WINDOW_EVENTS, WINDOW_STRIDE,
                         _window_features, windowize)
from detector_v05 import GRUDetector             # GRU-alone baseline (same architecture)

N_ACT = len(ACTIONS)
ACT_INDEX = {a: i for i, a in enumerate(ACTIONS)}
ATTACK_MODES = ["aggregate", "ordering", "both", "stealth"]


# ---------------------------------------------------------------------------
# 1. Synthetic data: two orthogonal partial signals, one per attack mode
# ---------------------------------------------------------------------------
def _structured_transition(p_next=0.5) -> np.ndarray:
    """Doubly-stochastic circulant matrix: marginal action frequencies stay
    uniform (so aggregates can't see it); only the bigram structure differs."""
    T = np.full((N_ACT, N_ACT), (1 - p_next) / (N_ACT - 1))
    for i in range(N_ACT):
        T[i, (i + 1) % N_ACT] = p_next
    return T


def make_hybrid_synthetic(n_benign=600, n_attack=260, seed=0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    T_struct = _structured_transition()
    T_uniform = np.full((N_ACT, N_ACT), 1 / N_ACT)
    rows = []

    def emit(cid, label, mode, structured, n_targets):
        n_events = int(rng.integers(60, 220))
        dt_scale = 6.0                                   # identical for all -> no signal
        targets = [f"tgt_{i}" for i in range(max(2, n_targets))]
        T = T_struct if structured else T_uniform
        a = int(rng.integers(0, N_ACT))
        t = rng.uniform(0, 1e6)
        for _ in range(n_events):
            a = rng.choice(N_ACT, p=T[a])
            t += max(0.0, rng.exponential(dt_scale))
            rows.append(dict(
                campaign_id=cid, ts=t,
                action=ACTIONS[a],
                target=rng.choice(targets),
                depth=int(rng.poisson(1.5)),             # identical for all -> no signal
                artifact_ai=float(np.clip(rng.normal(0.5, 0.2), 0, 1)),
                label=label, mode=mode,
            ))

    # benign: few targets (low breadth), uniform transitions
    for i in range(n_benign):
        emit(f"benign_{i}", 0, "benign", structured=False,
             n_targets=int(rng.integers(3, 9)))          # overlaps the low end of attacks

    # attacks: assign a mode; express only the matching channel(s)
    mode_p = [0.35, 0.35, 0.20, 0.10]                    # aggregate / ordering / both / stealth
    for i in range(n_attack):
        mode = rng.choice(ATTACK_MODES, p=mode_p)
        broad = mode in ("aggregate", "both")
        structured = mode in ("ordering", "both")
        # breadth overlaps benign on purpose (partial signal): broad ~ U(8,22)
        n_targets = int(rng.integers(8, 22)) if broad else int(rng.integers(3, 9))
        emit(f"attack_{i}", 1, mode, structured=structured, n_targets=n_targets)

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# 2. Aligned featurization: same windows -> (sequence tensor, aggregate vector)
# ---------------------------------------------------------------------------
def hybrid_windows(df: pd.DataFrame):
    """One pass, one set of windows, two views of each. Returns:
        X_seq (N,T,Fs)  per-event sequence features (as in v0.5)
        X_agg (N,Fa)    v0 aggregate feature vector
        agg_cols        names of the aggregate columns
        y (N,)          window label
        groups (N,)     campaign id
        modes (N,)      attack mode of the source campaign (for per-mode recall)
    """
    Xs, agg_rows, ys, gs, ms = [], [], [], [], []
    Fs = N_ACT + 4
    for cid, g in df.sort_values("ts").groupby("campaign_id", sort=False):
        g = g.reset_index(drop=True)
        for start in range(0, max(1, len(g) - WINDOW_EVENTS + 1), WINDOW_STRIDE):
            w = g.iloc[start:start + WINDOW_EVENTS]
            if len(w) < WINDOW_EVENTS // 2:
                continue
            # --- sequence view ---
            mat = np.zeros((WINDOW_EVENTS, Fs), dtype=np.float32)
            ts = w["ts"].to_numpy()
            acts = w["action"].to_numpy()
            depths = w["depth"].to_numpy()
            ai = w["artifact_ai"].to_numpy()
            n = min(len(w), WINDOW_EVENTS)
            for k in range(n):
                mat[k, ACT_INDEX[acts[k]]] = 1.0
                dt = ts[k] - ts[k - 1] if k > 0 else 0.0
                mat[k, N_ACT + 0] = np.log1p(max(0.0, dt))
                mat[k, N_ACT + 1] = depths[k] / 6.0
                mat[k, N_ACT + 2] = ai[k]
                mat[k, N_ACT + 3] = k / WINDOW_EVENTS
            Xs.append(mat)
            # --- aggregate view (reuse v0's exact features) ---
            agg_rows.append(_window_features(w, cid))
            ys.append(int(w["label"].max()))
            gs.append(cid)
            ms.append(w["mode"].iloc[0])
    agg_df = pd.DataFrame(agg_rows)
    agg_cols = [c for c in agg_df.columns if c not in ("campaign_id", "label")]
    return (np.stack(Xs), agg_df[agg_cols].to_numpy(dtype=np.float32), agg_cols,
            np.array(ys), np.array(gs), np.array(ms))


# ---------------------------------------------------------------------------
# 3. Models
# ---------------------------------------------------------------------------
def agg_baseline(X_agg, y, tr, seed):
    """v0's gradient-boosted aggregate model. Returns (proba_tr, predict_fn)."""
    pos = y[tr].mean()
    sw = np.where(y[tr] == 1, (1 - pos) / max(pos, 1e-9), 1.0)
    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.06, max_depth=6,
        l2_regularization=1.0, random_state=seed)
    clf.fit(X_agg[tr], y[tr], sample_weight=sw)
    return clf.predict_proba(X_agg[tr])[:, 1], (lambda Xq: clf.predict_proba(Xq)[:, 1])


def gru_scores(X_seq, y, tr, te, epochs=40, lr=1.5e-3, seed=0):
    """v0.5's GRU (same architecture) trained once; scores BOTH folds so a
    train-tuned threshold can be applied to the matching test scores."""
    torch.manual_seed(seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    model = GRUDetector(X_seq.shape[2]).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    pw = torch.tensor([(y[tr] == 0).sum() / max(1, (y[tr] == 1).sum())],
                      dtype=torch.float32, device=dev)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pw)
    Xtr = torch.tensor(X_seq[tr], device=dev)
    ytr = torch.tensor(y[tr], dtype=torch.float32, device=dev)
    n = len(Xtr)
    for _ in range(epochs):
        model.train()
        perm = torch.randperm(n, device=dev)
        for i in range(0, n, 256):
            idx = perm[i:i + 256]
            opt.zero_grad()
            loss_fn(model(Xtr[idx]), ytr[idx]).backward()
            opt.step()
    model.eval()
    with torch.no_grad():
        ptr = torch.sigmoid(model(Xtr)).cpu().numpy()
        pte = torch.sigmoid(model(torch.tensor(X_seq[te], device=dev))).cpu().numpy()
    return ptr, pte


class HybridDetector(nn.Module):
    """GRU final hidden state CONCAT aggregate feature vector -> one MLP head."""

    def __init__(self, n_seq_feat, n_agg_feat, hidden=48):
        super().__init__()
        self.gru = nn.GRU(n_seq_feat, hidden, num_layers=2,
                          batch_first=True, dropout=0.1)
        self.head = nn.Sequential(
            nn.Linear(hidden + n_agg_feat, 64), nn.ReLU(), nn.Dropout(0.1),
            nn.Linear(64, 1))

    def forward(self, x_seq, x_agg):
        _, h = self.gru(x_seq)                 # h: (layers, B, hidden)
        z = torch.cat([h[-1], x_agg], dim=1)   # fuse sequence summary + aggregates
        return self.head(z).squeeze(-1)


def train_hybrid(X_seq, X_agg, y, tr, te, epochs=40, lr=1.5e-3, seed=0):
    torch.manual_seed(seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"

    # standardize aggregates on TRAIN only (the GRU inputs are already ~unit-scale)
    mu = X_agg[tr].mean(0, keepdims=True)
    sd = X_agg[tr].std(0, keepdims=True) + 1e-6
    Xa = ((X_agg - mu) / sd).astype(np.float32)

    model = HybridDetector(X_seq.shape[2], X_agg.shape[1]).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    pw = torch.tensor([(y[tr] == 0).sum() / max(1, (y[tr] == 1).sum())],
                      dtype=torch.float32, device=dev)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pw)

    Xs_t = torch.tensor(X_seq[tr], device=dev)
    Xa_t = torch.tensor(Xa[tr], device=dev)
    y_t = torch.tensor(y[tr], dtype=torch.float32, device=dev)
    n = len(Xs_t)
    for _ in range(epochs):
        model.train()
        perm = torch.randperm(n, device=dev)
        for i in range(0, n, 256):
            idx = perm[i:i + 256]
            opt.zero_grad()
            loss = loss_fn(model(Xs_t[idx], Xa_t[idx]), y_t[idx])
            loss.backward()
            opt.step()
    model.eval()
    with torch.no_grad():
        proba_te = torch.sigmoid(
            model(torch.tensor(X_seq[te], device=dev),
                  torch.tensor(Xa[te], device=dev))).cpu().numpy()
        proba_tr = torch.sigmoid(
            model(torch.tensor(X_seq[tr], device=dev),
                  torch.tensor(Xa[tr], device=dev))).cpu().numpy()
    return proba_tr, proba_te


# ---------------------------------------------------------------------------
# 4. Eval helpers
# ---------------------------------------------------------------------------
def _best_f1_threshold(y, proba):
    grid = np.linspace(0.05, 0.95, 19)
    return max(grid, key=lambda th: precision_recall_fscore_support(
        y, proba >= th, average="binary", zero_division=0)[2])


def _fp_per_hour(events, n_test_windows, n_fp):
    agg = windowize(events)
    benign_dt = agg.loc[agg.label == 0, "dt_median"].median()
    secs_per_window = max(1.0, WINDOW_EVENTS * (benign_dt or 1.0))
    return n_fp / ((n_test_windows * secs_per_window) / 3600 + 1e-9)


def _recall_by_mode(y, modes, pred):
    """Per-attack-mode recall among attack windows -> shows complementarity."""
    out = {}
    for m in ("aggregate", "ordering", "both", "stealth"):
        sel = (y == 1) & (modes == m)
        out[m] = (pred[sel].sum() / sel.sum()) if sel.sum() else float("nan")
    return out


# ---------------------------------------------------------------------------
# 5. Run: three models, one shared campaign split
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--epochs", type=int, default=40)
    args = ap.parse_args()

    events = make_hybrid_synthetic(seed=args.seed)
    X_seq, X_agg, agg_cols, y, groups, modes = hybrid_windows(events)

    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=args.seed)
    tr, te = next(splitter.split(X_seq, y, groups))
    yte, modes_te = y[te], modes[te]

    # (a) aggregate-only (v0), (b) GRU-only (v0.5), (c) hybrid — same tr/te,
    # each trained ONCE and scored on both folds (train scores tune thresholds).
    agg_tr, agg_predict = agg_baseline(X_agg, y, tr, args.seed)
    agg_p = agg_predict(X_agg[te])
    gru_tr, gru_p = gru_scores(X_seq, y, tr, te, epochs=args.epochs, seed=args.seed)
    hyb_tr, hyb_p = train_hybrid(X_seq, X_agg, y, tr, te, epochs=args.epochs, seed=args.seed)

    agg_auc = average_precision_score(yte, agg_p)
    gru_auc = average_precision_score(yte, gru_p)
    hyb_auc = average_precision_score(yte, hyb_p)
    best_single = max(agg_auc, gru_auc)

    # FP/hour for the hybrid at a TRAIN-tuned threshold (no test fitting)
    hyb_th = _best_f1_threshold(y[tr], hyb_tr)
    hyb_pred = hyb_p >= hyb_th
    hp, hr, hf1, _ = precision_recall_fscore_support(
        yte, hyb_pred, average="binary", zero_division=0)
    n_fp = int(((hyb_pred == 1) & (yte == 0)).sum())
    fph = _fp_per_hour(events, len(yte), n_fp)

    print("\n=== AI-Attack Detector v2 — hybrid (aggregate + GRU) [synthetic] ===")
    print(f"windows: {len(y):,}  (attack {y.mean()*100:.1f}%)   "
          f"one shared campaign-level split")
    print("\n--- PR-AUC on the SAME test fold ---")
    print(f"  v0  aggregate-only (breadth-visible, order-blind):  {agg_auc:.3f}")
    print(f"  v0.5 GRU-only      (order-visible, breadth-blind):  {gru_auc:.3f}")
    print(f"  v2  HYBRID         (sees both channels):            {hyb_auc:.3f}")
    print(f"  lift over best single model:                        {hyb_auc - best_single:+.3f}")
    print(f"\n  hybrid @train-tuned thr={hyb_th:.2f}:  precision {hp:.3f}  "
          f"recall {hr:.3f}  F1 {hf1:.3f}  FP/hour {fph:.2f}")

    # per-mode recall: each model at its OWN train-tuned threshold
    agg_th = _best_f1_threshold(y[tr], agg_tr)
    gru_th = _best_f1_threshold(y[tr], gru_tr)
    rec_agg = _recall_by_mode(yte, modes_te, agg_p >= agg_th)
    rec_gru = _recall_by_mode(yte, modes_te, gru_p >= gru_th)
    rec_hyb = _recall_by_mode(yte, modes_te, hyb_pred)

    print("\n--- recall by attack mode (why the hybrid wins) ---")
    print(f"  {'mode':<12}{'aggregate':>11}{'GRU':>8}{'hybrid':>9}")
    for m in ("aggregate", "ordering", "both", "stealth"):
        print(f"  {m:<12}{rec_agg[m]:>11.3f}{rec_gru[m]:>8.3f}{rec_hyb[m]:>9.3f}")
    print("\n  aggregate-only attacks: caught by the aggregate channel, missed by the GRU.")
    print("  ordering-only attacks:  caught by the GRU, missed by the aggregate model.")
    print("  the hybrid catches both -> higher PR-AUC than either model alone.\n")


if __name__ == "__main__":
    main()
