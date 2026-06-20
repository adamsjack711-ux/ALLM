"""
AI-Attack Detector — v0.5 sequence model
========================================
v0 used order-blind window AGGREGATES. v0.5 adds a GRU over the per-event
SEQUENCE, which can see structure that averages destroy: the *order* of
operations in an attack (recon -> access -> lateral -> exfil), accelerating
cadence, characteristic action transitions.

To prove the sequence model earns its keep, the synthetic data here puts the
discriminating signal entirely in EVENT ORDERING:
  - attacks follow a structured (kill-chain-like) action transition matrix
  - benign sessions use uniform-random action transitions
  - both are doubly-stochastic, so the MARGINAL action frequencies are identical
  - timing / depth / targets / ai-artifact are drawn from the SAME distribution
    for both classes -> they carry no signal at all

Result: the v0 aggregate baseline is near chance (it literally cannot see order),
while the GRU recovers the structure. This is the realistic lesson -- real attack
traces have ordering structure that aggregates blur.

    python detector_v05.py

Dependencies: numpy, pandas, scikit-learn, torch
"""

from __future__ import annotations
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import average_precision_score

from detector_v0 import ACTIONS, WINDOW_EVENTS, WINDOW_STRIDE, windowize, run

N_ACT = len(ACTIONS)
torch.manual_seed(0)


# ---------------------------------------------------------------------------
# 1. Synthetic data where the signal is ORDER, not averages
# ---------------------------------------------------------------------------
def _attack_transition(p_next=0.6) -> np.ndarray:
    """Doubly-stochastic circulant matrix: from action i, go to (i+1)%N with
    prob p_next, else spread uniformly. Stationary distribution is uniform, so
    marginal action frequencies match benign -- only the BIGRAM structure differs."""
    T = np.full((N_ACT, N_ACT), (1 - p_next) / (N_ACT - 1))
    for i in range(N_ACT):
        T[i, (i + 1) % N_ACT] = p_next
    return T


def make_seq_synthetic(n_benign=600, n_attack=180, seed=0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    T_attack = _attack_transition()
    T_benign = np.full((N_ACT, N_ACT), 1 / N_ACT)   # uniform transitions
    rows = []

    def emit(cid, label, T):
        n_events = int(rng.integers(60, 220))
        # identical non-ordering features for BOTH classes -> zero signal there
        dt_scale = 6.0
        n_targets = int(rng.integers(3, 10))
        targets = [f"tgt_{i}" for i in range(n_targets)]
        a = rng.integers(0, N_ACT)
        t = rng.uniform(0, 1e6)
        for _ in range(n_events):
            a = rng.choice(N_ACT, p=T[a])           # next action via Markov chain
            t += max(0.0, rng.exponential(dt_scale))
            rows.append(dict(
                campaign_id=cid, ts=t,
                action=ACTIONS[a],
                target=rng.choice(targets),
                depth=int(rng.poisson(1.5)),
                artifact_ai=float(np.clip(rng.normal(0.5, 0.2), 0, 1)),
                label=label,
            ))

    for i in range(n_benign):
        emit(f"benign_{i}", 0, T_benign)
    for i in range(n_attack):
        # 25% of attacks go "low-and-slow" with no ordering signal -- they look
        # benign on this feature, so they cap achievable recall (realistic ceiling).
        stealthy = rng.random() < 0.25
        emit(f"attack_{i}", 1, T_benign if stealthy else T_attack)
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# 2. Sequence featurization (one row per window -> a (T, F) tensor)
# ---------------------------------------------------------------------------
ACT_INDEX = {a: i for i, a in enumerate(ACTIONS)}


def seq_windows(df: pd.DataFrame):
    """Returns X (n_windows, WINDOW_EVENTS, F), y, groups. Per-event features:
    action one-hot (N_ACT) + log dt + depth + artifact_ai + position."""
    Xs, ys, gs = [], [], []
    F = N_ACT + 4
    for cid, g in df.sort_values("ts").groupby("campaign_id", sort=False):
        g = g.reset_index(drop=True)
        for start in range(0, max(1, len(g) - WINDOW_EVENTS + 1), WINDOW_STRIDE):
            w = g.iloc[start:start + WINDOW_EVENTS]
            if len(w) < WINDOW_EVENTS // 2:
                continue
            mat = np.zeros((WINDOW_EVENTS, F), dtype=np.float32)
            ts = w["ts"].to_numpy()
            for k, (_, ev) in enumerate(w.iterrows()):
                if k >= WINDOW_EVENTS:
                    break
                mat[k, ACT_INDEX[ev["action"]]] = 1.0
                dt = ts[k] - ts[k - 1] if k > 0 else 0.0
                mat[k, N_ACT + 0] = np.log1p(max(0.0, dt))
                mat[k, N_ACT + 1] = ev["depth"] / 6.0
                mat[k, N_ACT + 2] = ev["artifact_ai"]
                mat[k, N_ACT + 3] = k / WINDOW_EVENTS      # position
            Xs.append(mat)
            ys.append(int(w["label"].max()))
            gs.append(cid)
    return np.stack(Xs), np.array(ys), np.array(gs)


# ---------------------------------------------------------------------------
# 3. The GRU
# ---------------------------------------------------------------------------
class GRUDetector(nn.Module):
    def __init__(self, n_features, hidden=48):
        super().__init__()
        self.gru = nn.GRU(n_features, hidden, num_layers=2, batch_first=True, dropout=0.1)
        self.head = nn.Sequential(nn.Linear(hidden, 16), nn.ReLU(), nn.Linear(16, 1))

    def forward(self, x):
        _, h = self.gru(x)              # h: (1, B, hidden) -- last hidden state
        return self.head(h[-1]).squeeze(-1)


def train_gru(Xtr, ytr, Xte, epochs=40, lr=1.5e-3):
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    model = GRUDetector(Xtr.shape[2]).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    pos_weight = torch.tensor([(ytr == 0).sum() / max(1, (ytr == 1).sum())],
                              dtype=torch.float32, device=dev)
    loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)

    Xtr_t = torch.tensor(Xtr, device=dev)
    ytr_t = torch.tensor(ytr, dtype=torch.float32, device=dev)
    n = len(Xtr_t)
    for ep in range(epochs):
        model.train()
        perm = torch.randperm(n, device=dev)
        for i in range(0, n, 256):
            idx = perm[i:i + 256]
            opt.zero_grad()
            loss = loss_fn(model(Xtr_t[idx]), ytr_t[idx])
            loss.backward()
            opt.step()
    model.eval()
    with torch.no_grad():
        proba = torch.sigmoid(model(torch.tensor(Xte, device=dev))).cpu().numpy()
    return proba


# ---------------------------------------------------------------------------
# 4. Apples-to-apples comparison on ONE campaign-level split
# ---------------------------------------------------------------------------
def main():
    events = make_seq_synthetic(seed=0)

    # shared split on campaign groups so both models see identical train/test
    _, y_all, g_all = seq_windows(events)
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=0)
    tr_idx, te_idx = next(splitter.split(np.zeros(len(y_all)), y_all, g_all))

    # --- aggregate baseline (v0) on the SAME data ---
    agg = windowize(events)
    base = run(agg, seed=0)        # run() reproduces the same campaign split (seed=0)

    # --- GRU on event sequences ---
    Xseq, yseq, _ = seq_windows(events)
    proba = train_gru(Xseq[tr_idx], yseq[tr_idx], Xseq[te_idx])
    gru_auc = average_precision_score(yseq[te_idx], proba)

    base_rate = yseq.mean()
    print("\n=== v0.5 sequence model vs v0 aggregate baseline ===")
    print(f"windows:            {len(yseq):>6,}  (attack {base_rate*100:.1f}%)")
    print(f"base rate (chance): {base_rate:.3f}")
    print(f"v0 aggregate GBT:   {base.pr_auc:.3f}   <- order-blind, expected near chance")
    print(f"v0.5 GRU sequence:  {gru_auc:.3f}   <- recovers the ordering signal")
    lift = gru_auc - base.pr_auc
    print(f"lift from sequence: {lift:+.3f}")
    print("\nSignal here lives entirely in action ORDER; aggregates can't see it,")
    print("which is exactly when a sequence model is worth the extra complexity.\n")


if __name__ == "__main__":
    main()
