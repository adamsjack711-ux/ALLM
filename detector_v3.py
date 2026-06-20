"""
AI-Attack Detector — v3 real-data wiring + streaming serving loop
=================================================================
v0/v0.5/v1/v2 are offline experiments. v3 is the thin operational layer:

  1. REAL-DATA WIRING — the same pipeline runs on a real dataset by adapting it
     into the normalized schema once (`adapt_real_dataframe` for generic sources,
     `adapter_winlogs.adapt_winlog_dataframe` for Windows/Sysmon logs). The HF
     temporal-attack-pattern dataset is reached with `--data <hf_id>` (lazy
     `datasets` import); everything else stays schema-agnostic.

  2. STREAMING SERVING LOOP — `StreamingAlerter` ingests events one at a time,
     keeps a per-campaign sliding buffer, scores each completed 32-event window
     with the best model (the v2 hybrid), and emits an alert when the risk
     crosses a threshold TUNED AGAINST AN FP/HOUR BUDGET (not F1 -- a SOC cares
     about alert volume, not balanced accuracy).

  3. MEAN-TIME-TO-DETECT — replay held-out attack traces through the alerter and
     measure wall-clock seconds from attack onset to first alert.

Runs end-to-end offline on synthetic data:

    python detector_v3.py --demo
    python detector_v3.py --demo --fp-budget 0.5     # stricter alert budget
    python detector_v3.py --data <path_or_hf_id>     # real data (needs network for HF)

Dependencies: numpy, pandas, scikit-learn, torch
"""

from __future__ import annotations
import argparse
from collections import deque

import numpy as np
import pandas as pd
import torch
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import average_precision_score, precision_recall_fscore_support

from detector_v0 import (ACTIONS, WINDOW_EVENTS, WINDOW_STRIDE,
                         _window_features, windowize)
from detector_v2 import (make_hybrid_synthetic, HybridDetector, N_ACT, ACT_INDEX)

SEQ_F = N_ACT + 4


# ---------------------------------------------------------------------------
# 1. Per-window featurization (single source of truth, used batch AND streaming)
# ---------------------------------------------------------------------------
def featurize_window(w: pd.DataFrame, agg_cols) -> tuple[np.ndarray, np.ndarray]:
    """One window -> (sequence tensor (T,SEQ_F), aggregate vector (len(agg_cols),))."""
    mat = np.zeros((WINDOW_EVENTS, SEQ_F), dtype=np.float32)
    ts = w["ts"].to_numpy()
    acts = w["action"].to_numpy()
    depths = w["depth"].to_numpy()
    ai = w["artifact_ai"].to_numpy()
    n = min(len(w), WINDOW_EVENTS)
    for k in range(n):
        idx = ACT_INDEX.get(acts[k])
        if idx is not None:                     # unknown actions (real data) -> no one-hot
            mat[k, idx] = 1.0
        dt = ts[k] - ts[k - 1] if k > 0 else 0.0
        mat[k, N_ACT + 0] = np.log1p(max(0.0, dt))
        mat[k, N_ACT + 1] = depths[k] / 6.0
        mat[k, N_ACT + 2] = ai[k]
        mat[k, N_ACT + 3] = k / WINDOW_EVENTS
    feat = _window_features(w, w["campaign_id"].iloc[0])
    agg = np.array([feat[c] for c in agg_cols], dtype=np.float32)
    return mat, agg


def build_windows(df: pd.DataFrame, agg_cols=None):
    """All windows for a dataframe, with timestamps for MTTD bookkeeping."""
    rows_seq, rows_agg, ys, gs, end_ts, start_ts = [], [], [], [], [], []
    if agg_cols is None:
        sample = _window_features(df.head(WINDOW_EVENTS), str(df["campaign_id"].iloc[0]))
        agg_cols = [c for c in sample if c not in ("campaign_id", "label")]
    for cid, g in df.sort_values("ts").groupby("campaign_id", sort=False):
        g = g.reset_index(drop=True)
        cstart = float(g["ts"].iloc[0])
        for s in range(0, max(1, len(g) - WINDOW_EVENTS + 1), WINDOW_STRIDE):
            w = g.iloc[s:s + WINDOW_EVENTS]
            if len(w) < WINDOW_EVENTS // 2:
                continue
            mat, agg = featurize_window(w, agg_cols)
            rows_seq.append(mat)
            rows_agg.append(agg)
            ys.append(int(w["label"].max()))
            gs.append(cid)
            end_ts.append(float(w["ts"].iloc[-1]))
            start_ts.append(cstart)
    return (np.stack(rows_seq), np.stack(rows_agg), np.array(ys), np.array(gs),
            np.array(end_ts), np.array(start_ts), agg_cols)


# ---------------------------------------------------------------------------
# 2. Train the best model (v2 hybrid) and expose a reusable scorer
# ---------------------------------------------------------------------------
class HybridScorer:
    """Trained hybrid model + the train-fold aggregate standardization, wrapped
    so a single window (or a batch) can be scored anywhere (batch or stream)."""

    def __init__(self, model, mu, sd, agg_cols, dev):
        self.model, self.mu, self.sd, self.agg_cols, self.dev = model, mu, sd, agg_cols, dev

    def score(self, X_seq, X_agg) -> np.ndarray:
        Xa = ((X_agg - self.mu) / self.sd).astype(np.float32)
        self.model.eval()
        with torch.no_grad():
            p = torch.sigmoid(self.model(
                torch.tensor(X_seq, device=self.dev),
                torch.tensor(Xa, device=self.dev))).cpu().numpy()
        return p

    def score_one(self, seq_mat, agg_vec) -> float:
        return float(self.score(seq_mat[None], agg_vec[None])[0])


def train_hybrid_scorer(X_seq, X_agg, y, agg_cols, epochs=40, lr=1.5e-3, seed=0):
    torch.manual_seed(seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    mu = X_agg.mean(0, keepdims=True)
    sd = X_agg.std(0, keepdims=True) + 1e-6
    Xa = ((X_agg - mu) / sd).astype(np.float32)

    model = HybridDetector(X_seq.shape[2], X_agg.shape[1]).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    pw = torch.tensor([(y == 0).sum() / max(1, (y == 1).sum())],
                      dtype=torch.float32, device=dev)
    loss_fn = torch.nn.BCEWithLogitsLoss(pos_weight=pw)
    Xs_t = torch.tensor(X_seq, device=dev)
    Xa_t = torch.tensor(Xa, device=dev)
    y_t = torch.tensor(y, dtype=torch.float32, device=dev)
    n = len(Xs_t)
    for _ in range(epochs):
        model.train()
        perm = torch.randperm(n, device=dev)
        for i in range(0, n, 256):
            idx = perm[i:i + 256]
            opt.zero_grad()
            loss_fn(model(Xs_t[idx], Xa_t[idx]), y_t[idx]).backward()
            opt.step()
    return HybridScorer(model, mu, sd, agg_cols, dev)


# ---------------------------------------------------------------------------
# 3. Threshold tuned against an FP/HOUR BUDGET (not F1)
# ---------------------------------------------------------------------------
def secs_per_window(events: pd.DataFrame) -> float:
    agg = windowize(events)
    benign_dt = agg.loc[agg.label == 0, "dt_median"].median()
    if not np.isfinite(benign_dt) or benign_dt <= 0:
        benign_dt = agg["dt_median"].median() or 1.0
    return max(1.0, WINDOW_EVENTS * float(benign_dt))


def tune_threshold_for_budget(y, proba, spw, budget_fph):
    """Smallest threshold whose estimated FP/hour <= budget (=> highest recall
    within the alert budget). Estimated on the fold this is called with."""
    n = len(y)
    grid = np.unique(np.quantile(proba, np.linspace(0, 1, 201)))
    for th in grid:                              # ascending -> first feasible = lowest th
        fp = int(((proba >= th) & (y == 0)).sum())
        fph = fp / ((n * spw) / 3600 + 1e-9)
        if fph <= budget_fph:
            return float(th), fph
    return float(grid[-1]), float("inf")


# ---------------------------------------------------------------------------
# 4. Streaming alerter — ingest events, emit alerts on completed windows
# ---------------------------------------------------------------------------
class StreamingAlerter:
    """Feed events in time order; emits an alert dict the first stride-aligned
    window whose hybrid risk crosses the threshold. One alerter per campaign."""

    def __init__(self, scorer: HybridScorer, threshold: float):
        self.scorer = scorer
        self.threshold = threshold
        self.buf: deque = deque(maxlen=WINDOW_EVENTS)
        self.seen = 0
        self.alerted = False

    def feed(self, event: dict):
        self.buf.append(event)
        self.seen += 1
        # score on stride-aligned boundaries once the buffer is usefully full
        if len(self.buf) < WINDOW_EVENTS // 2 or self.seen % WINDOW_STRIDE != 0:
            return None
        w = pd.DataFrame(list(self.buf))
        seq, agg = featurize_window(w, self.scorer.agg_cols)
        risk = self.scorer.score_one(seq, agg)
        if risk >= self.threshold and not self.alerted:
            self.alerted = True
            return {"risk": risk, "ts": float(w["ts"].iloc[-1]),
                    "events_seen": self.seen}
        return None


def replay_mttd(df: pd.DataFrame, scorer: HybridScorer, threshold: float):
    """Replay each campaign as a stream; record time-to-first-alert. Returns a
    per-campaign dataframe (attack vs benign, detected, detect ts, mttd seconds)."""
    recs = []
    for cid, g in df.sort_values("ts").groupby("campaign_id", sort=False):
        g = g.reset_index(drop=True)
        is_attack = bool(g["label"].max())
        # onset = first attack event for attack campaigns, else campaign start
        if is_attack and (g["label"] == 1).any():
            onset = float(g.loc[g["label"] == 1, "ts"].iloc[0])
        else:
            onset = float(g["ts"].iloc[0])
        alerter = StreamingAlerter(scorer, threshold)
        alert = None
        for _, ev in g.iterrows():
            a = alerter.feed(ev.to_dict())
            if a is not None:
                alert = a
                break
        recs.append(dict(
            campaign_id=cid, is_attack=is_attack,
            detected=alert is not None,
            mttd_s=(alert["ts"] - onset) if alert is not None else np.nan,
        ))
    return pd.DataFrame(recs)


# ---------------------------------------------------------------------------
# 5. Data loading
# ---------------------------------------------------------------------------
def load_events(args) -> tuple[pd.DataFrame, str]:
    if args.data:
        from inspect_dataset import load_any            # lazy (HF datasets optional)
        raw = load_any(args.data)
        if args.winlog:
            from adapter_winlogs import adapt_winlog_dataframe
            df = adapt_winlog_dataframe(raw)
        else:
            from detector_v0 import adapt_real_dataframe
            df = adapt_real_dataframe(raw)
        # promote to campaign-level labels (a campaign is attack if any event is)
        camp = df.groupby("campaign_id")["label"].max()
        df["label"] = df["campaign_id"].map(camp).astype(int)
        return df, f"real:{args.data}"
    return make_hybrid_synthetic(seed=args.seed), "synthetic"


# ---------------------------------------------------------------------------
# 6. End-to-end: train, tune to budget, batch metrics, stream MTTD
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true", help="run on synthetic data")
    ap.add_argument("--data", type=str, help="path or HF id for a real dataset")
    ap.add_argument("--winlog", action="store_true", help="adapt --data as Windows logs")
    ap.add_argument("--fp-budget", type=float, default=1.0, help="max false alerts/hour")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--epochs", type=int, default=40)
    args = ap.parse_args()
    if not (args.demo or args.data):
        ap.error("pass --demo (synthetic) or --data <path_or_hf_id>")

    events, src = load_events(args)

    X_seq, X_agg, y, groups, end_ts, start_ts, agg_cols = build_windows(events)
    tr, te = next(GroupShuffleSplit(n_splits=1, test_size=0.25,
                                    random_state=args.seed).split(X_seq, y, groups))
    test_campaigns = set(groups[te])

    # --- train best model (hybrid) on train fold ---
    scorer = train_hybrid_scorer(X_seq[tr], X_agg[tr], y[tr], agg_cols,
                                 epochs=args.epochs, seed=args.seed)
    p_tr = scorer.score(X_seq[tr], X_agg[tr])
    p_te = scorer.score(X_seq[te], X_agg[te])
    pr_auc = average_precision_score(y[te], p_te)

    # --- tune threshold to the FP/hour budget on the TRAIN fold ---
    spw = secs_per_window(events)
    thr, fph_tr = tune_threshold_for_budget(y[tr], p_tr, spw, args.fp_budget)

    # --- batch metrics on test at that operating point ---
    pred = p_te >= thr
    prec, rec, f1, _ = precision_recall_fscore_support(
        y[te], pred, average="binary", zero_division=0)
    n_fp = int(((pred == 1) & (y[te] == 0)).sum())
    fph_te = n_fp / ((len(y[te]) * spw) / 3600 + 1e-9)

    print(f"\n=== AI-Attack Detector v3 — serving loop  [{src}] ===")
    print(f"events {len(events):,} | windows {len(y):,} (attack {y.mean()*100:.1f}%) "
          f"| campaign-level split | model: v2 hybrid")
    print(f"\n--- detection quality on held-out campaigns ---")
    print(f"  PR-AUC:                 {pr_auc:.3f}")
    print(f"  FP/hour budget:         {args.fp_budget:.2f}  -> threshold {thr:.3f}")
    print(f"  achieved FP/hour (test):{fph_te:>6.2f}")
    print(f"  precision {prec:.3f} | recall {rec:.3f} | F1 {f1:.3f}")

    # --- streaming replay -> mean-time-to-detect on test attack traces ---
    test_df = events[events["campaign_id"].isin(test_campaigns)]
    rep = replay_mttd(test_df, scorer, thr)
    atk = rep[rep.is_attack]
    ben = rep[~rep.is_attack]
    det = atk[atk.detected]
    print(f"\n--- streaming replay (test campaigns, threshold {thr:.3f}) ---")
    print(f"  attack traces:          {len(atk)}")
    print(f"  detected:               {len(det)}  ({len(det)/max(1,len(atk))*100:.0f}% of attacks)")
    if len(det):
        mt = det["mttd_s"].to_numpy()
        print(f"  mean-time-to-detect:    {mt.mean():>8.1f} s   (~{mt.mean()/60:.1f} min)")
        print(f"  median-time-to-detect:  {np.median(mt):>8.1f} s   (~{np.median(mt)/60:.1f} min)")
    fp_campaigns = int(ben.detected.sum())
    print(f"  benign traces w/ alert: {fp_campaigns}/{len(ben)}  "
          f"({fp_campaigns/max(1,len(ben))*100:.0f}% false-alarm campaigns)")
    print("\nThreshold is tuned to an alert BUDGET (FP/hour), not F1 -- the knob a")
    print("SOC actually turns. MTTD is measured by replaying traces as a stream.\n")


if __name__ == "__main__":
    main()
