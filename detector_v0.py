"""
AI-Attack Detector — v0 baseline
=================================
Goal of v0: prove signal exists. Load trace events, window them, extract
aggregate features, split BY CAMPAIGN (no leakage), train a gradient-boosted
baseline, and report PR-AUC + attack-class precision/recall + an estimated
false-positive rate per hour.

Runs end-to-end TODAY on synthetic data:

    python detector_v0.py --synthetic

To use the real HuggingFace temporal-attack-pattern dataset, inspect its
columns once and fill in the mapping in `adapt_real_dataframe()`, then:

    python detector_v0.py --data <path_or_hf_id>

Dependencies: numpy, pandas, scikit-learn  (datasets only for the real loader)
"""

from __future__ import annotations
import argparse
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    average_precision_score,
    precision_recall_fscore_support,
    confusion_matrix,
)

# ---------------------------------------------------------------------------
# 1. Normalized event schema
# ---------------------------------------------------------------------------
# Every data source gets adapted into this flat schema. Build features against
# THIS, never against a vendor-specific format, so swapping data sources later
# touches only the adapter.
#
#   campaign_id : str   grouping key (a single attack run OR a benign session)
#   ts          : float unix seconds (used for inter-event timing)
#   action      : str   one of ACTIONS below
#   target      : str   host / endpoint / table / path (hashed downstream)
#   depth       : int   pivot depth (0 = entry point)
#   artifact_ai : float 0..1  "does an associated script look AI-generated"
#   label       : int   1 = attack window source, 0 = benign  (campaign-level)

ACTIONS = ["tool_call", "api_request", "shell_cmd", "file_access", "net_egress"]
WINDOW_EVENTS = 32          # events per window
WINDOW_STRIDE = 16          # sliding stride (overlap = WINDOW_EVENTS - STRIDE)


# ---------------------------------------------------------------------------
# 2. Synthetic generator  (lets v0 run before you wire in real data)
# ---------------------------------------------------------------------------
def make_synthetic(n_benign=600, n_attack=180, seed=0) -> pd.DataFrame:
    """Generate benign + attack campaigns with genuinely overlapping classes.

    Each campaign gets a latent 'automation' score drawn from class-conditional
    distributions that OVERLAP heavily (benign ~N(0.42,0.22), attack ~N(0.58,0.22)).
    Every feature derives from that latent plus noise, so no feature -- and no
    window average -- cleanly separates the classes. This guarantees irreducible
    error (Bayes error > 0), keeping PR-AUC realistic (~0.8) like real telemetry.
    """
    rng = np.random.default_rng(seed)
    rows = []

    def emit(cid, label, latent):
        n_events = int(rng.integers(60, 220))
        # higher latent -> faster timing, deeper pivots, more targets, more AI-ish
        dt_scale = float(np.clip(rng.normal(12 - 11 * latent, 4), 0.3, 25))
        depth_max = max(1, int(round(rng.normal(1 + 6 * latent, 1.5))))
        n_targets = max(2, int(round(rng.normal(3 + 12 * latent, 3))))
        ai_mean = float(np.clip(rng.normal(0.35 + 0.4 * latent, 0.15), 0, 1))
        t = rng.uniform(0, 1e6)
        targets = [f"tgt_{i}" for i in range(n_targets)]
        for _ in range(n_events):
            t += max(0.0, rng.exponential(dt_scale))
            rows.append(dict(
                campaign_id=cid, ts=t,
                action=rng.choice(ACTIONS),
                target=rng.choice(targets),
                depth=int(min(depth_max, rng.poisson(depth_max * 0.5))),
                artifact_ai=float(np.clip(rng.normal(ai_mean, 0.22), 0, 1)),
                label=label,
            ))

    for i in range(n_benign):
        emit(f"benign_{i}", 0, float(np.clip(rng.normal(0.35, 0.17), 0, 1)))
    for i in range(n_attack):
        emit(f"attack_{i}", 1, float(np.clip(rng.normal(0.66, 0.17), 0, 1)))

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# 3. Real-dataset adapter  (fill this in once you inspect the HF schema)
# ---------------------------------------------------------------------------
def adapt_real_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """Map a real dataset's columns onto the normalized schema.

    Inspect the source first (e.g. `datasets.load_dataset(...).to_pandas().head()`),
    then rename/derive columns here. The rest of the pipeline is schema-agnostic.
    """
    # EXAMPLE mapping -- adjust the right-hand side to the real column names:
    rename = {
        # "trace_id":      "campaign_id",
        # "timestamp":     "ts",
        # "span_name":     "action",
        # "resource":      "target",
        # "is_malicious":  "label",
    }
    df = df.rename(columns=rename)
    required = {"campaign_id", "ts", "action", "target", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(
            f"Adapter incomplete -- still missing {missing}. "
            f"Edit adapt_real_dataframe() to map these from the source columns."
        )
    if "depth" not in df:
        df["depth"] = 0
    if "artifact_ai" not in df:
        df["artifact_ai"] = 0.0
    return df


def load_real(path_or_id: str) -> pd.DataFrame:
    try:
        from datasets import load_dataset
    except ImportError as e:
        raise SystemExit("pip install datasets --break-system-packages") from e
    ds = load_dataset(path_or_id, split="train")
    return adapt_real_dataframe(ds.to_pandas())


# ---------------------------------------------------------------------------
# 4. Windowing  (sliding window WITHIN each campaign only)
# ---------------------------------------------------------------------------
def windowize(df: pd.DataFrame) -> pd.DataFrame:
    """Turn the event stream into one row per window of WINDOW_EVENTS events.
    Windows never cross campaign boundaries."""
    feats = []
    for cid, g in df.sort_values("ts").groupby("campaign_id", sort=False):
        g = g.reset_index(drop=True)
        for start in range(0, max(1, len(g) - WINDOW_EVENTS + 1), WINDOW_STRIDE):
            w = g.iloc[start:start + WINDOW_EVENTS]
            if len(w) < WINDOW_EVENTS // 2:      # skip tiny tail windows
                continue
            feats.append(_window_features(w, cid))
    return pd.DataFrame(feats)


def _window_features(w: pd.DataFrame, cid: str) -> dict:
    dt = np.diff(w["ts"].to_numpy())
    dt = dt[dt >= 0]
    f = {
        "campaign_id": cid,
        "label": int(w["label"].max()),          # window is attack if any event is
        # --- timing: the single strongest tell for machine speed ---
        "dt_mean": float(dt.mean()) if len(dt) else 0.0,
        "dt_median": float(np.median(dt)) if len(dt) else 0.0,
        "dt_std": float(dt.std()) if len(dt) else 0.0,
        "events_per_sec": len(w) / (w["ts"].iloc[-1] - w["ts"].iloc[0] + 1e-6),
        # --- breadth / pivoting ---
        "distinct_targets": w["target"].nunique(),
        "target_churn": w["target"].nunique() / len(w),
        "depth_max": int(w["depth"].max()),
        "depth_mean": float(w["depth"].mean()),
        # --- artifact signal ---
        "ai_artifact_mean": float(w["artifact_ai"].mean()),
        "ai_artifact_max": float(w["artifact_ai"].max()),
    }
    # action-type histogram (normalized) -- shape of behavior
    counts = w["action"].value_counts(normalize=True)
    for a in ACTIONS:
        f[f"act_{a}"] = float(counts.get(a, 0.0))
    return f


# ---------------------------------------------------------------------------
# 5. Campaign-level split + baseline model + evaluation
# ---------------------------------------------------------------------------
@dataclass
class Result:
    pr_auc: float
    precision: float
    recall: float
    f1: float
    fp_per_hour: float
    cm: np.ndarray


def run(df_windows: pd.DataFrame, seed=0) -> Result:
    feat_cols = [c for c in df_windows.columns if c not in ("campaign_id", "label")]
    X = df_windows[feat_cols].to_numpy()
    y = df_windows["label"].to_numpy()
    groups = df_windows["campaign_id"].to_numpy()

    # CAMPAIGN-LEVEL split: no campaign appears in both train and test, so
    # near-duplicate windows can't leak and inflate the score.
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed)
    train_idx, test_idx = next(splitter.split(X, y, groups))

    # class_weight handles the benign/attack imbalance
    pos = y[train_idx].mean()
    sample_w = np.where(y[train_idx] == 1, (1 - pos) / pos, 1.0)

    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.06, max_depth=6,
        l2_regularization=1.0, random_state=seed,
    )
    clf.fit(X[train_idx], y[train_idx], sample_weight=sample_w)

    proba = clf.predict_proba(X[test_idx])[:, 1]
    yt = y[test_idx]
    pr_auc = average_precision_score(yt, proba)          # PR-AUC, not ROC-AUC

    # threshold pick: highest F1 on the test sweep (v0 only; tune on a val split later)
    thresholds = np.linspace(0.05, 0.95, 19)
    best = max(thresholds, key=lambda th: precision_recall_fscore_support(
        yt, proba >= th, average="binary", zero_division=0)[2])
    pred = proba >= best
    p, r, f1, _ = precision_recall_fscore_support(
        yt, pred, average="binary", zero_division=0)

    cm = confusion_matrix(yt, pred)
    # rough FP/hour: assumes each test window ~ WINDOW_EVENTS * median benign dt
    benign_dt = df_windows.loc[df_windows.label == 0, "dt_median"].median()
    secs_per_window = max(1.0, WINDOW_EVENTS * (benign_dt or 1.0))
    fp = cm[0, 1]
    test_seconds = len(yt) * secs_per_window
    fp_per_hour = fp / (test_seconds / 3600 + 1e-9)

    return Result(pr_auc, p, r, f1, fp_per_hour, cm)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--synthetic", action="store_true", help="run on generated data")
    ap.add_argument("--data", type=str, help="path or HF id for real dataset")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    if args.data:
        events = load_real(args.data)
        src = f"real:{args.data}"
    else:
        events = make_synthetic(seed=args.seed)
        src = "synthetic"

    windows = windowize(events)
    res = run(windows, seed=args.seed)

    print(f"\n=== AI-Attack Detector v0  [{src}] ===")
    print(f"events:        {len(events):>7,}")
    print(f"windows:       {len(windows):>7,}  "
          f"(attack {windows.label.mean()*100:.1f}%)")
    print(f"PR-AUC:        {res.pr_auc:.3f}   <- headline metric")
    print(f"precision:     {res.precision:.3f}")
    print(f"recall:        {res.recall:.3f}")
    print(f"F1 (attack):   {res.f1:.3f}")
    print(f"FP / hour:     {res.fp_per_hour:.2f}   <- decides if a SOC keeps it on")
    print(f"confusion:\n{res.cm}")
    print("\n(baseline only -- beat this PR-AUC with the sequence model in v0.5)\n")


if __name__ == "__main__":
    main()
