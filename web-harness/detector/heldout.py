"""Held-out attacker evaluation.

If the detector overfits the attack class it saw at training time, it
won't generalize. We test this:

  1. In-distribution baseline: train on a random 70/30 split of all
     classes; pick τ to meet the FP/hour budget on the test set; record
     per-attacker recall.
  2. For each attacker class A in {playwright_bot, pentesterpro}:
        - Train without any sessions labelled A.
        - Score all A-labelled sessions with the same τ.
        - Held-out recall = TPR on those sessions.
  3. Flag `overfits_attacker[A] = True` if held-out recall < 0.5 ×
     in-distribution recall on A. Per the plan's gate.

Writes `data/reports/heldout.json`.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import numpy as np
import torch

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from features import (  # noqa: E402
    AGENT_LABELS, F_HP, F_REQ, F_SESS,
    apply_aggregate_scaler,
    build_sessions,
    fit_aggregate_scaler,
)
from model import Detector, pad_batch  # noqa: E402
from train import split_sessions, train_head  # noqa: E402
from eval import pick_threshold_for_fp_budget, score_sessions  # noqa: E402


def train_and_score(train_sess, test_sess, ablate_hp=False):
    if not train_sess or not test_sess:
        return None, None
    mean, std = fit_aggregate_scaler(train_sess)
    tr_n = apply_aggregate_scaler(train_sess, mean, std)
    te_n = apply_aggregate_scaler(test_sess, mean, std)
    val_split_idx = max(1, int(0.85 * len(tr_n)))
    tr_split = tr_n[:val_split_idx]
    val_split = tr_n[val_split_idx:] or te_n
    model, _, _ = train_head(
        tr_split, val_split, ablate_hp=ablate_hp,
        epochs=200, lr=1e-3, patience=20,
    )
    scores = score_sessions(model, te_n)
    return model, scores


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=pathlib.Path, default=pathlib.Path("/data"))
    ap.add_argument(
        "--out", type=pathlib.Path,
        default=pathlib.Path("/data/reports/heldout.json"),
    )
    ap.add_argument("--fp-per-hour-budget", type=float, default=0.5)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    sessions = build_sessions(args.data)
    attackers_in_data = sorted(
        {s.src_label for s in sessions if s.src_label in AGENT_LABELS}
    )
    if len(attackers_in_data) < 2:
        msg = (
            f"[heldout] need ≥2 attacker classes in data, got "
            f"{attackers_in_data}; phase 5 not exercised"
        )
        print(msg, file=sys.stderr)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"skipped": msg}, indent=2))
        return 0

    # --- 1. In-distribution baseline. ---
    train_in, test_in = split_sessions(sessions, test_size=0.3, seed=args.seed)
    model_in, scores_in = train_and_score(train_in, test_in)
    y_in = np.array([s.y for s in test_in])
    tpick = pick_threshold_for_fp_budget(
        y_in, scores_in, test_in, args.fp_per_hour_budget
    )
    tau = tpick["threshold"]

    in_dist_recall: dict[str, float] = {}
    for a in attackers_in_data:
        mask = np.array([s.src_label == a for s in test_in])
        if mask.sum() == 0:
            in_dist_recall[a] = float("nan")
            continue
        in_dist_recall[a] = float((scores_in[mask] >= tau).mean())

    # --- 2. For each attacker, train without it and test recall on it. ---
    per_attacker: dict[str, dict] = {}
    for excluded in attackers_in_data:
        train_excl = [s for s in sessions if s.src_label != excluded]
        test_excl = [s for s in sessions if s.src_label == excluded]
        if not train_excl or not test_excl:
            per_attacker[excluded] = {"skipped": "empty split"}
            continue
        # Make sure the training set still has at least one positive
        # (other attacker) AND at least one negative.
        ys = [s.y for s in train_excl]
        if sum(ys) == 0 or sum(1 for y in ys if y == 0) == 0:
            per_attacker[excluded] = {"skipped": "single-class train"}
            continue
        _, scores_excl = train_and_score(train_excl, test_excl)
        recall = float((scores_excl >= tau).mean())
        in_dist = in_dist_recall.get(excluded)
        ratio = (
            recall / in_dist if in_dist and in_dist > 1e-9 else float("nan")
        )
        per_attacker[excluded] = {
            "in_dist_recall": in_dist,
            "heldout_recall": recall,
            "heldout_ratio": ratio,
            "overfits_attacker": (
                bool(in_dist and recall < 0.5 * in_dist)
                if in_dist is not None
                else None
            ),
            "n_train_sessions": len(train_excl),
            "n_holdout_sessions": len(test_excl),
        }

    report = {
        "threshold_in_dist": tau,
        "fp_per_hour_budget": args.fp_per_hour_budget,
        "in_dist_session_hours_test": tpick["session_hours"],
        "attackers": attackers_in_data,
        "per_attacker": per_attacker,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    print(f"[heldout] wrote {args.out}", flush=True)
    for a, info in per_attacker.items():
        if "skipped" in info:
            print(f"  {a:>14}  SKIPPED: {info['skipped']}", flush=True)
            continue
        flag = "OVERFITS" if info["overfits_attacker"] else "ok"
        print(
            f"  {a:>14}  in_dist={info['in_dist_recall']:.2f}  "
            f"heldout={info['heldout_recall']:.2f}  "
            f"ratio={info['heldout_ratio']:.2f}  [{flag}]",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
