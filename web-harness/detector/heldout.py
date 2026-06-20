"""Held-out family evaluation.

If the detector overfits the families it saw at training time, it
won't generalize. Phase 8 widens this from "held-out attacker" (phase
5) to "held-out family" — both for agent recall *and* for benign_bot
FP generalization.

  1. In-distribution baseline: train on a random 70/30 split of all
     classes; pick τ to meet the FP/hour budget on the test set;
     record per-family recall (agents) and per-family FP rate
     (benign_bot, human).

  2. For each AGENT family A in the data:
        - Train without any sessions labelled A.
        - Score all A-labelled sessions with the same τ.
        - Held-out recall = TPR on those sessions.
        - Flag `overfits_attacker[A] = True` if held-out recall < 0.5 ×
          in-distribution recall on A.

  3. For each BENIGN_BOT family B in the data:
        - Train without any sessions labelled B (still has the other
          benign and agent classes).
        - Score B sessions with the same τ. The model has never seen
          this benign-automation shape before — the question is
          whether it generalizes "benign" or alarms on the novelty.
        - Held-out FP rate = alert rate on the B-sessions.
        - Flag `fp_generalization_fail[B] = True` if held-out
          fp_rate > 2 × in-distribution fp_rate on B. (Symmetric
          factor-of-two gate to the agent overfit check.)

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
    F_HP, F_REQ, F_SESS,
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


def _families_by_class(sessions, klass: str) -> list[str]:
    return sorted({s.family for s in sessions if s.klass == klass and s.family})


def _alert_rate(scores: np.ndarray, mask: np.ndarray, tau: float) -> float:
    if mask.sum() == 0:
        return float("nan")
    return float((scores[mask] >= tau).mean())


def _heldout_agent_family(
    sessions, excluded: str, tau: float
) -> dict | None:
    train_excl = [s for s in sessions if s.family != excluded]
    test_excl = [s for s in sessions if s.family == excluded]
    if not train_excl or not test_excl:
        return {"skipped": "empty split"}
    ys = [s.y for s in train_excl]
    if sum(ys) == 0 or sum(1 for y in ys if y == 0) == 0:
        return {"skipped": "single-class train"}
    _, scores_excl = train_and_score(train_excl, test_excl)
    return {
        "n_train_sessions": len(train_excl),
        "n_holdout_sessions": len(test_excl),
        "scores": scores_excl,
        "heldout_recall": float((scores_excl >= tau).mean()),
    }


def _heldout_benign_family(
    sessions, excluded: str, tau: float
) -> dict | None:
    train_excl = [s for s in sessions if s.family != excluded]
    test_excl = [s for s in sessions if s.family == excluded]
    if not train_excl or not test_excl:
        return {"skipped": "empty split"}
    ys = [s.y for s in train_excl]
    if sum(ys) == 0 or sum(1 for y in ys if y == 0) == 0:
        return {"skipped": "single-class train"}
    _, scores_excl = train_and_score(train_excl, test_excl)
    return {
        "n_train_sessions": len(train_excl),
        "n_holdout_sessions": len(test_excl),
        "heldout_fp_rate": float((scores_excl >= tau).mean()),
    }


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
    agent_families = _families_by_class(sessions, "agent")
    benign_families = _families_by_class(sessions, "benign_bot")

    if len(agent_families) < 2:
        msg = (
            f"[heldout] need ≥2 agent families in data, got {agent_families}; "
            f"phase 5 not exercised"
        )
        print(msg, file=sys.stderr)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"skipped": msg}, indent=2))
        return 0

    # --- 1. In-distribution baseline. ---
    train_in, test_in = split_sessions(sessions, test_size=0.3, seed=args.seed)
    _, scores_in = train_and_score(train_in, test_in)
    tpick = pick_threshold_for_fp_budget(
        np.array([s.y for s in test_in]), scores_in, test_in,
        args.fp_per_hour_budget,
    )
    tau = tpick["threshold"]

    in_dist_recall: dict[str, float] = {}
    for a in agent_families:
        mask = np.array([s.family == a for s in test_in])
        in_dist_recall[a] = _alert_rate(scores_in, mask, tau)

    in_dist_fp: dict[str, float] = {}
    for b in benign_families:
        mask = np.array([s.family == b for s in test_in])
        in_dist_fp[b] = _alert_rate(scores_in, mask, tau)

    # --- 2. Held-out agent families. ---
    per_attacker: dict[str, dict] = {}
    for excluded in agent_families:
        info = _heldout_agent_family(sessions, excluded, tau)
        if info is None or "skipped" in info:
            per_attacker[excluded] = info or {"skipped": "no result"}
            continue
        in_dist = in_dist_recall.get(excluded)
        recall = info["heldout_recall"]
        ratio = (recall / in_dist if in_dist and in_dist > 1e-9 else float("nan"))
        per_attacker[excluded] = {
            "in_dist_recall": in_dist,
            "heldout_recall": recall,
            "heldout_ratio": ratio,
            "overfits_attacker": (
                bool(in_dist and recall < 0.5 * in_dist)
                if in_dist is not None
                else None
            ),
            "n_train_sessions": info["n_train_sessions"],
            "n_holdout_sessions": info["n_holdout_sessions"],
        }

    # --- 3. Held-out benign_bot families (phase 8 addition). ---
    per_benign: dict[str, dict] = {}
    for excluded in benign_families:
        info = _heldout_benign_family(sessions, excluded, tau)
        if info is None or "skipped" in info:
            per_benign[excluded] = info or {"skipped": "no result"}
            continue
        in_dist = in_dist_fp.get(excluded)
        fp_rate = info["heldout_fp_rate"]
        ratio = (
            fp_rate / in_dist if in_dist and in_dist > 1e-9 else float("nan")
        )
        per_benign[excluded] = {
            "in_dist_fp_rate": in_dist,
            "heldout_fp_rate": fp_rate,
            "heldout_ratio": ratio,
            "fp_generalization_fail": (
                bool(in_dist is not None and fp_rate > 2.0 * max(in_dist, 1e-6))
            ),
            "n_train_sessions": info["n_train_sessions"],
            "n_holdout_sessions": info["n_holdout_sessions"],
        }

    report = {
        "threshold_in_dist": tau,
        "fp_per_hour_budget": args.fp_per_hour_budget,
        "in_dist_session_hours_test": tpick["session_hours"],
        "agent_families": agent_families,
        "benign_families": benign_families,
        "per_attacker": per_attacker,
        "per_benign_family": per_benign,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    print(f"[heldout] wrote {args.out}", flush=True)
    for a, info in per_attacker.items():
        if "skipped" in info:
            print(f"  agent {a:>14}  SKIPPED: {info['skipped']}", flush=True)
            continue
        flag = "OVERFITS" if info["overfits_attacker"] else "ok"
        print(
            f"  agent {a:>14}  in_dist={info['in_dist_recall']:.2f}  "
            f"heldout={info['heldout_recall']:.2f}  "
            f"ratio={info['heldout_ratio']:.2f}  [{flag}]",
            flush=True,
        )
    for b, info in per_benign.items():
        if "skipped" in info:
            print(f"  benign {b:>13}  SKIPPED: {info['skipped']}", flush=True)
            continue
        flag = "FP-GEN-FAIL" if info["fp_generalization_fail"] else "ok"
        in_d = info["in_dist_fp_rate"]
        in_d_s = f"{in_d:.2f}" if in_d is not None and not np.isnan(in_d) else "nan"
        print(
            f"  benign {b:>13}  in_dist_fp={in_d_s}  "
            f"heldout_fp={info['heldout_fp_rate']:.2f}  [{flag}]",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
