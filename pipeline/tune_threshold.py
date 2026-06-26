"""Composite-objective threshold tuner (phase-host-7).

Phase-host-3's `alert_fatigue` picks τ at a fixed FP/hour budget. That's
the right default when an operator says "I can absorb N alerts/hour."
But sometimes the question is the inverse: "given a desired recall,
what's the minimum FP/hour I can pay?" Or even broader: "trace the
Pareto frontier so I can pick a τ in the middle."

This module sweeps τ over a grid, computes detect_rate + FP/hour per
deployment at each τ, and emits:

  1. The full Pareto curve (every τ tried, with its metrics)
  2. The composite-objective pick:

         score(τ) = recall(τ) - recall_weight × fp_per_hour(τ) / 100

     The recall_weight default of 100 means a 1pp recall drop is
     valued the same as 1 FP/hour saved at the named deployment.
     Tune for the operational reality the same way phase-host-6's
     cost-benefit ranking does.

The model + train partition are exactly what `pipeline.alert_fatigue`
uses, so the picked τ is directly comparable to its FP-budget-based τ.

Output: `data/host/threshold_tune.json` carrying:
  - `pareto`: list of {tau, detect_rate, fp_rate, fp_per_hour[per dep]}
  - `picked`: the composite-objective τ + its metrics
  - `recall_weight` + `deployment_name` used
  - `train_campaigns` + `eval_campaigns`

NEVER reports accuracy.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Optional

import numpy as np
import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline import alert_fatigue as af  # noqa: E402
from pipeline import per_eid_attribution as pea  # noqa: E402


def sweep_thresholds(
    eval_windows: pd.DataFrame, eval_scores: np.ndarray,
    benign_dt_median: float,
    deployments: list[dict],
    tau_grid: Optional[list[float]] = None,
) -> list[dict]:
    """At each τ in the grid, compute detect_rate + per-deployment
    FP/hour. detect_rate is over ATTACK-labeled windows (label=1);
    fp_rate is over BENIGN-labeled windows (label=0)."""
    from detector_v0 import WINDOW_STRIDE
    if tau_grid is None:
        # 0.05 → 0.95 step 0.05 gives 19 points; enough granularity
        # for the Pareto curve without melting CPU.
        tau_grid = [round(0.05 * i, 2) for i in range(1, 20)]

    labels = eval_windows["label"].to_numpy()
    attack_mask = labels == 1
    benign_mask = labels == 0
    n_attack = int(attack_mask.sum())
    n_benign = int(benign_mask.sum())

    out: list[dict] = []
    for tau in tau_grid:
        flagged = eval_scores >= tau
        detect_rate = (
            float(flagged[attack_mask].mean()) if n_attack else float("nan")
        )
        fp_rate = (
            float(flagged[benign_mask].mean()) if n_benign else float("nan")
        )
        per_deployment = []
        for dep in deployments:
            N = dep["hosts"]
            R = dep["events_per_sec_per_host"]
            events_per_hour = N * R * 3600.0
            w_total = events_per_hour / WINDOW_STRIDE
            fp_per_hour = fp_rate * w_total
            per_deployment.append({
                "deployment": dep["name"],
                "hosts": N,
                "events_per_sec_per_host": R,
                "windows_per_hour_continuous": w_total,
                "fp_per_hour": fp_per_hour,
            })
        out.append({
            "tau": tau,
            "detect_rate": detect_rate,
            "fp_rate": fp_rate,
            "per_deployment": per_deployment,
        })
    return out


def pareto_front(curve: list[dict], deployment_name: str) -> list[dict]:
    """Filter `curve` to the Pareto-efficient points wrt
    (detect_rate, fp_per_hour) at the named deployment. Both axes are
    expressed as "higher detect_rate, lower fp_per_hour"."""
    rows: list[tuple[float, float, dict]] = []
    for row in curve:
        fph = next(
            (d["fp_per_hour"] for d in row["per_deployment"]
             if d["deployment"] == deployment_name),
            None,
        )
        if fph is None or row["detect_rate"] != row["detect_rate"]:  # NaN
            continue
        rows.append((row["detect_rate"], fph, row))
    # Sort by detect_rate desc, then walk to keep only points whose
    # fp_per_hour is strictly less than the running minimum.
    rows.sort(key=lambda r: -r[0])
    front: list[dict] = []
    best_fph = float("inf")
    for detect, fph, row in rows:
        if fph < best_fph:
            front.append(row)
            best_fph = fph
    return front


def composite_score(
    row: dict, deployment_name: str, recall_weight: float,
) -> float:
    """`recall - recall_weight × fp_per_hour / 100`. Higher = better."""
    detect = row["detect_rate"]
    if detect != detect:  # NaN
        return float("-inf")
    fph = next(
        (d["fp_per_hour"] for d in row["per_deployment"]
         if d["deployment"] == deployment_name),
        None,
    )
    if fph is None:
        return float("-inf")
    return detect - recall_weight * fph / 100.0


def run(
    data_root: pathlib.Path, *,
    deployments: list[dict],
    deployment_name: Optional[str] = None,
    recall_weight: float = 100.0,
    fp_per_hour_budget: float = 1.0,
    seed: int = 0,
    train_frac: float = 0.75,
) -> dict:
    trained = pea._train_classifier_from_manifest(
        data_root, seed=seed,
        fp_per_hour_budget=fp_per_hour_budget,
        train_frac=train_frac,
    )
    # Rebuild eval windows the same way alert_fatigue does so the
    # detect_rate / fp_rate are over the same partition.
    manifest = af.provenance_host.load(data_root / "manifest.jsonl")
    meta_by_cid = {r["campaign_id"]: r for r in manifest}
    windows_by_cid: dict[str, pd.DataFrame] = {}
    for row in manifest:
        cid = row["campaign_id"]
        norm = af._campaign_normalized(cid, data_root)
        if norm is None or norm.empty:
            continue
        norm = norm.copy()
        norm["label"] = norm.groupby("campaign_id")["label"].transform("max")
        windows = af._windowize_with_tactic(norm)
        if not windows.empty:
            windows_by_cid[cid] = windows
    eval_cids = trained["eval_cids"]
    eval_windows = pd.concat(
        [windows_by_cid[c] for c in eval_cids if c in windows_by_cid],
        ignore_index=True,
    )
    if eval_windows.empty:
        raise SystemExit("[tune_threshold] eval partition is empty")

    Xev = eval_windows[trained["feat_cols"]].to_numpy()
    eval_scores = trained["classifier"].predict_proba(Xev)[:, 1]

    curve = sweep_thresholds(
        eval_windows, eval_scores, trained["benign_dt_median"], deployments,
    )

    target_dep = deployment_name or deployments[0]["name"]
    pareto = pareto_front(curve, target_dep)
    scored = [
        (composite_score(row, target_dep, recall_weight), row)
        for row in curve
    ]
    scored.sort(key=lambda r: -r[0])
    picked_row = scored[0][1] if scored else None

    return {
        "deployments": deployments,
        "deployment_name": target_dep,
        "recall_weight": recall_weight,
        "tau_at_fp_budget": float(trained["tau"]),
        "fp_per_hour_budget": fp_per_hour_budget,
        "train_campaigns": trained["train_cids"],
        "eval_campaigns": eval_cids,
        "pareto": pareto,
        "curve": curve,
        "picked": picked_row,
        "picked_composite_score": (
            scored[0][0] if scored else None
        ),
    }


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    ap.add_argument("--deployments-file", type=pathlib.Path, default=None,
                    help="JSON file from pipeline.calibrate_eventrate. "
                         "Falls back to alert_fatigue's DEFAULT_DEPLOYMENTS.")
    ap.add_argument("--deployment", default=None,
                    help="pick a specific deployment to optimize against; "
                         "defaults to the first in the list")
    ap.add_argument("--recall-weight", type=float, default=100.0,
                    help="composite objective weight (default 100). Higher = "
                         "more sensitive to FP/hour; lower = prioritize recall.")
    ap.add_argument("--fp-budget", type=float, default=1.0,
                    help="FP/hour budget for the comparison τ (the one "
                         "alert_fatigue would pick); included in output for "
                         "audit only.")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--train-frac", type=float, default=0.75)
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host/threshold_tune.json"))
    args = ap.parse_args(argv)

    if args.deployments_file is not None:
        deployments = af.load_deployments_file(args.deployments_file)
    else:
        deployments = af.DEFAULT_DEPLOYMENTS

    report = run(
        args.data_root,
        deployments=deployments,
        deployment_name=args.deployment,
        recall_weight=args.recall_weight,
        fp_per_hour_budget=args.fp_budget,
        seed=args.seed, train_frac=args.train_frac,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    print(f"\n[tune_threshold] wrote {args.out}")
    print(f"  target deployment   = {report['deployment_name']}")
    print(f"  recall_weight       = {report['recall_weight']}")
    print(f"  τ at FP budget {args.fp_budget:.2f} = "
          f"{report['tau_at_fp_budget']:.3f} (alert_fatigue's default)")
    picked = report.get("picked")
    if picked is not None:
        pd_row = next(
            (d for d in picked["per_deployment"]
             if d["deployment"] == report["deployment_name"]),
            {},
        )
        print(f"  composite-picked τ  = {picked['tau']:.3f}  "
              f"detect_rate={picked['detect_rate']:.3f}  "
              f"fp_per_hour={pd_row.get('fp_per_hour', 0):.2f}/h")
        print(f"  composite score     = "
              f"{report['picked_composite_score']:.4f}")
    print()
    pareto = report.get("pareto") or []
    print(f"  Pareto frontier     = {len(pareto)} points")
    for r in pareto[:6]:
        pd_row = next(
            (d for d in r["per_deployment"]
             if d["deployment"] == report["deployment_name"]),
            {},
        )
        print(f"    τ={r['tau']:.2f}  detect={r['detect_rate']:.3f}  "
              f"fp/h={pd_row.get('fp_per_hour', 0):.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
