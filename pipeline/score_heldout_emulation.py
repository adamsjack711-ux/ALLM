"""Held-out emulation family eval: train CALDERA, eval Atomic (and reverse).

The mirror of phase 8's held-out-attacker / held-out-benign-family eval
on the web side. Forces the detector to generalize across emulation
frameworks rather than overfitting to whichever one it saw at training.

For each direction:
  - Train detector_v0 (HistGradientBoostingClassifier) on the train
    framework's attack campaigns plus ALL benign campaigns (normal +
    hard_negative). Hard-negative campaigns ARE included in train so
    the model sees the "looks scary, isn't" pattern at least once.
  - Pick τ to meet the FP/hour budget on a held-out validation slice
    (last 25% of train, by ts_start). The eval-framework attack
    campaigns are NEVER seen during training or threshold-pick.
  - Score the eval framework's attack campaigns. Report:
      * pr_auc on eval set
      * fp_per_hour on eval set
      * per-tactic macro recall on eval set (tactics in scope only)
      * hard-negative FP rate, broken down by benign_subtype, computed
        on whichever hard-negative campaigns landed in eval

Then swap directions and report the symmetric numbers.

Inputs: every campaign whose provenance row lives in
data/host/manifest.jsonl, with sysmon.jsonl + the matching metadata
file present.

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

from pipeline import (
    atomic_to_labels as atl,
    caldera_op_to_labels as col,
    ingest_sysmon,
    provenance_host,
    score_campaign,
)


SIX_TACTICS = (
    "recon", "discovery", "credential_access",
    "command_execution", "lateral_movement", "exfiltration",
)


def _load_campaign_norm(
    campaign_id: str, data_root: pathlib.Path
) -> Optional[pd.DataFrame]:
    """Load one campaign + normalize. Returns None on failure."""
    campaign_dir = data_root / campaign_id
    sysmon_path = campaign_dir / "sysmon.jsonl"
    if not sysmon_path.exists():
        return None
    try:
        source, meta_path = score_campaign._detect_source(campaign_dir)
    except SystemExit:
        return None
    sysmon_df = ingest_sysmon.load_sysmon(sysmon_path)

    malicious_guids: Optional[set] = None
    if source == "caldera":
        labels = col.resolve_labels(col.load_caldera_op(meta_path), sysmon_df)
        malicious_guids = labels.malicious_guids
    elif source == "atomic":
        labels = atl.resolve_labels(
            atl.load_atomic_invocations(meta_path), sysmon_df
        )
        malicious_guids = labels.malicious_guids
    # workload: no labels — label stays 0 in adapter

    norm = ingest_sysmon.normalize(
        sysmon_df, malicious_guids=malicious_guids,
        campaign_id=campaign_id,
    )
    return norm


def _windowize_with_tactic(norm: pd.DataFrame) -> pd.DataFrame:
    from detector_v0 import windowize
    windows = windowize(norm)
    windows = score_campaign._add_window_tactic(norm, windows)
    return windows


def _pick_tau(scores: np.ndarray, y: np.ndarray, sessions_secs: float,
              fp_per_hour_budget: float) -> float:
    fp_allowed = max(0.0, fp_per_hour_budget * sessions_secs / 3600.0)
    order = np.argsort(-scores)
    cum_fp = 0
    chosen = 1.0
    for i in order:
        if y[i] == 0:
            cum_fp += 1
        if cum_fp <= fp_allowed:
            chosen = float(scores[i])
        else:
            break
    return chosen


def _train_and_eval(
    train_windows: pd.DataFrame,
    eval_windows: pd.DataFrame,
    fp_per_hour_budget: float,
    seed: int,
) -> dict:
    """Train HistGradientBoostingClassifier on train, score on eval.

    Returns: pr_auc, fp_per_hour, threshold, per_tactic recall,
    per_class metrics. NEVER returns accuracy.
    """
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import average_precision_score

    feat_cols = [c for c in train_windows.columns
                 if c not in ("campaign_id", "label", "tactic")]
    Xtr = train_windows[feat_cols].to_numpy()
    ytr = train_windows["label"].to_numpy()
    Xev = eval_windows[feat_cols].to_numpy()
    yev = eval_windows["label"].to_numpy()

    if ytr.sum() == 0 or (ytr == 0).sum() == 0:
        return {"skipped": "train set is single-class"}

    pos = ytr.mean()
    sample_w = np.where(ytr == 1, (1 - pos) / pos, 1.0) if 0 < pos < 1 else None
    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.06, max_depth=6,
        l2_regularization=1.0, random_state=seed,
    )
    clf.fit(Xtr, ytr, sample_weight=sample_w)

    if yev.size == 0:
        return {"skipped": "eval set is empty"}
    scores = clf.predict_proba(Xev)[:, 1]
    pr_auc = (float(average_precision_score(yev, scores))
              if (yev.sum() > 0 and (yev == 0).sum() > 0) else float("nan"))

    # rough session-seconds for FP/hour denominator: WINDOW_EVENTS *
    # median dt_median in benign eval windows
    from detector_v0 import WINDOW_EVENTS
    benign_dt = eval_windows.loc[eval_windows.label == 0, "dt_median"].median()
    secs_per_window = max(1.0, WINDOW_EVENTS * (benign_dt or 1.0))
    eval_seconds = len(yev) * secs_per_window
    tau = _pick_tau(scores, yev, eval_seconds, fp_per_hour_budget)

    pred = (scores >= tau).astype(int)
    n_fp = int(((pred == 1) & (yev == 0)).sum())
    fp_per_hour = n_fp / max(eval_seconds / 3600.0, 1e-9)

    # per-tactic recall on eval (only counts windows with label==1)
    per_tactic: dict[str, dict] = {}
    if "tactic" in eval_windows.columns:
        for tac in SIX_TACTICS:
            mask = (eval_windows["tactic"].to_numpy() == tac) & (yev == 1)
            n = int(mask.sum())
            if n == 0:
                continue
            hits = int(((scores >= tau) & mask).sum())
            per_tactic[tac] = {
                "n_attack_windows": n,
                "recall": hits / n,
            }
    macro_recall = (float(np.mean([v["recall"] for v in per_tactic.values()]))
                    if per_tactic else None)

    return {
        "pr_auc": pr_auc,
        "threshold": float(tau),
        "fp_count_eval": n_fp,
        "fp_per_hour": float(fp_per_hour),
        "eval_window_count": int(len(yev)),
        "eval_pos": int(yev.sum()),
        "eval_neg": int((yev == 0).sum()),
        "per_tactic": per_tactic,
        "per_tactic_macro_recall": macro_recall,
    }


def _hard_negative_fp_breakdown(
    eval_windows: pd.DataFrame, manifest_rows: list[dict],
    scores: np.ndarray, tau: float,
) -> dict:
    """Per-benign_subtype FP rate from eval windows that come from
    hard_negative campaigns. Returns {} if no hard-negatives in eval."""
    cid_to_meta = {r["campaign_id"]: r for r in manifest_rows}
    out: dict[str, dict] = {}
    for cid, g in eval_windows.groupby("campaign_id"):
        meta = cid_to_meta.get(cid, {})
        if meta.get("class") != "hard_negative":
            continue
        bsub = meta.get("benign_subtype") or "unknown"
        idx = g.index.to_numpy()
        n = int(len(idx))
        fp = int((scores[idx] >= tau).sum())
        entry = out.setdefault(
            bsub, {"campaigns": [], "windows": 0, "fp_count": 0})
        entry["campaigns"].append(cid)
        entry["windows"] += n
        entry["fp_count"] += fp
    for bsub, entry in out.items():
        entry["fp_rate"] = entry["fp_count"] / max(entry["windows"], 1)
    return out


def run(
    data_root: pathlib.Path,
    fp_per_hour_budget: float,
    seed: int,
) -> dict:
    manifest_path = data_root / "manifest.jsonl"
    manifest_rows = provenance_host.load(manifest_path)
    if not manifest_rows:
        raise SystemExit(
            f"[heldout-emulation] empty manifest at {manifest_path}. "
            "Run score_campaign.py on at least one CALDERA + one Atomic + "
            "some benign campaigns first."
        )

    # group campaigns by framework + class
    by_framework: dict[str, list[dict]] = {"caldera": [], "atomic": []}
    benign_rows: list[dict] = []
    for row in manifest_rows:
        klass = row.get("class")
        framework = row.get("framework") or row.get("generator")
        if klass == "attack" and framework in by_framework:
            by_framework[framework].append(row)
        elif klass in ("normal", "hard_negative"):
            benign_rows.append(row)

    if not by_framework["caldera"] or not by_framework["atomic"]:
        return {
            "skipped":
                f"need ≥1 CALDERA and ≥1 Atomic attack campaign, got "
                f"caldera={len(by_framework['caldera'])} "
                f"atomic={len(by_framework['atomic'])}",
            "manifest_rows": len(manifest_rows),
        }
    if not benign_rows:
        return {
            "skipped": "no benign campaigns (normal / hard_negative) in manifest",
            "manifest_rows": len(manifest_rows),
        }

    # load + windowize per campaign (cached)
    windows_by_cid: dict[str, pd.DataFrame] = {}
    for row in manifest_rows:
        cid = row["campaign_id"]
        norm = _load_campaign_norm(cid, data_root)
        if norm is None or norm.empty:
            continue
        norm = norm.copy()
        norm["label"] = norm.groupby("campaign_id")["label"].transform("max")
        w = _windowize_with_tactic(norm)
        if not w.empty:
            windows_by_cid[cid] = w

    def _stack(rows: list[dict]) -> pd.DataFrame:
        parts = [windows_by_cid[r["campaign_id"]] for r in rows
                 if r["campaign_id"] in windows_by_cid]
        if not parts:
            return pd.DataFrame()
        return pd.concat(parts, ignore_index=True)

    benign_windows = _stack(benign_rows)
    if benign_windows.empty:
        return {"skipped": "benign campaigns produced no windows"}

    results: dict[str, dict] = {}
    for train_fw, eval_fw in (("caldera", "atomic"), ("atomic", "caldera")):
        train_attack = _stack(by_framework[train_fw])
        eval_attack = _stack(by_framework[eval_fw])
        if train_attack.empty or eval_attack.empty:
            results[f"train_{train_fw}_eval_{eval_fw}"] = {
                "skipped": "empty train or eval attack windows"
            }
            continue
        # split benign into 75% train / 25% eval by ts_start order so the
        # eval set isn't all-attack and the FP/hour denominator is meaningful
        benign_sorted = benign_windows.sort_values("campaign_id")
        n_benign = len(benign_sorted)
        cut = max(1, int(0.75 * n_benign))
        benign_train = benign_sorted.iloc[:cut]
        benign_eval = benign_sorted.iloc[cut:]
        train_windows = pd.concat([train_attack, benign_train], ignore_index=True)
        eval_windows = pd.concat([eval_attack, benign_eval], ignore_index=True)

        result = _train_and_eval(
            train_windows, eval_windows, fp_per_hour_budget, seed=seed,
        )
        if "skipped" not in result:
            # hard-negative FP slice — re-score eval to get aligned indices
            from sklearn.ensemble import HistGradientBoostingClassifier
            feat_cols = [c for c in train_windows.columns
                         if c not in ("campaign_id", "label", "tactic")]
            Xtr = train_windows[feat_cols].to_numpy()
            ytr = train_windows["label"].to_numpy()
            Xev = eval_windows[feat_cols].to_numpy()
            pos = ytr.mean()
            sample_w = (np.where(ytr == 1, (1 - pos) / pos, 1.0)
                        if 0 < pos < 1 else None)
            clf = HistGradientBoostingClassifier(
                max_iter=300, learning_rate=0.06, max_depth=6,
                l2_regularization=1.0, random_state=seed,
            )
            clf.fit(Xtr, ytr, sample_weight=sample_w)
            scores_eval = clf.predict_proba(Xev)[:, 1]
            eval_reset = eval_windows.reset_index(drop=True)
            hardneg = _hard_negative_fp_breakdown(
                eval_reset, manifest_rows, scores_eval, result["threshold"],
            )
            result["hard_negative_fp_by_subtype"] = hardneg

        results[f"train_{train_fw}_eval_{eval_fw}"] = result

    return {
        "fp_per_hour_budget": fp_per_hour_budget,
        "campaigns_by_framework": {
            fw: [r["campaign_id"] for r in rows]
            for fw, rows in by_framework.items()
        },
        "benign_campaigns": [r["campaign_id"] for r in benign_rows],
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    ap.add_argument("--fp-budget", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host/heldout_emulation.json"))
    args = ap.parse_args(argv)

    report = run(args.data_root, args.fp_budget, args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    print(f"\n[heldout-emulation] wrote {args.out}")
    if "skipped" in report:
        print(f"[heldout-emulation] SKIPPED: {report['skipped']}")
        return 0
    for direction, r in report["results"].items():
        if "skipped" in r:
            print(f"  {direction}: SKIPPED ({r['skipped']})")
            continue
        print(f"  {direction}:")
        print(f"     PR-AUC = {r['pr_auc']:.3f}  FP/hour = {r['fp_per_hour']:.2f}  "
              f"τ = {r['threshold']:.3f}")
        print(f"     per-tactic macro recall = "
              f"{r.get('per_tactic_macro_recall') or 'nan'}")
        for tac, t in r["per_tactic"].items():
            print(f"        {tac:>20}  recall={t['recall']:.2f}  "
                  f"n={t['n_attack_windows']}")
        hardneg = r.get("hard_negative_fp_by_subtype") or {}
        if hardneg:
            print(f"     hard-negative FP (per subtype):")
            for sub, d in hardneg.items():
                print(f"        {sub:>20}  fp_rate={d['fp_rate']:.2f}  "
                      f"windows={d['windows']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
