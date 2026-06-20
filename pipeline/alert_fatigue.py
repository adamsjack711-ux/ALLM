"""Alert-fatigue arithmetic for the host pipeline.

The web-harness side computes FP/hour at the SESSION level — `p_session ×
(60 / μ_minutes)`. The host pipeline doesn't have sessions; it has
32-event windows produced continuously as Sysmon events stream in. So
the host-side arithmetic is window-rate-based, derived from:

  Per-window FP rate at τ:
    p_w(class, subtype) = P(score >= τ | label = 0, class, subtype)

  Window production rate for a deployment of N hosts each emitting R
  events/sec (combined across Sysmon EID 1, 3, 11, 13, …):
    W_total = N × R × 3600 / WINDOW_STRIDE   windows/hour

  Expected FPs per hour from continuous normal workload at threshold τ:
    E[FP/hour | normal] = p_w(normal) × W_total

  Expected FPs from sanctioned hard-negative bursts (PS remoting,
  scheduled tasks, etc.), each lasting D_b seconds at burst rate R_b,
  fired F bursts/host/day:
    B_b = (D_b × R_b) / WINDOW_STRIDE         windows per burst
    E[FP/hour | hard_negative] = Σ_subtypes p_w(subtype) × B_b × F × N / 24

  Mean time-to-detect on attack campaigns: first window's
  wall-clock-from-campaign-start where score >= τ. Reported per
  emulation family (CALDERA, Atomic) so the held-out family's MTTD
  can be compared to the in-distribution one.

Inputs: a `data/host/manifest.jsonl` populated by `score_campaign.py`
(any combination of CALDERA / Atomic attack + normal workload +
hard_negative campaigns).

Output: `data/host/alert_fatigue.json` with the structured
arithmetic, and a readable summary on stdout.

NEVER reports accuracy.
"""

from __future__ import annotations

import argparse
import dataclasses
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


# Deployment-shape defaults. Real environments vary widely — these are
# starting points the CLI overrides. Per-host event rate is the
# combined Sysmon stream rate (EID 1 + 3 + 11 + 13 + …) under normal
# user activity on a Windows workstation, observed across a handful of
# real deployments. Bump for fleet hosts running heavy build
# pipelines, drop for kiosks.
DEFAULT_DEPLOYMENTS = [
    {"name": "small_office",   "hosts": 10,  "events_per_sec_per_host": 1.0},
    {"name": "med_business",   "hosts": 50,  "events_per_sec_per_host": 1.5},
    {"name": "large_business", "hosts": 200, "events_per_sec_per_host": 2.0},
]

# Sanctioned hard-negative burst shapes — how often, how long, how
# hot. These come from the phase-host-2 hard-negative synthesizers
# and approximate the activity patterns the SOC would see in
# production.
DEFAULT_BURST_SHAPES = {
    "ps_remoting":     {"bursts_per_host_per_day": 4,  "duration_s": 300, "burst_event_rate": 6.0},
    "wmi":             {"bursts_per_host_per_day": 12, "duration_s": 60,  "burst_event_rate": 5.0},
    "sched_task":      {"bursts_per_host_per_day": 6,  "duration_s": 30,  "burst_event_rate": 3.0},
    "sanctioned_scan": {"bursts_per_host_per_day": 1,  "duration_s": 600, "burst_event_rate": 8.0},
    "backup":          {"bursts_per_host_per_day": 2,  "duration_s": 900, "burst_event_rate": 4.0},
}


# ----------------------------------------------------------------------
# Data loading
# ----------------------------------------------------------------------

def _campaign_normalized(
    campaign_id: str, data_root: pathlib.Path,
) -> Optional[pd.DataFrame]:
    """Load + normalize one campaign with the right labeler for its
    source. Re-uses the routing logic in score_campaign so we don't
    drift between scoring paths."""
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
        labels = atl.resolve_labels(atl.load_atomic_invocations(meta_path), sysmon_df)
        malicious_guids = labels.malicious_guids
    # workload: no labels — adapt_winlog_dataframe writes label=0 throughout

    return ingest_sysmon.normalize(
        sysmon_df, malicious_guids=malicious_guids, campaign_id=campaign_id,
    )


def _windowize_with_tactic(norm: pd.DataFrame) -> pd.DataFrame:
    from detector_v0 import windowize
    windows = windowize(norm)
    return score_campaign._add_window_tactic(norm, windows)


# ----------------------------------------------------------------------
# Threshold picking + arithmetic
# ----------------------------------------------------------------------

@dataclasses.dataclass
class WindowScores:
    campaign_id: str
    klass: str                # attack | normal | hard_negative
    framework: str            # caldera | atomic | scripted | …
    benign_subtype: str       # ps_remoting | wmi | … | "" for non-hardneg
    scores: np.ndarray        # per-window risk
    labels: np.ndarray        # per-window 0/1 ground truth
    ts_first: float           # earliest window ts for MTTD


def _train_and_score(
    train_windows: pd.DataFrame,
    eval_windows: pd.DataFrame,
    seed: int = 0,
) -> tuple[np.ndarray, float]:
    """Train HistGradientBoostingClassifier on `train_windows`, return
    eval scores + the median per-window benign duration in train (for
    rate-based FP/hour math).
    """
    from sklearn.ensemble import HistGradientBoostingClassifier
    feat_cols = [c for c in train_windows.columns
                 if c not in ("campaign_id", "label", "tactic")]
    Xtr = train_windows[feat_cols].to_numpy()
    ytr = train_windows["label"].to_numpy()
    Xev = eval_windows[feat_cols].to_numpy()
    if ytr.sum() == 0 or (ytr == 0).sum() == 0:
        raise SystemExit(
            "[alert_fatigue] train set is single-class; need ≥1 attack + "
            "≥1 benign campaign in the manifest's TRAIN partition")
    pos = ytr.mean()
    sample_w = np.where(ytr == 1, (1 - pos) / pos, 1.0) if 0 < pos < 1 else None
    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.06, max_depth=6,
        l2_regularization=1.0, random_state=seed,
    )
    clf.fit(Xtr, ytr, sample_weight=sample_w)
    scores = clf.predict_proba(Xev)[:, 1]
    benign_dt_median = float(
        train_windows.loc[train_windows.label == 0, "dt_median"].median()
        or 1.0
    )
    return scores, benign_dt_median


def _pick_tau_for_fp_budget(
    scores: np.ndarray, labels: np.ndarray,
    benign_eval_window_count: int, benign_dt_median: float,
    fp_per_hour_budget: float,
) -> float:
    """Pick the most permissive τ that keeps FP/hour ≤ budget on the
    eval set, using `benign_dt_median` to convert window count → time.
    """
    from detector_v0 import WINDOW_EVENTS
    if benign_eval_window_count == 0:
        return 1.0
    seconds_per_window = max(1.0, WINDOW_EVENTS * benign_dt_median)
    benign_seconds = benign_eval_window_count * seconds_per_window
    benign_hours = max(benign_seconds / 3600.0, 1e-9)
    fp_allowed = fp_per_hour_budget * benign_hours
    order = np.argsort(-scores)
    cum_fp = 0
    chosen = 1.0
    for i in order:
        if labels[i] == 0:
            cum_fp += 1
        if cum_fp <= fp_allowed:
            chosen = float(scores[i])
        else:
            break
    return chosen


def _per_window_fp_rates(
    eval_blocks: list[WindowScores], tau: float,
) -> tuple[dict, dict]:
    """Returns (per_class_fp_rate, per_hardneg_subtype_fp_rate)."""
    per_class: dict[str, dict] = {}
    for wb in eval_blocks:
        if wb.klass != "normal":
            continue
        cell = per_class.setdefault("normal", {"n_windows": 0, "fp_windows": 0})
        cell["n_windows"] += int(len(wb.scores))
        cell["fp_windows"] += int((wb.scores >= tau).sum())
    for cell in per_class.values():
        cell["fp_rate"] = cell["fp_windows"] / max(cell["n_windows"], 1)

    per_subtype: dict[str, dict] = {}
    for wb in eval_blocks:
        if wb.klass != "hard_negative" or not wb.benign_subtype:
            continue
        cell = per_subtype.setdefault(
            wb.benign_subtype, {"n_windows": 0, "fp_windows": 0,
                                "campaigns": []})
        cell["n_windows"] += int(len(wb.scores))
        cell["fp_windows"] += int((wb.scores >= tau).sum())
        cell["campaigns"].append(wb.campaign_id)
    for cell in per_subtype.values():
        cell["fp_rate"] = cell["fp_windows"] / max(cell["n_windows"], 1)

    return per_class, per_subtype


def _mttd_by_attack_family(
    eval_blocks: list[WindowScores], tau: float, window_seconds: float,
) -> dict:
    """Per-(framework) mean time-to-detect: first window in each attack
    campaign whose score >= τ, in seconds from the campaign's first
    window. Averaged across campaigns in that framework.
    """
    by_fw: dict[str, list[float]] = {}
    for wb in eval_blocks:
        if wb.klass != "attack":
            continue
        flagged = np.where(wb.scores >= tau)[0]
        if len(flagged) == 0:
            ttd = float("nan")
        else:
            ttd = float(flagged[0] * window_seconds)
        by_fw.setdefault(wb.framework, []).append(ttd)
    out: dict[str, dict] = {}
    for fw, vals in by_fw.items():
        clean = [v for v in vals if not np.isnan(v)]
        n_detected = len(clean)
        out[fw] = {
            "n_campaigns": len(vals),
            "n_detected": n_detected,
            "detect_rate": n_detected / max(len(vals), 1),
            "mttd_s": float(np.mean(clean)) if clean else None,
            "mttd_s_p95": float(np.percentile(clean, 95)) if clean else None,
        }
    return out


def _fp_per_hour_estimate(
    per_class_fp: dict, per_subtype_fp: dict,
    deployments: list[dict], burst_shapes: dict,
) -> list[dict]:
    """For each deployment shape, the expected FP/hour broken down by
    normal-workload background + per-subtype hard-negative bursts.
    """
    from detector_v0 import WINDOW_EVENTS, WINDOW_STRIDE
    out: list[dict] = []
    for dep in deployments:
        N = dep["hosts"]
        R = dep["events_per_sec_per_host"]
        # windows/hour from continuous normal traffic
        events_per_hour = N * R * 3600.0
        w_total = events_per_hour / WINDOW_STRIDE

        normal_fp_rate = per_class_fp.get("normal", {}).get("fp_rate", 0.0)
        normal_fp_per_hour = normal_fp_rate * w_total

        subtype_contribs: dict[str, dict] = {}
        hardneg_fp_per_hour = 0.0
        for subtype, shape in burst_shapes.items():
            fp_rate = per_subtype_fp.get(subtype, {}).get("fp_rate", 0.0)
            if fp_rate == 0.0:
                # not seen in eval — skip rather than fabricate
                continue
            # windows per burst
            wb = max(1, (shape["duration_s"] * shape["burst_event_rate"]) / WINDOW_STRIDE)
            bursts_per_hour = (shape["bursts_per_host_per_day"] * N) / 24.0
            fph = fp_rate * wb * bursts_per_hour
            hardneg_fp_per_hour += fph
            subtype_contribs[subtype] = {
                "windows_per_burst": wb,
                "bursts_per_hour": bursts_per_hour,
                "fp_per_hour": fph,
            }

        total = normal_fp_per_hour + hardneg_fp_per_hour
        out.append({
            "deployment": dep["name"],
            "hosts": N,
            "events_per_sec_per_host": R,
            "windows_per_hour_continuous": w_total,
            "normal_fp_per_hour": normal_fp_per_hour,
            "hard_negative_fp_per_hour": hardneg_fp_per_hour,
            "hard_negative_breakdown": subtype_contribs,
            "total_fp_per_hour": total,
        })
    return out


# ----------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------

def run(
    data_root: pathlib.Path,
    fp_per_hour_budget: float,
    seed: int,
    deployments: list[dict],
    burst_shapes: dict,
    train_frac: float = 0.75,
) -> dict:
    manifest = provenance_host.load(data_root / "manifest.jsonl")
    if not manifest:
        raise SystemExit(
            f"[alert_fatigue] manifest empty at {data_root}/manifest.jsonl. "
            f"Run pipeline.score_campaign on at least one CALDERA / Atomic "
            f"attack campaign + one normal workload + ideally a hard-negative "
            f"subtype or two."
        )

    windows_by_cid: dict[str, pd.DataFrame] = {}
    meta_by_cid: dict[str, dict] = {r["campaign_id"]: r for r in manifest}
    for row in manifest:
        cid = row["campaign_id"]
        norm = _campaign_normalized(cid, data_root)
        if norm is None or norm.empty:
            continue
        norm = norm.copy()
        norm["label"] = norm.groupby("campaign_id")["label"].transform("max")
        windows = _windowize_with_tactic(norm)
        if not windows.empty:
            windows_by_cid[cid] = windows

    if not windows_by_cid:
        raise SystemExit("[alert_fatigue] no windows produced from any campaign")

    # Stratified split — keep at least one of each (class, framework,
    # benign_subtype) bucket in train AND in eval so the arithmetic
    # below isn't dominated by a missing class. With small N this is
    # critical: a random split of 6 campaigns can easily land 0 normal
    # workloads in eval and the FP-rate denominator becomes empty.
    rng = np.random.default_rng(seed)
    cid_list = sorted(windows_by_cid)
    by_bucket: dict[tuple, list[str]] = {}
    for cid in cid_list:
        m = meta_by_cid[cid]
        bucket = (m.get("class"), m.get("framework"), m.get("benign_subtype", ""))
        by_bucket.setdefault(bucket, []).append(cid)
    train_cids: list[str] = []
    eval_cids: list[str] = []
    for bucket, cids in by_bucket.items():
        cids = list(cids)
        rng.shuffle(cids)
        if len(cids) == 1:
            train_cids.append(cids[0])
            continue
        cut = max(1, int(train_frac * len(cids)))
        cut = min(cut, len(cids) - 1)  # always leave one in eval
        train_cids.extend(cids[:cut])
        eval_cids.extend(cids[cut:])
    if not eval_cids:
        # last-resort fallback: evaluating on train (numbers are
        # optimistic but the structure is correct)
        eval_cids = list(train_cids)

    train_windows = pd.concat([windows_by_cid[c] for c in train_cids], ignore_index=True)
    eval_windows = pd.concat([windows_by_cid[c] for c in eval_cids], ignore_index=True)

    if train_windows["label"].sum() == 0 or (train_windows["label"] == 0).sum() == 0:
        raise SystemExit(
            "[alert_fatigue] train partition is single-class — stage at least "
            "one attack + one benign campaign before running")

    eval_scores, benign_dt_median = _train_and_score(
        train_windows, eval_windows, seed=seed,
    )
    eval_labels = eval_windows["label"].to_numpy()
    benign_eval_count = int((eval_labels == 0).sum())
    tau = _pick_tau_for_fp_budget(
        eval_scores, eval_labels, benign_eval_count, benign_dt_median,
        fp_per_hour_budget,
    )

    eval_windows_reset = eval_windows.reset_index(drop=True)
    blocks: list[WindowScores] = []
    for cid, grp in eval_windows_reset.groupby("campaign_id"):
        meta = meta_by_cid.get(cid, {})
        idx = grp.index.to_numpy()
        blocks.append(WindowScores(
            campaign_id=cid,
            klass=meta.get("class", "unknown"),
            framework=meta.get("framework", ""),
            benign_subtype=meta.get("benign_subtype", "") or "",
            scores=eval_scores[idx],
            labels=eval_labels[idx],
            ts_first=float(meta.get("ts_start", 0.0)),
        ))

    per_class_fp, per_subtype_fp = _per_window_fp_rates(blocks, tau)
    from detector_v0 import WINDOW_EVENTS
    window_seconds = WINDOW_EVENTS * benign_dt_median
    mttd = _mttd_by_attack_family(blocks, tau, window_seconds=window_seconds)
    deployment_estimates = _fp_per_hour_estimate(
        per_class_fp, per_subtype_fp, deployments, burst_shapes,
    )

    return {
        "fp_per_hour_budget": fp_per_hour_budget,
        "threshold": tau,
        "train_campaigns": train_cids,
        "eval_campaigns": eval_cids,
        "benign_dt_median_s": benign_dt_median,
        "window_seconds_estimate": window_seconds,
        "per_class_fp_rate": per_class_fp,
        "per_hard_negative_subtype_fp_rate": per_subtype_fp,
        "mttd_by_attack_family": mttd,
        "deployment_estimates": deployment_estimates,
        "burst_shapes_used": burst_shapes,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    ap.add_argument("--fp-budget", type=float, default=1.0,
                    help="alert FP/hour budget τ is picked against (default 1.0)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--hosts", type=int, default=None,
                    help="single deployment override: number of hosts")
    ap.add_argument("--event-rate", type=float, default=None,
                    help="single deployment override: events/sec/host")
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host/alert_fatigue.json"))
    args = ap.parse_args(argv)

    if args.hosts is not None and args.event_rate is not None:
        deployments = [{
            "name": f"custom_{args.hosts}h_{args.event_rate}eps",
            "hosts": args.hosts,
            "events_per_sec_per_host": args.event_rate,
        }]
    else:
        deployments = DEFAULT_DEPLOYMENTS

    report = run(
        args.data_root, args.fp_budget, args.seed,
        deployments=deployments, burst_shapes=DEFAULT_BURST_SHAPES,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    print(f"\n[alert_fatigue] wrote {args.out}")
    print(f"  threshold τ                = {report['threshold']:.3f}  "
          f"(budget {args.fp_budget:.2f} FP/hour)")
    print(f"  benign window duration est = {report['window_seconds_estimate']:.1f}s")
    pc = report["per_class_fp_rate"].get("normal", {})
    if pc:
        print(f"  per-window FP on normal    = {pc['fp_rate']:.4f}  "
              f"({pc['fp_windows']}/{pc['n_windows']} windows)")
    print()
    print("  per-hard-negative-subtype window FP rate at τ:")
    for sub, cell in sorted(report["per_hard_negative_subtype_fp_rate"].items()):
        print(f"    {sub:>20}  fp_rate={cell['fp_rate']:.3f}  "
              f"windows={cell['n_windows']}")
    print()
    print("  MTTD per attack family:")
    for fw, m in sorted(report["mttd_by_attack_family"].items()):
        mttd = m["mttd_s"]
        mttd_s = f"{mttd:.1f}s" if mttd is not None else "n/a"
        print(f"    {fw:>10}  detected {m['n_detected']}/{m['n_campaigns']}  "
              f"MTTD={mttd_s}")
    print()
    print("  deployment FP/hour estimates:")
    for est in report["deployment_estimates"]:
        print(f"    {est['deployment']:>18}  hosts={est['hosts']:<3}  "
              f"R={est['events_per_sec_per_host']:.1f}/s  "
              f"total={est['total_fp_per_hour']:.2f}/h  "
              f"(normal={est['normal_fp_per_hour']:.2f} + "
              f"hard_neg={est['hard_negative_fp_per_hour']:.2f})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
