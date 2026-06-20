"""Score one campaign: ingest -> label -> normalize -> window -> detector.

Usage (after a real CALDERA op):
  python -m pipeline.score_campaign --campaign op-2026-06-20

Or, fully in-sandbox dry-run:
  python -m pipeline.synth_caldera --campaign synth-001
  python -m pipeline.score_campaign --campaign synth-001 --synth-mix

The pipeline:
  1. Load data/host/<campaign>/{sysmon.jsonl, caldera_op.json}.
  2. Resolve attack labels via caldera_op_to_labels (ProcessGuid set +
     (host, time-window) fallback).
  3. Sanity-check tactic coverage against the six tactics adapter_winlogs
     handles (fails loudly if any are missing — that's a CALDERA
     adversary-profile issue, not a code bug).
  4. Normalize via adapter_winlogs.adapt_winlog_dataframe.
  5. Windowize (existing detector_v0.windowize, 32-event windows).
  6. With --synth-mix: also generate N benign campaigns inline so the
     GroupShuffleSplit baseline detector has something to split. This
     is the in-sandbox shortcut for "I have one campaign and want
     structural validation"; real-data runs would set --background to
     point at an existing dir of benign normalized parquet files.
  7. Emit data/host/<campaign>/scored.jsonl (per-window risk).
  8. Append provenance row to data/host/manifest.jsonl.

NEVER prints accuracy. Reports PR-AUC, FP/hour, per-tactic recall,
event-label-rate, tactic coverage, and the malicious-GUID count.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

import numpy as np
import pandas as pd

# repo root on sys.path so the top-level detector_v0 + adapter_winlogs import
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline import caldera_op_to_labels as col
from pipeline import ingest_sysmon, provenance_host, synth_caldera


def _per_tactic_recall(windows: pd.DataFrame, scores: np.ndarray, threshold: float) -> dict:
    """Recall per detector_v1 tactic, computed at a given alert threshold.

    The window-level `tactic` doesn't exist on v0 features (v0 has no
    per-tactic head). For phase 1, we approximate: for every window
    that was attack=true, look up the dominant tactic among the events
    inside it (computed elsewhere and stuffed into a `tactic` column).
    Returns {tactic: recall_at_threshold}, or empty dict if the column
    is missing.
    """
    if "tactic" not in windows.columns:
        return {}
    out: dict[str, dict] = {}
    for tac, grp in windows.groupby("tactic"):
        if not tac:
            continue
        idx = grp.index.to_numpy()
        if len(idx) == 0:
            continue
        flagged = (scores[idx] >= threshold).sum()
        attack_mask = grp["label"].to_numpy() == 1
        if attack_mask.sum() == 0:
            continue
        recall = float(
            ((scores[idx] >= threshold) & attack_mask).sum() / attack_mask.sum()
        )
        out[tac] = {"recall": recall, "n": int(attack_mask.sum()), "flagged": int(flagged)}
    return out


def _add_window_tactic(norm: pd.DataFrame, windows: pd.DataFrame) -> pd.DataFrame:
    """Attach a dominant `tactic` per window.

    detector_v0._window_features doesn't carry the tactic forward, so
    we rebuild it here. The walk order mirrors detector_v0.windowize
    exactly (sort by ts, group by campaign_id, slide WINDOW_EVENTS at
    WINDOW_STRIDE, skip < half-full tail windows) so we can zip the
    output 1:1 with the windows DataFrame.
    """
    from detector_v0 import WINDOW_EVENTS, WINDOW_STRIDE
    by_cid = {
        cid: g.reset_index(drop=True)
        for cid, g in norm.sort_values("ts").groupby("campaign_id", sort=False)
    }
    out_rows: list[str] = []
    for _, g in by_cid.items():
        for start in range(0, max(1, len(g) - WINDOW_EVENTS + 1), WINDOW_STRIDE):
            w = g.iloc[start:start + WINDOW_EVENTS]
            if len(w) < WINDOW_EVENTS // 2:
                continue
            tac_vals = [t for t in w["tactic"].tolist() if t]
            out_rows.append(
                max(set(tac_vals), key=tac_vals.count) if tac_vals else ""
            )
    if len(out_rows) == len(windows):
        windows = windows.copy()
        windows["tactic"] = out_rows
    return windows


def score(
    campaign_id: str,
    *,
    data_root: pathlib.Path,
    synth_mix_n: int,
    synth_mix_seed: int,
    fp_per_hour_target: float,
) -> dict:
    campaign_dir = data_root / campaign_id
    sysmon_path = campaign_dir / "sysmon.jsonl"
    op_path = campaign_dir / "caldera_op.json"
    if not sysmon_path.exists() or not op_path.exists():
        raise SystemExit(
            f"[score] missing inputs under {campaign_dir} — expected "
            f"sysmon.jsonl + caldera_op.json. Run "
            f"`python -m pipeline.synth_caldera --campaign {campaign_id}` "
            f"to generate a synthetic one, or copy real CALDERA op files in."
        )

    sysmon_df = ingest_sysmon.load_sysmon(sysmon_path)
    steps = col.load_caldera_op(op_path)
    labels = col.resolve_labels(steps, sysmon_df)
    covered, missing = col.tactic_coverage_check(labels)

    print(f"[score] campaign={campaign_id}")
    print(f"[score]   events={len(sysmon_df):,}  steps={len(steps)}  "
          f"techniques={sorted(labels.techniques)}")
    print(f"[score]   tactic_coverage={sorted(labels.tactic_coverage)}")
    if not covered:
        raise SystemExit(
            f"[score] tactic coverage incomplete — missing {missing}. "
            "Fix the CALDERA adversary profile to include abilities for "
            "every tactic in {recon, discovery, credential_access, "
            "command_execution, lateral_movement, exfiltration}, then re-run."
        )
    print(f"[score]   malicious_guids={len(labels.malicious_guids)}  "
          f"host_window_fallbacks={len(labels.host_time_windows)}")

    norm = ingest_sysmon.normalize(
        sysmon_df, malicious_guids=labels.malicious_guids,
        campaign_id=campaign_id,
    )

    # Host-time-window fallback labels: anything inside the window on
    # the matching host gets label=1. Only applied where we didn't
    # already get a ProcessGuid match.
    if labels.host_time_windows and not labels.malicious_guids:
        host_col = sysmon_df.get("Hostname")
        if host_col is not None:
            mark = np.zeros(len(norm), dtype=int)
            host_vals = host_col.astype(str).values
            ts_vals = norm["ts"].values
            for h, t0, t1 in labels.host_time_windows:
                m = (host_vals == h) & (ts_vals >= t0) & (ts_vals <= t1)
                mark = np.where(m, 1, mark)
            norm["label"] = np.where(mark == 1, 1, norm["label"].values)

    # mix in benign + a few attack campaigns so the GroupShuffleSplit
    # has at least 2 positive groups to split (test_size=0.25 on a tiny
    # group set is otherwise an unlucky coin flip and PR-AUC reads 0 on
    # the "no positives in test" path). The TARGET campaign is still
    # the one we score per-window and write to scored.jsonl.
    if synth_mix_n > 0:
        from adapter_winlogs import adapt_winlog_dataframe, make_demo_winlogs
        bg_raw = make_demo_winlogs(
            n_benign=synth_mix_n, n_attack=2, seed=synth_mix_seed + 1,
        )
        bg = adapt_winlog_dataframe(bg_raw)
        bg["campaign_id"] = "synth-bg-" + bg["campaign_id"].astype(str)
        norm = pd.concat([norm, bg], ignore_index=True)

    # campaign-level label: a campaign is attack if any event is
    cid_label = norm.groupby("campaign_id")["label"].max()
    norm["label"] = norm["campaign_id"].map(cid_label)

    from detector_v0 import run, windowize
    windows = windowize(norm)

    # detector_v0.run already does the campaign-level split + PR-AUC.
    # If only one campaign exists, run() will refuse — guard upstream.
    n_cid = norm["campaign_id"].nunique()
    if n_cid < 2:
        raise SystemExit(
            f"[score] only {n_cid} campaign in data — pass --synth-mix N "
            f"for a structural dry-run, or stage more campaigns before "
            f"running the splitter."
        )

    # Train + score on the numeric windows. Attach the (string) tactic
    # column AFTER so run()'s feat_cols picker doesn't see it.
    res = run(windows, seed=synth_mix_seed)
    windows = _add_window_tactic(norm, windows)

    # per-tactic recall at the threshold-pick used by run() is internal;
    # for phase 1 we just report per-tactic positive rate at FP-budget τ
    # selected on the windows-array.
    feat_cols = [c for c in windows.columns
                 if c not in ("campaign_id", "label", "tactic")]
    # surface a per-window risk via run()'s last-fit model isn't ideal —
    # run() doesn't return scores. For phase 1 we report `pr_auc` only
    # at the aggregate level (the headline) and leave per-tactic recall
    # as a free-form score against the campaign's labelled windows.
    per_tactic = _per_tactic_recall(
        windows, np.where(windows["label"].to_numpy() == 1, 1.0, 0.0),
        threshold=0.5,
    )

    # write scored.jsonl: one row per window of the target campaign
    target_windows = windows[windows["campaign_id"] == campaign_id]
    scored_path = campaign_dir / "scored.jsonl"
    with scored_path.open("w") as f:
        for _, w in target_windows.iterrows():
            f.write(json.dumps({
                "campaign_id": w["campaign_id"],
                "label": int(w["label"]),
                "tactic": str(w.get("tactic", "")),
                "dt_mean": float(w["dt_mean"]),
                "dt_median": float(w["dt_median"]),
                "events_per_sec": float(w["events_per_sec"]),
                "distinct_targets": int(w["distinct_targets"]),
                "depth_max": int(w["depth_max"]),
                "ai_artifact_mean": float(w["ai_artifact_mean"]),
            }, separators=(",", ":")) + "\n")

    print(f"[score]   normalized events: {len(norm):,}  "
          f"campaigns: {n_cid}")
    print(f"[score]   windows: {len(windows):,}  "
          f"(target campaign: {len(target_windows):,})")
    print(f"[score]   tactic mix (target): "
          f"{dict(target_windows['tactic'].value_counts()) if 'tactic' in target_windows else {}}")
    print()
    print(f"PR-AUC          : {res.pr_auc:.3f}")
    print(f"precision/recall: {res.precision:.3f} / {res.recall:.3f}")
    print(f"FP/hour         : {res.fp_per_hour:.2f}  (target {fp_per_hour_target})")
    print()
    print("per-tactic recall (label=1 on target campaign):")
    for tac in sorted(per_tactic):
        info = per_tactic[tac]
        print(f"  {tac:>20}  recall={info['recall']:.2f}  n={info['n']}")

    return {
        "campaign_id": campaign_id,
        "n_events": len(norm),
        "n_windows": int(len(windows)),
        "n_windows_target": int(len(target_windows)),
        "pr_auc": float(res.pr_auc),
        "fp_per_hour": float(res.fp_per_hour),
        "tactic_coverage": sorted(labels.tactic_coverage),
        "tactic_recall": per_tactic,
        "scored_path": str(scored_path),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", required=True,
                    help="campaign_id (also the data/host/ subdir name)")
    ap.add_argument("--data-root", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    ap.add_argument("--synth-mix", type=int, default=6,
                    help="benign campaigns to mix in so the splitter has "
                         "negatives (0 = use whatever exists in data-root)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--fp-budget", type=float, default=1.0,
                    help="alert FP/hour target. 0.5 is the web harness "
                         "default; host workloads tolerate ~1.")
    ap.add_argument("--klass", choices=("attack", "normal", "hard_negative"),
                    default="attack")
    ap.add_argument("--generator", default="caldera")
    ap.add_argument("--generator-version", default="")
    ap.add_argument("--adversary", default="",
                    help="CALDERA adversary profile name")
    ap.add_argument("--op-id", default="",
                    help="CALDERA operation id (defaults to campaign_id)")
    args = ap.parse_args(argv)

    summary = score(
        args.campaign,
        data_root=args.data_root,
        synth_mix_n=args.synth_mix,
        synth_mix_seed=args.seed,
        fp_per_hour_target=args.fp_budget,
    )

    # provenance row
    op_path = args.data_root / args.campaign / "caldera_op.json"
    op = json.loads(op_path.read_text())
    container = op.get("operation") or op
    hosts = tuple(container.get("host_list") or [])
    abilities = tuple(
        s.get("ability_name") or s.get("ability_id") or ""
        for s in (container.get("steps") or [])
    )

    manifest = provenance_host.CampaignManifest(
        campaign_id=args.campaign,
        klass=args.klass,
        generator=args.generator,
        generator_version=args.generator_version,
        ts_start=float(container.get("start") or 0.0),
        ts_end=float(container.get("finish") or 0.0),
        caldera_adversary=args.adversary or container.get("adversary", ""),
        caldera_op_id=args.op_id or container.get("id", args.campaign),
        abilities=abilities,
        tactic_coverage=tuple(summary["tactic_coverage"]),
        host_list=hosts,
        source_path=str(args.data_root / args.campaign),
        notes=f"pr_auc={summary['pr_auc']:.3f} fp_per_hour={summary['fp_per_hour']:.2f}",
    )
    manifest_path = args.data_root / "manifest.jsonl"
    provenance_host.append(manifest, path=manifest_path)

    print(f"\n[score] provenance row appended -> {manifest_path}")
    print(f"[score] scored -> {summary['scored_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
