"""Score one campaign: ingest -> label -> normalize -> window -> detector.

Phase 1 handled CALDERA campaigns only. Phase 2 widens this to:
  - CALDERA operations (caldera_op.json) — class=attack, framework=caldera
  - Atomic Red Team invocations (atomic_invocations.json) — class=attack,
    framework=atomic; the held-out emulation family
  - Scripted normal workload (workload.json with class=normal) — the bulk
    benign baseline
  - Hard-negative campaigns (workload.json with class=hard_negative +
    benign_subtype) — sanctioned admin activity that looks scary

Usage:
  python -m pipeline.score_campaign --campaign synth-caldera-001
  python -m pipeline.score_campaign --campaign synth-atomic-001
  python -m pipeline.score_campaign --campaign workload-001
  python -m pipeline.score_campaign --campaign hardneg-ps-remoting-001

The source type is auto-detected from which metadata file lives under
`data/host/<campaign>/`:
  - caldera_op.json   -> CALDERA attack
  - atomic_invocations.json -> Atomic Red Team attack
  - workload.json     -> normal / hard_negative (read class from JSON)

For attack campaigns the pipeline still does ProcessGuid + (host,
time-window) label resolution + tactic-coverage check. For class=normal
and class=hard_negative we skip labeling (label stays 0 everywhere) but
still emit scored.jsonl + a manifest row so the FP/hour denominator
sees these campaigns.

NEVER prints accuracy. Reports PR-AUC, FP/hour, per-tactic recall,
tactic coverage, malicious-GUID count.
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
)


SourceKind = str  # "caldera" | "atomic" | "workload"


def _detect_source(campaign_dir: pathlib.Path) -> tuple[SourceKind, pathlib.Path]:
    candidates = [
        ("caldera",  campaign_dir / "caldera_op.json"),
        ("atomic",   campaign_dir / "atomic_invocations.json"),
        ("workload", campaign_dir / "workload.json"),
    ]
    for kind, path in candidates:
        if path.exists():
            return kind, path
    raise SystemExit(
        f"[score] {campaign_dir} has no recognized metadata file "
        f"(expected one of caldera_op.json / atomic_invocations.json / "
        f"workload.json). Run the matching pipeline.synth_* module to "
        f"generate one, or drop in real data."
    )


def _per_tactic_recall(windows: pd.DataFrame, scores: np.ndarray,
                       threshold: float) -> dict:
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
        out[tac] = {"recall": recall, "n": int(attack_mask.sum()),
                    "flagged": int(flagged)}
    return out


def _add_window_tactic(norm: pd.DataFrame,
                       windows: pd.DataFrame) -> pd.DataFrame:
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


def _resolve_attack_labels(
    source: SourceKind,
    meta_path: pathlib.Path,
    sysmon_df: pd.DataFrame,
) -> tuple[col.Labels, list[str], list[str]]:
    """Returns (labels, host_list, ability_names)."""
    if source == "caldera":
        steps = col.load_caldera_op(meta_path)
        meta = json.loads(meta_path.read_text())
        container = meta.get("operation") or meta
        hosts = list(container.get("host_list") or [])
        abilities = [
            s.get("ability_name") or s.get("ability_id") or ""
            for s in (container.get("steps") or [])
        ]
    elif source == "atomic":
        steps = atl.load_atomic_invocations(meta_path)
        meta = json.loads(meta_path.read_text())
        hosts = list(meta.get("host_list") or [])
        abilities = [inv.get("atomic_name") or inv.get("name") or ""
                     for inv in meta.get("invocations", [])]
    else:
        raise ValueError(f"_resolve_attack_labels called for source={source!r}")

    labels = col.resolve_labels(steps, sysmon_df)
    return labels, hosts, abilities


def score(
    campaign_id: str,
    *,
    data_root: pathlib.Path,
    synth_mix_n: int,
    synth_mix_seed: int,
    fp_per_hour_target: float,
    skip_synth_mix_if_benign: bool = False,
) -> dict:
    campaign_dir = data_root / campaign_id
    sysmon_path = campaign_dir / "sysmon.jsonl"
    if not sysmon_path.exists():
        raise SystemExit(f"[score] missing {sysmon_path}")
    source, meta_path = _detect_source(campaign_dir)

    print(f"[score] campaign={campaign_id} source={source}")
    sysmon_df = ingest_sysmon.load_sysmon(sysmon_path)
    print(f"[score]   events={len(sysmon_df):,}")

    # decide klass / framework / benign_subtype based on the metadata file
    workload_meta: dict = {}
    if source == "workload":
        workload_meta = json.loads(meta_path.read_text())
        klass = workload_meta.get("class", "normal")
        framework = workload_meta.get("framework", "scripted")
        benign_subtype = workload_meta.get("benign_subtype", "")
    elif source == "caldera":
        klass = "attack"
        framework = "caldera"
        benign_subtype = ""
    else:
        klass = "attack"
        framework = "atomic"
        benign_subtype = ""

    if klass == "attack":
        labels, host_list, abilities = _resolve_attack_labels(
            source, meta_path, sysmon_df
        )
        covered, missing = col.tactic_coverage_check(labels)
        print(f"[score]   techniques={sorted(labels.techniques)}")
        print(f"[score]   tactic_coverage={sorted(labels.tactic_coverage)}")
        if not covered:
            raise SystemExit(
                f"[score] tactic coverage incomplete — missing {missing}. "
                "Extend the campaign so all six tactics fire, then re-run."
            )
        print(f"[score]   malicious_guids={len(labels.malicious_guids)}  "
              f"host_window_fallbacks={len(labels.host_time_windows)}")
        malicious_guids: Optional[set] = labels.malicious_guids
        tactic_coverage = sorted(labels.tactic_coverage)
        host_time_windows = labels.host_time_windows
    else:
        labels = None
        malicious_guids = None
        tactic_coverage = []
        host_time_windows = []
        host_list = workload_meta.get("host_list", [])
        abilities = []
        print(f"[score]   class={klass} framework={framework} "
              f"benign_subtype={benign_subtype or '-'}")

    norm = ingest_sysmon.normalize(
        sysmon_df, malicious_guids=malicious_guids,
        campaign_id=campaign_id,
    )

    if host_time_windows and not (malicious_guids or set()):
        host_col = sysmon_df.get("Hostname")
        if host_col is not None:
            mark = np.zeros(len(norm), dtype=int)
            host_vals = host_col.astype(str).values
            ts_vals = norm["ts"].values
            for h, t0, t1 in host_time_windows:
                m = (host_vals == h) & (ts_vals >= t0) & (ts_vals <= t1)
                mark = np.where(m, 1, mark)
            norm["label"] = np.where(mark == 1, 1, norm["label"].values)

    # synth-mix gives the splitter ≥2 positive groups when running on a
    # single attack campaign. Skip when scoring a benign campaign on its
    # own — caller should pass --synth-mix 0 in that case anyway.
    if synth_mix_n > 0 and not (skip_synth_mix_if_benign and klass != "attack"):
        from adapter_winlogs import adapt_winlog_dataframe, make_demo_winlogs
        bg_raw = make_demo_winlogs(
            n_benign=synth_mix_n, n_attack=2, seed=synth_mix_seed + 1,
        )
        bg = adapt_winlog_dataframe(bg_raw)
        bg["campaign_id"] = "synth-bg-" + bg["campaign_id"].astype(str)
        norm = pd.concat([norm, bg], ignore_index=True)

    cid_label = norm.groupby("campaign_id")["label"].max()
    norm["label"] = norm["campaign_id"].map(cid_label)

    from detector_v0 import run, windowize
    windows = windowize(norm)

    n_cid = norm["campaign_id"].nunique()
    if n_cid < 2:
        raise SystemExit(
            f"[score] only {n_cid} campaign in data — pass --synth-mix N "
            "or stage more campaigns before running the splitter."
        )

    res = run(windows, seed=synth_mix_seed)
    windows = _add_window_tactic(norm, windows)

    per_tactic = _per_tactic_recall(
        windows, np.where(windows["label"].to_numpy() == 1, 1.0, 0.0),
        threshold=0.5,
    )

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

    print(f"[score]   normalized events: {len(norm):,}  campaigns: {n_cid}")
    print(f"[score]   windows: {len(windows):,}  "
          f"(target campaign: {len(target_windows):,})")
    print()
    print(f"PR-AUC          : {res.pr_auc:.3f}")
    print(f"precision/recall: {res.precision:.3f} / {res.recall:.3f}")
    print(f"FP/hour         : {res.fp_per_hour:.2f}  (target {fp_per_hour_target})")
    print()
    if per_tactic:
        print("per-tactic recall (label=1 on target campaign):")
        for tac in sorted(per_tactic):
            info = per_tactic[tac]
            print(f"  {tac:>20}  recall={info['recall']:.2f}  n={info['n']}")

    return {
        "campaign_id": campaign_id,
        "source": source,
        "klass": klass,
        "framework": framework,
        "benign_subtype": benign_subtype,
        "host_list": host_list,
        "abilities": abilities,
        "tactic_coverage": tactic_coverage,
        "n_events": len(norm),
        "n_windows": int(len(windows)),
        "n_windows_target": int(len(target_windows)),
        "pr_auc": float(res.pr_auc),
        "fp_per_hour": float(res.fp_per_hour),
        "tactic_recall": per_tactic,
        "scored_path": str(scored_path),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--data-root", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    ap.add_argument("--synth-mix", type=int, default=6)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--fp-budget", type=float, default=1.0)
    ap.add_argument("--adversary", default="")
    ap.add_argument("--op-id", default="")
    ap.add_argument("--generator-version", default="")
    args = ap.parse_args(argv)

    summary = score(
        args.campaign,
        data_root=args.data_root,
        synth_mix_n=args.synth_mix,
        synth_mix_seed=args.seed,
        fp_per_hour_target=args.fp_budget,
    )

    # Build the provenance row from the campaign metadata + score summary.
    campaign_dir = args.data_root / args.campaign
    klass = summary["klass"]
    framework = summary["framework"]
    benign_subtype = summary["benign_subtype"]
    host_list = summary["host_list"]
    abilities = summary["abilities"]

    ts_start = 0.0
    ts_end = 0.0
    caldera_op_id = ""
    caldera_adversary = ""
    if summary["source"] == "caldera":
        op = json.loads((campaign_dir / "caldera_op.json").read_text())
        container = op.get("operation") or op
        ts_start = float(container.get("start") or 0.0)
        ts_end = float(container.get("finish") or 0.0)
        caldera_op_id = args.op_id or container.get("id", args.campaign)
        caldera_adversary = args.adversary or container.get("adversary", "")
    elif summary["source"] == "atomic":
        op = json.loads((campaign_dir / "atomic_invocations.json").read_text())
        ts_start = float(op.get("ts_start") or 0.0)
        ts_end = float(op.get("ts_end") or 0.0)
    else:
        meta = json.loads((campaign_dir / "workload.json").read_text())
        ts_start = float(meta.get("ts_start") or 0.0)
        ts_end = float(meta.get("ts_end") or 0.0)

    generator = framework  # phase 2: generator name == framework name
    manifest = provenance_host.CampaignManifest(
        campaign_id=args.campaign,
        klass=klass,
        generator=generator,
        generator_version=args.generator_version,
        framework=framework,
        benign_subtype=benign_subtype,
        ts_start=ts_start,
        ts_end=ts_end,
        caldera_adversary=caldera_adversary,
        caldera_op_id=caldera_op_id,
        abilities=tuple(abilities),
        tactic_coverage=tuple(summary["tactic_coverage"]),
        host_list=tuple(host_list),
        source_path=str(campaign_dir),
        notes=f"pr_auc={summary['pr_auc']:.3f} fp_per_hour={summary['fp_per_hour']:.2f}",
    )
    manifest_path = args.data_root / "manifest.jsonl"
    provenance_host.append(manifest, path=manifest_path)
    print(f"\n[score] provenance row appended -> {manifest_path}")
    print(f"[score] scored -> {summary['scored_path']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
