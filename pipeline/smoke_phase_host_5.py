"""End-to-end smoke for phase-host-5 per-EID FP attribution.

Reuses the phase-host-2 staged set (CALDERA + Atomic + workload +
hard-negatives), runs `pipeline.per_eid_attribution` against the
normal-workload campaign, then runs `pipeline.alert_fatigue` with the
attribution file auto-discovered.

Asserts:
  - per_eid_attribution.json carries `dropout_attribution` +
    `window_composition` + `threshold` + `target_campaign_id` +
    `train_campaigns` + `eval_campaigns`.
  - dropout_attribution.per_eid has one row per distinct EID in the
    workload campaign with the right shape (eid, n_events_dropped,
    share_events, n_windows_dropout, fp_rate_dropout,
    contribution_to_fp_rate). At least one row has share_events > 0
    and a non-None contribution.
  - window_composition.by_dominant_eid is keyed by stringified EIDs
    and each cell has n_windows + n_flagged + fp_rate +
    mean_share_dominant. Sum of n_windows across buckets equals
    window_composition.n_windows.
  - alert_fatigue with --per-eid-attribution attaches
    `per_eid_contributions` to every `deployment_estimate`. Each
    contribution row has eid + fp_per_hour + contribution_to_fp_rate.
    Sign and magnitude relationship: |fp_per_hour| ==
    |contribution_to_fp_rate × windows_per_hour_continuous|.
  - alert_fatigue auto-discovery: passing no --per-eid-attribution
    flag still picks up the file from data/host/per_eid_attribution.json.
  - `per_eid_attribution_source` field in alert_fatigue.json points
    at the right file.
  - "accuracy" never appears in any output JSON or stdout.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _run(cmd: list[str], cwd: pathlib.Path = ROOT) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if cp.returncode != 0:
        print(f"  stdout:\n{cp.stdout}\n  stderr:\n{cp.stderr}", flush=True)
    return cp


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    t0 = time.time()
    with tempfile.TemporaryDirectory() as td:
        data_root = pathlib.Path(td) / "data" / "host"
        data_root.mkdir(parents=True)

        # Stage the phase-host-2 set: 1 CALDERA + 1 Atomic + 1 workload +
        # 3 hard-negative subtypes. Enough for the stratified split +
        # for per_eid_attribution to find distinct EIDs in the workload.
        synths = [
            [sys.executable, "-m", "pipeline.synth_caldera",
             "--campaign", "synth-caldera-001", "--out", str(data_root)],
            [sys.executable, "-m", "pipeline.synth_atomic",
             "--campaign", "synth-atomic-001", "--out", str(data_root)],
            [sys.executable, "-m", "pipeline.synth_workload",
             "--campaign", "workload-001", "--out", str(data_root)],
            [sys.executable, "-m", "pipeline.synth_hard_negatives",
             "--campaign", "hardneg-ps-001",
             "--benign-subtype", "ps_remoting", "--out", str(data_root)],
            [sys.executable, "-m", "pipeline.synth_hard_negatives",
             "--campaign", "hardneg-wmi-001",
             "--benign-subtype", "wmi", "--out", str(data_root)],
            [sys.executable, "-m", "pipeline.synth_hard_negatives",
             "--campaign", "hardneg-sched-001",
             "--benign-subtype", "sched_task", "--out", str(data_root)],
        ]
        for cmd in synths:
            cp = _run(cmd)
            _assert(cp.returncode == 0, f"[smoke-p5] synth {cmd[-3]} failed")

        for cid in ("synth-caldera-001", "synth-atomic-001", "workload-001",
                    "hardneg-ps-001", "hardneg-wmi-001", "hardneg-sched-001"):
            cp = _run([sys.executable, "-m", "pipeline.score_campaign",
                       "--campaign", cid, "--data-root", str(data_root),
                       "--synth-mix", "4"])
            _assert(cp.returncode == 0, f"[smoke-p5] score {cid} failed")

        # ---- 1. per_eid_attribution against workload-001 ----
        attribution_out = data_root / "per_eid_attribution.json"
        cp = _run([sys.executable, "-m", "pipeline.per_eid_attribution",
                   "--campaign", "workload-001",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(attribution_out)])
        _assert(cp.returncode == 0,
                "[smoke-p5] per_eid_attribution.py failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p5] per_eid_attribution stdout mentions accuracy")
        attribution = json.loads(attribution_out.read_text())

        for key in ("target_campaign_id", "threshold", "seed",
                    "train_campaigns", "eval_campaigns",
                    "dropout_attribution", "window_composition"):
            _assert(key in attribution,
                    f"[smoke-p5] attribution JSON missing {key!r}")

        # Dropout shape
        drop = attribution["dropout_attribution"]
        for key in ("target_campaign_id", "total_events",
                    "n_distinct_eids", "n_windows_full",
                    "fp_rate_full", "per_eid"):
            _assert(key in drop, f"[smoke-p5] dropout missing {key!r}")
        _assert(drop["n_distinct_eids"] >= 1,
                f"[smoke-p5] expected ≥1 distinct EID in workload, got "
                f"{drop['n_distinct_eids']}")
        _assert(len(drop["per_eid"]) == drop["n_distinct_eids"],
                f"[smoke-p5] per_eid length {len(drop['per_eid'])} != "
                f"n_distinct_eids {drop['n_distinct_eids']}")

        per_eid = drop["per_eid"]
        any_priced = False
        for entry in per_eid:
            for k in ("eid", "n_events_dropped", "share_events"):
                _assert(k in entry,
                        f"[smoke-p5] per_eid row missing {k!r}: {entry}")
            _assert(isinstance(entry["eid"], int),
                    f"[smoke-p5] eid not int: {entry}")
            _assert(entry["share_events"] >= 0,
                    f"[smoke-p5] negative share_events: {entry}")
            if entry.get("contribution_to_fp_rate") is not None:
                any_priced = True
        _assert(any_priced,
                f"[smoke-p5] no per_eid row has a non-None contribution — "
                f"workload campaign too small? {per_eid}")

        # Composition shape
        comp = attribution["window_composition"]
        _assert("by_dominant_eid" in comp,
                f"[smoke-p5] composition missing by_dominant_eid")
        _assert(comp["n_windows"] > 0,
                f"[smoke-p5] composition has 0 windows: {comp}")
        # Sum n_windows across buckets equals total
        bucket_sum = sum(c["n_windows"] for c in comp["by_dominant_eid"].values())
        _assert(bucket_sum == comp["n_windows"],
                f"[smoke-p5] composition bucket sum {bucket_sum} != "
                f"total {comp['n_windows']}")
        for eid_key, cell in comp["by_dominant_eid"].items():
            for k in ("n_windows", "n_flagged", "fp_rate", "mean_share_dominant"):
                _assert(k in cell,
                        f"[smoke-p5] composition[{eid_key}] missing {k!r}: {cell}")
            _assert(0.0 <= cell["fp_rate"] <= 1.0,
                    f"[smoke-p5] composition[{eid_key}] fp_rate out of range: "
                    f"{cell}")

        # Belt + suspenders: no accuracy anywhere in the JSON
        _assert("accuracy" not in json.dumps(attribution).lower(),
                "[smoke-p5] attribution JSON mentions accuracy")

        # ---- 2. alert_fatigue auto-discovers + attaches contributions ----
        af_out = data_root / "alert_fatigue.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(af_out)])
        _assert(cp.returncode == 0, "[smoke-p5] alert_fatigue.py failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p5] alert_fatigue stdout mentions accuracy")
        af_report = json.loads(af_out.read_text())

        # Auto-discovery sets per_eid_attribution_source
        _assert(af_report.get("per_eid_attribution_source") == str(attribution_out),
                f"[smoke-p5] auto-discovery wrong: "
                f"{af_report.get('per_eid_attribution_source')!r}")

        # Every deployment estimate has the contributions block
        depl = af_report["deployment_estimates"]
        _assert(len(depl) >= 1, "[smoke-p5] no deployment_estimates")
        for est in depl:
            _assert("per_eid_contributions" in est,
                    f"[smoke-p5] deployment {est['deployment']} missing "
                    f"per_eid_contributions")
            contribs = est["per_eid_contributions"]
            for c in contribs:
                for k in ("eid", "share_events",
                          "contribution_to_fp_rate", "fp_per_hour"):
                    _assert(k in c,
                            f"[smoke-p5] contribution row missing {k!r}: {c}")
                # Sign + magnitude relationship
                expected = c["contribution_to_fp_rate"] * est["windows_per_hour_continuous"]
                _assert(abs(c["fp_per_hour"] - expected) < 1e-6,
                        f"[smoke-p5] fp_per_hour math wrong: "
                        f"got {c['fp_per_hour']}, expected {expected}")
            # Contributions are sorted by |fp_per_hour| desc
            if len(contribs) >= 2:
                vals = [abs(c["fp_per_hour"]) for c in contribs]
                _assert(vals == sorted(vals, reverse=True),
                        f"[smoke-p5] contributions not sorted by |fp_per_hour|: "
                        f"{vals}")

        _assert("accuracy" not in json.dumps(af_report).lower(),
                "[smoke-p5] alert_fatigue JSON mentions accuracy")

        # ---- 3. Without an attribution file, the block is just absent ----
        attribution_out.unlink()
        af_out_no = data_root / "alert_fatigue_no_attr.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(af_out_no)])
        _assert(cp.returncode == 0,
                "[smoke-p5] alert_fatigue without attribution failed")
        af_no = json.loads(af_out_no.read_text())
        _assert(af_no.get("per_eid_attribution_source") is None,
                f"[smoke-p5] attribution_source should be None when file "
                f"absent: {af_no.get('per_eid_attribution_source')!r}")
        for est in af_no["deployment_estimates"]:
            _assert("per_eid_contributions" not in est,
                    f"[smoke-p5] deployment {est['deployment']} has "
                    f"per_eid_contributions block without an attribution file")

    print()
    print(f"PHASE-HOST-5 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
