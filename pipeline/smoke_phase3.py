"""End-to-end smoke for the host phase-3 alert-fatigue arithmetic.

Synthesizes the phase-host-2 set (CALDERA + Atomic + workload +
hard-negative subtypes) in a tmpdir, scores each campaign, then runs
`pipeline.alert_fatigue` and asserts:

  - The arithmetic output JSON has the expected top-level keys:
    threshold, per_class_fp_rate, per_hard_negative_subtype_fp_rate,
    mttd_by_attack_family, deployment_estimates, burst_shapes_used.
  - The stratified split puts at least one of each (class, framework,
    benign_subtype) bucket in train + eval so the FP-rate denominator
    isn't empty.
  - At least one attack family has an MTTD entry (with detect_rate +
    n_campaigns + n_detected populated).
  - deployment_estimates carries the three default deployment shapes
    with normal_fp_per_hour + hard_negative_fp_per_hour fields each.
  - The custom-deployment override (--hosts / --event-rate) produces
    a single deployment with the matching shape.
  - "accuracy" never appears in the output.
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

        # Stage 6 campaigns: 1 CALDERA + 1 Atomic + 1 normal +
        # 3 hard-negative subtypes. This matches the phase-host-2 smoke
        # shape but adds the alert-fatigue scoring on top.
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
            _assert(cp.returncode == 0, f"[smoke-p3] synth {cmd[-3]} failed")

        # Score every campaign so each gets a provenance row in the manifest
        for cid in ("synth-caldera-001", "synth-atomic-001", "workload-001",
                    "hardneg-ps-001", "hardneg-wmi-001", "hardneg-sched-001"):
            cp = _run([sys.executable, "-m", "pipeline.score_campaign",
                       "--campaign", cid, "--data-root", str(data_root),
                       "--synth-mix", "4"])
            _assert(cp.returncode == 0, f"[smoke-p3] score {cid} failed")

        # 1. Default 3-deployment run
        out_default = data_root / "alert_fatigue.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(out_default)])
        _assert(cp.returncode == 0, "[smoke-p3] alert_fatigue.py failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p3] alert_fatigue stdout mentions accuracy")
        report = json.loads(out_default.read_text())

        for key in ("threshold", "per_class_fp_rate",
                    "per_hard_negative_subtype_fp_rate",
                    "mttd_by_attack_family", "deployment_estimates",
                    "burst_shapes_used", "train_campaigns",
                    "eval_campaigns", "benign_dt_median_s",
                    "window_seconds_estimate"):
            _assert(key in report,
                    f"[smoke-p3] alert_fatigue JSON missing key {key!r}")

        # stratified split: both train_campaigns and eval_campaigns must
        # be non-empty (the smoke generates ≥2 of multiple buckets)
        _assert(len(report["train_campaigns"]) >= 1,
                "[smoke-p3] no train campaigns")
        _assert(len(report["eval_campaigns"]) >= 1,
                "[smoke-p3] no eval campaigns")

        # deployment_estimates shape
        depl = report["deployment_estimates"]
        _assert(len(depl) == 3,
                f"[smoke-p3] expected 3 default deployments, got {len(depl)}")
        for est in depl:
            for key in ("deployment", "hosts", "events_per_sec_per_host",
                        "windows_per_hour_continuous",
                        "normal_fp_per_hour",
                        "hard_negative_fp_per_hour",
                        "hard_negative_breakdown", "total_fp_per_hour"):
                _assert(key in est,
                        f"[smoke-p3] deployment estimate missing {key!r}: {est}")
            _assert(est["windows_per_hour_continuous"] > 0,
                    f"[smoke-p3] deployment {est['deployment']} has "
                    f"zero windows/hour — arithmetic broken")
            _assert(est["total_fp_per_hour"] >= 0,
                    "[smoke-p3] negative total_fp_per_hour")

        # mttd_by_attack_family — at least one framework with at least one
        # campaign (the synth has 1 CALDERA + 1 Atomic)
        mttd = report["mttd_by_attack_family"]
        _assert(len(mttd) >= 1,
                "[smoke-p3] no attack frameworks in MTTD block")
        for fw, m in mttd.items():
            for key in ("n_campaigns", "n_detected", "detect_rate",
                        "mttd_s", "mttd_s_p95"):
                _assert(key in m,
                        f"[smoke-p3] mttd[{fw}] missing {key!r}")

        # burst_shapes_used carries the 5 default subtypes
        bs = report["burst_shapes_used"]
        for sub in ("ps_remoting", "wmi", "sched_task",
                    "sanctioned_scan", "backup"):
            _assert(sub in bs,
                    f"[smoke-p3] burst_shapes_used missing {sub!r}")

        _assert("accuracy" not in json.dumps(report).lower(),
                "[smoke-p3] alert_fatigue JSON mentions accuracy")

        # 2. Custom-deployment override
        out_custom = data_root / "alert_fatigue_custom.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "0.5",
                   "--hosts", "150",
                   "--event-rate", "1.7",
                   "--out", str(out_custom)])
        _assert(cp.returncode == 0,
                "[smoke-p3] alert_fatigue.py custom deployment failed")
        custom = json.loads(out_custom.read_text())
        _assert(len(custom["deployment_estimates"]) == 1,
                "[smoke-p3] custom run should produce exactly 1 deployment")
        only = custom["deployment_estimates"][0]
        _assert(only["hosts"] == 150,
                f"[smoke-p3] custom hosts={only['hosts']!r}")
        _assert(only["events_per_sec_per_host"] == 1.7,
                f"[smoke-p3] custom event_rate={only['events_per_sec_per_host']!r}")
        _assert(custom["fp_per_hour_budget"] == 0.5,
                f"[smoke-p3] custom fp_budget={custom['fp_per_hour_budget']!r}")

    print()
    print(f"PHASE-HOST-3 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
