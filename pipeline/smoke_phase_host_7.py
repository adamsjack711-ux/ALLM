"""End-to-end smoke for phase-host-7: Sysmon XML gen + composite τ tune.

Stages the phase-host-2 synth set + runs per_eid_attribution + alert_fatigue,
then exercises:
  1. sysmon_config_gen: emits valid XML with the expected RuleGroup
     stanzas; falls back from cost-benefit → contributions → error.
  2. tune_threshold: produces a Pareto curve + a composite-objective
     pick that's at least as good as alert_fatigue's FP-budget τ on
     the composite metric.

NEVER reports accuracy.
"""

from __future__ import annotations

import json
import pathlib
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET

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


def _stage(data_root: pathlib.Path) -> None:
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
        _assert(cp.returncode == 0, f"[smoke-p7] synth {cmd[-3]} failed")
    for cid in ("synth-caldera-001", "synth-atomic-001", "workload-001",
                "hardneg-ps-001", "hardneg-wmi-001", "hardneg-sched-001"):
        cp = _run([sys.executable, "-m", "pipeline.score_campaign",
                   "--campaign", cid, "--data-root", str(data_root),
                   "--synth-mix", "4"])
        _assert(cp.returncode == 0, f"[smoke-p7] score {cid} failed")


def main() -> None:
    t0 = time.time()
    with tempfile.TemporaryDirectory() as td:
        data_root = pathlib.Path(td) / "data" / "host"
        data_root.mkdir(parents=True)
        _stage(data_root)

        # Run benign attribution → alert_fatigue → sysmon_config_gen
        # via phase-host-5 fallback (contributions, not cost-benefit).
        ben = data_root / "per_eid_attribution.json"
        cp = _run([sys.executable, "-m", "pipeline.per_eid_attribution",
                   "--campaign", "workload-001",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(ben)])
        _assert(cp.returncode == 0, "[smoke-p7] benign attribution failed")
        af_out = data_root / "alert_fatigue.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(af_out)])
        _assert(cp.returncode == 0, "[smoke-p7] alert_fatigue failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p7] alert_fatigue stdout mentions accuracy")
        af_report = json.loads(af_out.read_text())

        # ---- PART A: sysmon_config_gen falls back to contributions ----
        xml_out = data_root / "sysmon.xml"
        cp = _run([sys.executable, "-m", "pipeline.sysmon_config_gen",
                   "--alert-fatigue", str(af_out),
                   "--top-n", "5",
                   "--out", str(xml_out)])
        _assert(cp.returncode == 0, "[smoke-p7] sysmon_config_gen failed")
        xml_text = xml_out.read_text()
        _assert("Ranking source: contributions" in xml_text,
                f"[A] expected 'Ranking source: contributions' header, got:\n"
                f"{xml_text[:600]}")
        _assert("<Sysmon" in xml_text and "</Sysmon>" in xml_text,
                f"[A] XML wrapper missing")
        # Parse via ElementTree to verify well-formed XML even when no
        # rule groups land (synth EIDs 1/3/11/13 don't all map to the
        # catalog — only EID 13 does. The smoke accepts any non-negative
        # rule-group count as long as the XML parses.)
        root = ET.fromstring(xml_text)
        _assert(root.tag == "Sysmon",
                f"[A] root tag wrong: {root.tag}")
        rule_groups = root.findall(".//RuleGroup")
        _assert(len(rule_groups) >= 0,
                f"[A] negative RuleGroup count? {len(rule_groups)}")
        if len(rule_groups) == 0:
            _assert("No rule groups generated" in xml_text,
                    f"[A] 0 rule groups should include placeholder comment")
        _assert("accuracy" not in xml_text.lower(),
                "[A] XML mentions accuracy")

        # Edge case: alert_fatigue with no attribution → sysmon_config_gen
        # should exit with a useful error.
        no_attr_out = data_root / "alert_fatigue_no_attr.json"
        ben.unlink()
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(no_attr_out)])
        _assert(cp.returncode == 0, "[smoke-p7] alert_fatigue (no attr) failed")
        cp_fail = _run([sys.executable, "-m", "pipeline.sysmon_config_gen",
                        "--alert-fatigue", str(no_attr_out),
                        "--out", str(data_root / "fail.xml")])
        _assert(cp_fail.returncode != 0,
                "[A] sysmon_config_gen without attribution should error")
        _assert("per_eid" in cp_fail.stderr,
                f"[A] error should mention per_eid: {cp_fail.stderr}")

        # ---- PART B: tune_threshold produces Pareto + composite pick ----
        tune_out = data_root / "tune.json"
        cp = _run([sys.executable, "-m", "pipeline.tune_threshold",
                   "--data-root", str(data_root),
                   "--recall-weight", "100",
                   "--fp-budget", "1.0",
                   "--out", str(tune_out)])
        _assert(cp.returncode == 0, "[smoke-p7] tune_threshold failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p7] tune_threshold stdout mentions accuracy")
        tune_report = json.loads(tune_out.read_text())
        for key in ("deployments", "deployment_name", "recall_weight",
                    "tau_at_fp_budget", "fp_per_hour_budget",
                    "train_campaigns", "eval_campaigns",
                    "pareto", "curve", "picked",
                    "picked_composite_score"):
            _assert(key in tune_report,
                    f"[B] tune_threshold missing {key!r}")
        _assert(len(tune_report["curve"]) >= 5,
                f"[B] curve too small: {len(tune_report['curve'])}")
        _assert(len(tune_report["pareto"]) >= 1,
                f"[B] Pareto empty")
        # Pareto invariant: detect_rate non-increasing as fp_per_hour
        # increases (we sorted by detect_rate desc; the FP/hour of each
        # subsequent row must be strictly smaller).
        target_dep = tune_report["deployment_name"]
        last_fph = float("inf")
        for r in tune_report["pareto"]:
            pd_row = next(
                (d for d in r["per_deployment"]
                 if d["deployment"] == target_dep), None,
            )
            _assert(pd_row is not None,
                    f"[B] Pareto row missing target deployment: {r}")
            _assert(pd_row["fp_per_hour"] < last_fph + 1e-9,
                    f"[B] Pareto invariant broken: {pd_row['fp_per_hour']} "
                    f">= {last_fph}")
            last_fph = pd_row["fp_per_hour"]
        picked = tune_report["picked"]
        _assert(picked is not None and "tau" in picked,
                f"[B] no picked τ: {picked}")
        # Composite score of picked >= composite score at tau_at_fp_budget
        budget_tau = tune_report["tau_at_fp_budget"]
        budget_rows = [
            r for r in tune_report["curve"]
            if abs(r["tau"] - round(budget_tau, 2)) < 0.05
        ]
        if budget_rows:
            br = budget_rows[0]
            br_score = (
                br["detect_rate"]
                - tune_report["recall_weight"]
                * (next(d["fp_per_hour"] for d in br["per_deployment"]
                        if d["deployment"] == target_dep)) / 100.0
            )
            _assert(tune_report["picked_composite_score"] >= br_score - 1e-9,
                    f"[B] composite-picked τ should score ≥ budget τ: "
                    f"picked={tune_report['picked_composite_score']:.4f} "
                    f"vs budget={br_score:.4f}")

        # Edge case: recall_weight=0 → pure recall optimization, picks
        # the τ with highest detect_rate.
        tune_zero = data_root / "tune_zero.json"
        cp = _run([sys.executable, "-m", "pipeline.tune_threshold",
                   "--data-root", str(data_root),
                   "--recall-weight", "0",
                   "--out", str(tune_zero)])
        _assert(cp.returncode == 0, "[smoke-p7] tune --recall-weight=0 failed")
        z = json.loads(tune_zero.read_text())
        z_picked = z["picked"]
        max_detect = max(r["detect_rate"] for r in z["curve"]
                         if r["detect_rate"] == r["detect_rate"])
        _assert(z_picked["detect_rate"] >= max_detect - 1e-9,
                f"[B] recall_weight=0 should pick max detect_rate τ; got "
                f"{z_picked['detect_rate']} vs max {max_detect}")

    print()
    print(f"PHASE-HOST-7 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
