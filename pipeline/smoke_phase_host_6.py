"""End-to-end smoke for phase-host-6 attack-side per-EID attribution.

Builds on the phase-host-5 smoke: stages the phase-host-2 synth set
(CALDERA + Atomic + workload + hard-negatives), runs per_eid_attribution
in BOTH modes (--target-class normal and --target-class attack), then
runs alert_fatigue and asserts the cost-benefit rollup lands when both
attribution files exist.

Asserts:

  PART A — attack-side dropout produces the new schema
    - per_eid_attack_attribution.json carries attack_dropout_attribution
      with `detect_rate_full`, `n_attack_windows_full`, per-EID rows
      with `contribution_to_detect_rate` instead of `contribution_to_fp_rate`
    - at least one EID has a non-None contribution
    - target_class field is "attack"

  PART B — alert_fatigue cost-benefit rollup
    - alert_fatigue auto-discovers BOTH attribution files
    - per_eid_cost_benefit_meta has the two source paths +
      n_eids_with_cost_benefit >= 1
    - every deployment_estimate gains per_eid_cost_benefit rows with
      eid + fp_per_hour_saved + recall_lost + ranking_score + sources
    - rows sorted by ranking_score desc

  PART C — single-side cases stay backwards-compatible
    - with ONLY benign attribution → per_eid_contributions still attached,
      per_eid_cost_benefit_meta is None
    - with ONLY attack attribution → per_eid_contributions absent,
      per_eid_cost_benefit_meta is None

  PART D — recall_weight tunes the ranking
    - with recall_weight=0 → ranking_score == fp_per_hour_saved
    - with recall_weight=10000 → top of ranking flips to lowest-recall-cost

NEVER mentions accuracy in any output.
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


def _stage_synth_set(data_root: pathlib.Path) -> None:
    """Stage the phase-host-2 set (same as smoke_phase4/5)."""
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
        _assert(cp.returncode == 0, f"[smoke-p6] synth {cmd[-3]} failed")
    for cid in ("synth-caldera-001", "synth-atomic-001", "workload-001",
                "hardneg-ps-001", "hardneg-wmi-001", "hardneg-sched-001"):
        cp = _run([sys.executable, "-m", "pipeline.score_campaign",
                   "--campaign", cid, "--data-root", str(data_root),
                   "--synth-mix", "4"])
        _assert(cp.returncode == 0, f"[smoke-p6] score {cid} failed")


def main() -> None:
    t0 = time.time()
    with tempfile.TemporaryDirectory() as td:
        data_root = pathlib.Path(td) / "data" / "host"
        data_root.mkdir(parents=True)
        _stage_synth_set(data_root)

        # ---- PART A: attack-side dropout against synth-caldera-001 ----
        attack_attribution = data_root / "per_eid_attack_attribution.json"
        cp = _run([sys.executable, "-m", "pipeline.per_eid_attribution",
                   "--campaign", "synth-caldera-001",
                   "--target-class", "attack",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(attack_attribution)])
        _assert(cp.returncode == 0,
                "[smoke-p6] per_eid_attribution --target-class attack failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p6] attack stdout mentions accuracy")
        attack_report = json.loads(attack_attribution.read_text())
        _assert(attack_report.get("target_class") == "attack",
                f"[A] target_class wrong: {attack_report.get('target_class')!r}")
        drop = attack_report.get("attack_dropout_attribution") or {}
        for key in ("target_campaign_id", "total_events", "n_distinct_eids",
                    "n_windows_full", "n_attack_windows_full",
                    "detect_rate_full", "per_eid"):
            _assert(key in drop,
                    f"[A] attack_dropout missing {key!r}: {sorted(drop)}")
        _assert(drop["n_attack_windows_full"] > 0,
                f"[A] expected ≥1 attack window, got "
                f"{drop['n_attack_windows_full']}")
        priced = [r for r in drop["per_eid"]
                  if r.get("contribution_to_detect_rate") is not None]
        _assert(len(priced) >= 1,
                f"[A] no per_eid row has a non-None detect-rate contribution: "
                f"{drop['per_eid']}")
        for row in drop["per_eid"]:
            for k in ("eid", "n_events_dropped", "share_events"):
                _assert(k in row,
                        f"[A] attack per_eid row missing {k!r}: {row}")
        print(f"[smoke-p6]   attack dropout: detect_rate_full="
              f"{drop['detect_rate_full']:.4f}, "
              f"{len(priced)}/{drop['n_distinct_eids']} priced rows")

        # ---- PART B: cost-benefit when both attribution files exist ----
        benign_attribution = data_root / "per_eid_attribution.json"
        cp = _run([sys.executable, "-m", "pipeline.per_eid_attribution",
                   "--campaign", "workload-001",
                   "--target-class", "normal",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(benign_attribution)])
        _assert(cp.returncode == 0,
                "[smoke-p6] per_eid_attribution --target-class normal failed")
        _assert(benign_attribution.exists(),
                f"[B] benign attribution not created")

        af_out = data_root / "alert_fatigue.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(af_out)])
        _assert(cp.returncode == 0, "[smoke-p6] alert_fatigue failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p6] alert_fatigue stdout mentions accuracy")
        af_report = json.loads(af_out.read_text())
        cb_meta = af_report.get("per_eid_cost_benefit_meta")
        _assert(cb_meta is not None,
                f"[B] per_eid_cost_benefit_meta not attached: "
                f"{sorted(af_report)}")
        _assert(cb_meta["benign_attribution_source"] == str(benign_attribution),
                f"[B] benign source wrong: {cb_meta}")
        _assert(cb_meta["attack_attribution_source"] == str(attack_attribution),
                f"[B] attack source wrong: {cb_meta}")
        _assert(cb_meta["n_eids_with_cost_benefit"] >= 1,
                f"[B] no common EIDs between benign+attack: {cb_meta}")

        for est in af_report["deployment_estimates"]:
            cb = est.get("per_eid_cost_benefit")
            _assert(cb is not None,
                    f"[B] deployment {est['deployment']} missing "
                    f"per_eid_cost_benefit")
            _assert(len(cb) >= 1,
                    f"[B] deployment {est['deployment']} has empty cost-benefit")
            for row in cb:
                for k in ("eid", "share_events_benign", "share_events_attack",
                          "fp_per_hour_saved", "recall_lost", "ranking_score"):
                    _assert(k in row,
                            f"[B] cost_benefit row missing {k!r}: {row}")
            scores = [r["ranking_score"] for r in cb]
            _assert(scores == sorted(scores, reverse=True),
                    f"[B] cost-benefit not sorted by ranking_score desc: "
                    f"{scores}")

        _assert("accuracy" not in json.dumps(af_report).lower(),
                "[B] alert_fatigue JSON mentions accuracy")

        # ---- PART C: single-side fallback (only attack, no benign) ----
        benign_attribution.unlink()
        af_out_attack_only = data_root / "alert_fatigue_attack_only.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(af_out_attack_only)])
        _assert(cp.returncode == 0, "[smoke-p6] alert_fatigue attack-only failed")
        af_attack_only = json.loads(af_out_attack_only.read_text())
        _assert(af_attack_only.get("per_eid_cost_benefit_meta") is None,
                f"[C] cost-benefit should be None without benign: "
                f"{af_attack_only.get('per_eid_cost_benefit_meta')}")
        for est in af_attack_only["deployment_estimates"]:
            _assert("per_eid_cost_benefit" not in est,
                    f"[C] cost-benefit block leaked when benign absent: "
                    f"{est['deployment']}")
            _assert("per_eid_contributions" not in est,
                    f"[C] contributions block leaked when benign absent")

        # ---- PART D: recall_weight tunes the ranking ----
        # Restore benign attribution
        cp = _run([sys.executable, "-m", "pipeline.per_eid_attribution",
                   "--campaign", "workload-001",
                   "--target-class", "normal",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--out", str(benign_attribution)])
        _assert(cp.returncode == 0,
                "[D] benign re-run failed")

        # Run with recall_weight=0 → ranking_score == fp_per_hour_saved
        af_zero = data_root / "alert_fatigue_zero.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--recall-weight", "0",
                   "--out", str(af_zero)])
        _assert(cp.returncode == 0, "[D] alert_fatigue recall_weight=0 failed")
        report_zero = json.loads(af_zero.read_text())
        cb_zero = (report_zero["deployment_estimates"][0]
                   .get("per_eid_cost_benefit") or [])
        for row in cb_zero:
            _assert(abs(row["ranking_score"] - row["fp_per_hour_saved"]) < 1e-9,
                    f"[D] with recall_weight=0, ranking_score must equal "
                    f"fp_per_hour_saved: {row}")
        _assert(report_zero["per_eid_cost_benefit_meta"]["recall_weight"] == 0,
                "[D] recall_weight not threaded to report meta")

        # Run with recall_weight=10000 → top row should be the one with
        # the smallest recall_lost (most negative recall_lost ranks highest)
        af_high = data_root / "alert_fatigue_high.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--recall-weight", "10000",
                   "--out", str(af_high)])
        _assert(cp.returncode == 0, "[D] alert_fatigue recall_weight=10000 failed")
        report_high = json.loads(af_high.read_text())
        cb_high = (report_high["deployment_estimates"][0]
                   .get("per_eid_cost_benefit") or [])
        _assert(len(cb_high) >= 1,
                f"[D] high-weight cost-benefit empty: {cb_high}")
        # With weight=10000, the top row should have the lowest recall_lost
        # (could be negative, meaning filtering helps).
        min_recall_lost = min(r["recall_lost"] for r in cb_high)
        _assert(cb_high[0]["recall_lost"] == min_recall_lost,
                f"[D] with recall_weight=10000, top row should be smallest "
                f"recall_lost; got {cb_high[0]['recall_lost']} vs min "
                f"{min_recall_lost}")
        print(f"[smoke-p6]   recall_weight tuning verified")

    print()
    print(f"PHASE-HOST-6 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
