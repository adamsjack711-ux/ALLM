"""End-to-end smoke for the host phase-4 add-ons.

Reuses the phase-host-3 staged set (CALDERA + Atomic + workload +
hard-negatives), then exercises the two new pieces:

  1. `pipeline.calibrate_eventrate` against a real sysmon.jsonl,
     producing a deployments.json with per-EID share + suggested
     deployment shapes.

  2. `pipeline.alert_fatigue --deployments-file` consuming that
     calibrated file, plus `--multi-day` partitioning across 3 distinct
     UTC dates by re-stamping the manifest's ts_start values.

Asserts:
  - calibrate JSON carries events_per_sec_per_host + per_eid + deployments.
  - deployments-file run uses the calibrated deployment names (not the
    built-in DEFAULT_DEPLOYMENTS).
  - multi-day run emits a `daily` block with ≥2 distinct dates and a
    populated deployment_distribution with median/p95/min/max.
  - "accuracy" never appears in stdout or in any output JSON.
"""

from __future__ import annotations

import datetime as dt
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


def _restamp_manifest_dates(manifest_path: pathlib.Path, day_offsets: dict) -> None:
    """Rewrite each manifest row's ts_start to a chosen UTC day so the
    multi-day partition has ≥2 distinct dates to bucket on. ts_end is
    nudged the same delta to keep the (ts_start, ts_end) ordering valid.

    day_offsets maps campaign_id → integer day index. Day 0 is the most
    recent epoch-floor midnight; day 1 is 24h earlier; etc.
    """
    base = dt.datetime.now(tz=dt.timezone.utc).replace(
        hour=12, minute=0, second=0, microsecond=0,
    )
    rows: list[dict] = []
    for line in manifest_path.read_text().splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        cid = row["campaign_id"]
        if cid in day_offsets:
            new_start = (base - dt.timedelta(days=day_offsets[cid])).timestamp()
            duration = max(60.0, float(row["ts_end"]) - float(row["ts_start"]))
            row["ts_start"] = new_start
            row["ts_end"] = new_start + duration
        rows.append(row)
    manifest_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")


def main() -> None:
    t0 = time.time()
    with tempfile.TemporaryDirectory() as td:
        data_root = pathlib.Path(td) / "data" / "host"
        data_root.mkdir(parents=True)

        # Same 6-campaign set the phase-3 smoke uses
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
            _assert(cp.returncode == 0, f"[smoke-p4] synth {cmd[-3]} failed")

        for cid in ("synth-caldera-001", "synth-atomic-001", "workload-001",
                    "hardneg-ps-001", "hardneg-wmi-001", "hardneg-sched-001"):
            cp = _run([sys.executable, "-m", "pipeline.score_campaign",
                       "--campaign", cid, "--data-root", str(data_root),
                       "--synth-mix", "4"])
            _assert(cp.returncode == 0, f"[smoke-p4] score {cid} failed")

        # ---- 1. calibrate_eventrate against one sysmon dump ----
        sysmon_path = data_root / "workload-001" / "sysmon.jsonl"
        _assert(sysmon_path.exists(),
                f"[smoke-p4] expected sysmon dump at {sysmon_path}")
        dep_out = data_root / "deployments.json"
        cp = _run([sys.executable, "-m", "pipeline.calibrate_eventrate",
                   "--sysmon", str(sysmon_path),
                   "--hosts-per-deployment", "10,50,200",
                   "--out", str(dep_out)])
        _assert(cp.returncode == 0, "[smoke-p4] calibrate_eventrate failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p4] calibrate stdout mentions accuracy")
        calib = json.loads(dep_out.read_text())
        for key in ("n_events", "n_hosts_observed", "observation_seconds",
                    "events_per_sec_per_host", "per_eid", "deployments"):
            _assert(key in calib,
                    f"[smoke-p4] calibrate output missing {key!r}")
        eps = calib["events_per_sec_per_host"]
        for key in ("overall", "minute_bucket_p50", "minute_bucket_p95"):
            _assert(key in eps,
                    f"[smoke-p4] events_per_sec_per_host missing {key!r}")
        _assert(calib["n_events"] > 0, "[smoke-p4] calibrate parsed 0 events")
        _assert(len(calib["per_eid"]) >= 1,
                "[smoke-p4] calibrate produced empty per_eid")
        _assert(len(calib["deployments"]) >= 3,
                f"[smoke-p4] expected ≥3 suggested deployments, "
                f"got {len(calib['deployments'])}")
        calibrated_names = {d["name"] for d in calib["deployments"]}
        _assert(all(n.startswith("calibrated_") for n in calibrated_names),
                f"[smoke-p4] calibrated deployment names look wrong: "
                f"{calibrated_names}")

        # ---- 2. alert_fatigue --deployments-file ----
        out_dep = data_root / "alert_fatigue_deployments.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--deployments-file", str(dep_out),
                   "--out", str(out_dep)])
        _assert(cp.returncode == 0,
                "[smoke-p4] alert_fatigue with --deployments-file failed")
        rep = json.loads(out_dep.read_text())
        used_names = {est["deployment"] for est in rep["deployment_estimates"]}
        _assert(used_names.issubset(calibrated_names),
                f"[smoke-p4] --deployments-file did not propagate; "
                f"got {used_names}, expected subset of {calibrated_names}")
        _assert(len(rep["deployment_estimates"]) == len(calib["deployments"]),
                "[smoke-p4] deployment_estimates length != deployments count")
        _assert("accuracy" not in json.dumps(rep).lower(),
                "[smoke-p4] deployments-file alert_fatigue JSON mentions accuracy")

        # ---- 3. multi-day partition ----
        # Re-stamp the manifest so eval campaigns span ≥2 distinct UTC days.
        # We can't predict which campaigns the stratified split picks for
        # eval, so spread day offsets across all 6 — whichever land in
        # eval, ≥2 different days will be represented.
        _restamp_manifest_dates(
            data_root / "manifest.jsonl",
            day_offsets={
                "synth-caldera-001":  0,
                "synth-atomic-001":   1,
                "workload-001":       0,
                "hardneg-ps-001":     1,
                "hardneg-wmi-001":    2,
                "hardneg-sched-001":  2,
            },
        )

        out_mday = data_root / "alert_fatigue_multiday.json"
        cp = _run([sys.executable, "-m", "pipeline.alert_fatigue",
                   "--data-root", str(data_root),
                   "--fp-budget", "1.0",
                   "--multi-day",
                   "--out", str(out_mday)])
        _assert(cp.returncode == 0,
                "[smoke-p4] alert_fatigue --multi-day failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p4] multi-day stdout mentions accuracy")
        mrep = json.loads(out_mday.read_text())
        _assert("daily" in mrep,
                "[smoke-p4] --multi-day did not add 'daily' block")
        daily = mrep["daily"]
        for key in ("days", "deployment_distribution"):
            _assert(key in daily,
                    f"[smoke-p4] daily block missing {key!r}")
        days = daily["days"]
        _assert(len(days) >= 2,
                f"[smoke-p4] expected ≥2 day buckets after restamp, "
                f"got {len(days)} ({[d['date'] for d in days]})")
        dates = {d["date"] for d in days}
        _assert(len(dates) == len(days),
                f"[smoke-p4] day buckets aren't unique: {dates}")
        for day in days:
            for key in ("date", "n_campaigns", "per_class_fp_rate",
                        "per_hard_negative_subtype_fp_rate",
                        "deployment_estimates"):
                _assert(key in day,
                        f"[smoke-p4] day entry missing {key!r}: {day}")
            _assert(day["n_campaigns"] >= 1,
                    f"[smoke-p4] day {day['date']} has 0 campaigns")

        dist = daily["deployment_distribution"]
        _assert(len(dist) == len(rep["deployment_estimates"]),
                "[smoke-p4] distribution length != deployment count")
        # at least one deployment should have populated stats (the eval
        # split lands ≥1 day in each deployment bucket since deployments
        # are per-fleet, not per-day)
        populated = [d for d in dist if d["n_days"] > 0]
        _assert(len(populated) >= 1,
                f"[smoke-p4] no populated deployment distributions: {dist}")
        for d in populated:
            for key in ("median_total_fp_per_hour", "p95_total_fp_per_hour",
                        "min_total_fp_per_hour", "max_total_fp_per_hour"):
                _assert(d.get(key) is not None,
                        f"[smoke-p4] populated deployment {d['deployment']} "
                        f"missing {key!r}")
            _assert(d["min_total_fp_per_hour"] <= d["median_total_fp_per_hour"]
                    <= d["max_total_fp_per_hour"],
                    f"[smoke-p4] median outside [min, max] for "
                    f"{d['deployment']}: {d}")
        _assert("accuracy" not in json.dumps(mrep).lower(),
                "[smoke-p4] multi-day alert_fatigue JSON mentions accuracy")

    print()
    print(f"PHASE-HOST-4 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
