"""End-to-end smoke for the host phase-2 pipeline.

Synthesizes one of each campaign type in a temp dir:
  - synth-caldera-001     (class=attack, framework=caldera)
  - synth-atomic-001      (class=attack, framework=atomic)
  - workload-001          (class=normal, framework=scripted)
  - hardneg-ps-remoting-001 + hardneg-sched-task-001 (class=hard_negative)

Runs score_campaign on each, then score_heldout_emulation, and asserts:
  - manifest.jsonl has 5 rows with the expected (class, framework,
    benign_subtype) combinations.
  - All six tactics are covered in both attack campaigns.
  - scored.jsonl is emitted for every campaign.
  - heldout_emulation.json has BOTH directions
    (train_caldera_eval_atomic AND train_atomic_eval_caldera), and each
    direction has pr_auc / fp_per_hour / per_tactic / threshold.
  - Hard-negative FP block exists (may be empty if eval split puts all
    hardneg in train — we don't gate on the breakdown being non-empty,
    just on the key being present).
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
REQUIRED_TACTICS = (
    "recon", "discovery", "credential_access",
    "command_execution", "lateral_movement", "exfiltration",
)


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
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

        # 1. synth one of each type
        synths = [
            ([sys.executable, "-m", "pipeline.synth_caldera",
              "--campaign", "synth-caldera-001",
              "--out", str(data_root)], "caldera"),
            ([sys.executable, "-m", "pipeline.synth_atomic",
              "--campaign", "synth-atomic-001",
              "--out", str(data_root)], "atomic"),
            ([sys.executable, "-m", "pipeline.synth_workload",
              "--campaign", "workload-001",
              "--out", str(data_root)], "workload"),
            ([sys.executable, "-m", "pipeline.synth_hard_negatives",
              "--campaign", "hardneg-ps-remoting-001",
              "--benign-subtype", "ps_remoting",
              "--out", str(data_root)], "hardneg-ps"),
            ([sys.executable, "-m", "pipeline.synth_hard_negatives",
              "--campaign", "hardneg-sched-task-001",
              "--benign-subtype", "sched_task",
              "--out", str(data_root)], "hardneg-sched"),
        ]
        for cmd, tag in synths:
            cp = _run(cmd)
            _assert(cp.returncode == 0, f"[smoke-p2] synth {tag} failed")

        # 2. score every campaign — each appends to manifest.jsonl
        score_calls = [
            ("synth-caldera-001", 6, "--adversary", "synth_six_tactic"),
            ("synth-atomic-001",  6),
            ("workload-001",      6),
            ("hardneg-ps-remoting-001", 6),
            ("hardneg-sched-task-001",  6),
        ]
        for entry in score_calls:
            cid = entry[0]
            mix = entry[1]
            extra = list(entry[2:])
            cmd = [sys.executable, "-m", "pipeline.score_campaign",
                   "--campaign", cid,
                   "--data-root", str(data_root),
                   "--synth-mix", str(mix)] + extra
            cp = _run(cmd)
            _assert(cp.returncode == 0,
                    f"[smoke-p2] score_campaign {cid} failed")
            _assert("accuracy" not in cp.stdout.lower(),
                    f"[smoke-p2] score_campaign {cid} stdout mentions accuracy")
            scored = data_root / cid / "scored.jsonl"
            _assert(scored.exists() and scored.stat().st_size > 0,
                    f"[smoke-p2] scored.jsonl missing for {cid}")

        # 3. manifest shape
        manifest = data_root / "manifest.jsonl"
        _assert(manifest.exists(), "[smoke-p2] manifest.jsonl never written")
        rows = [json.loads(line) for line in manifest.read_text().splitlines() if line]
        _assert(len(rows) == 5,
                f"[smoke-p2] expected 5 manifest rows, got {len(rows)}")
        by_cid = {r["campaign_id"]: r for r in rows}

        exp = {
            "synth-caldera-001":         ("attack", "caldera", ""),
            "synth-atomic-001":          ("attack", "atomic",  ""),
            "workload-001":              ("normal", "scripted", ""),
            "hardneg-ps-remoting-001":   ("hard_negative", "scripted", "ps_remoting"),
            "hardneg-sched-task-001":    ("hard_negative", "scripted", "sched_task"),
        }
        for cid, (klass, framework, bsub) in exp.items():
            row = by_cid.get(cid)
            _assert(row is not None, f"[smoke-p2] missing manifest row {cid}")
            _assert(row["class"] == klass,
                    f"[smoke-p2] {cid} class={row['class']!r}, expected {klass!r}")
            _assert(row["framework"] == framework,
                    f"[smoke-p2] {cid} framework={row['framework']!r}, "
                    f"expected {framework!r}")
            _assert(row["benign_subtype"] == bsub,
                    f"[smoke-p2] {cid} benign_subtype={row['benign_subtype']!r}, "
                    f"expected {bsub!r}")
            if klass == "attack":
                for tac in REQUIRED_TACTICS:
                    _assert(tac in row["tactic_coverage"],
                            f"[smoke-p2] {cid} missing tactic {tac!r}")

        # 4. held-out emulation eval
        heldout_out = data_root / "heldout_emulation.json"
        cp = _run([sys.executable, "-m", "pipeline.score_heldout_emulation",
                   "--data-root", str(data_root),
                   "--out", str(heldout_out)])
        _assert(cp.returncode == 0, "[smoke-p2] score_heldout_emulation failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[smoke-p2] heldout stdout mentions accuracy")

        report = json.loads(heldout_out.read_text())
        _assert("skipped" not in report,
                f"[smoke-p2] heldout SKIPPED: {report.get('skipped')}")
        _assert("results" in report, "[smoke-p2] heldout missing results block")
        directions = report["results"]
        for key in ("train_caldera_eval_atomic", "train_atomic_eval_caldera"):
            _assert(key in directions,
                    f"[smoke-p2] heldout missing direction {key!r}")
            r = directions[key]
            _assert("skipped" not in r,
                    f"[smoke-p2] direction {key} SKIPPED: {r.get('skipped')}")
            for field in ("pr_auc", "fp_per_hour", "threshold",
                          "per_tactic", "hard_negative_fp_by_subtype"):
                _assert(field in r,
                        f"[smoke-p2] direction {key} missing {field!r}")
        _assert("accuracy" not in json.dumps(report).lower(),
                "[smoke-p2] heldout JSON mentions accuracy")

    print()
    print(f"HOST PHASE 2 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
