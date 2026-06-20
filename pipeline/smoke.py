"""End-to-end smoke for the host pipeline.

Exercises the synthetic CALDERA dry-run in a temporary directory and
verifies:
  - synth_caldera writes sysmon.jsonl + caldera_op.json.
  - score_campaign exits 0.
  - All six tactics are present in the op's tactic_coverage.
  - scored.jsonl is non-empty and carries label/tactic/dt_mean per row.
  - manifest.jsonl appends one campaign row with the expected fields.

Runs entirely in-sandbox. No network, no CALDERA, no Sysmon collector.
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
PROVENANCE_FIELDS = (
    "campaign_id", "ts_start", "ts_end", "class", "generator",
    "abilities", "tactic_coverage", "host_list", "config_sha",
    "source_path",
)


def main() -> None:
    t0 = time.time()
    with tempfile.TemporaryDirectory() as td:
        data_root = pathlib.Path(td) / "data" / "host"
        data_root.mkdir(parents=True)

        # 1. synth
        cp = subprocess.run(
            [sys.executable, "-m", "pipeline.synth_caldera",
             "--campaign", "synth-smoke",
             "--out", str(data_root)],
            cwd=ROOT, capture_output=True, text=True,
        )
        assert cp.returncode == 0, f"[smoke] synth failed:\n{cp.stderr}"

        camp_dir = data_root / "synth-smoke"
        sysmon = camp_dir / "sysmon.jsonl"
        op = camp_dir / "caldera_op.json"
        assert sysmon.exists() and sysmon.stat().st_size > 0, "[smoke] sysmon.jsonl missing or empty"
        assert op.exists() and op.stat().st_size > 0, "[smoke] caldera_op.json missing or empty"

        op_data = json.loads(op.read_text())
        techs = {s["technique_id"] for s in op_data["operation"]["steps"]}
        assert len(techs) >= 6, f"[smoke] op claims < 6 techniques: {techs}"

        # 2. score
        cp = subprocess.run(
            [sys.executable, "-m", "pipeline.score_campaign",
             "--campaign", "synth-smoke",
             "--data-root", str(data_root),
             "--synth-mix", "8",
             "--adversary", "synth_six_tactic",
             "--generator-version", "synth-smoke-0.1"],
            cwd=ROOT, capture_output=True, text=True,
        )
        if cp.returncode != 0:
            raise AssertionError(
                f"[smoke] score_campaign failed:\nstdout:\n{cp.stdout}\nstderr:\n{cp.stderr}"
            )
        stdout = cp.stdout

        # 3. tactic-coverage check fired and passed
        for tac in REQUIRED_TACTICS:
            assert tac in stdout, f"[smoke] tactic {tac!r} missing from score output"
        assert "PR-AUC" in stdout and "FP/hour" in stdout, "[smoke] eval lines missing"
        assert "accuracy" not in stdout.lower(), "[smoke] eval output mentions accuracy — that's a bug"

        # 4. scored.jsonl shape
        scored = camp_dir / "scored.jsonl"
        assert scored.exists() and scored.stat().st_size > 0, "[smoke] scored.jsonl missing or empty"
        rows = [json.loads(l) for l in scored.read_text().splitlines() if l.strip()]
        assert rows, "[smoke] scored.jsonl has no rows"
        for r in rows[:3]:
            for f in ("campaign_id", "label", "tactic", "dt_mean", "events_per_sec"):
                assert f in r, f"[smoke] scored row missing field {f!r}: {r}"

        # 5. manifest row
        manifest = data_root / "manifest.jsonl"
        assert manifest.exists(), "[smoke] manifest.jsonl never written"
        rows = [json.loads(l) for l in manifest.read_text().splitlines() if l.strip()]
        assert len(rows) == 1, f"[smoke] expected 1 manifest row, got {len(rows)}"
        m = rows[0]
        for f in PROVENANCE_FIELDS:
            assert f in m, f"[smoke] manifest row missing field {f!r}"
        assert m["class"] == "attack", f"[smoke] manifest class={m['class']!r}, expected 'attack'"
        for tac in REQUIRED_TACTICS:
            assert tac in m["tactic_coverage"], (
                f"[smoke] manifest tactic_coverage missing {tac!r}: "
                f"{m['tactic_coverage']}"
            )

    print()
    print(f"HOST PIPELINE SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
