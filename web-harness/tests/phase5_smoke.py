"""Phase-5 verification gate.

Runs the orchestrator end-to-end with N=6 sessions per generator
(playwright_bot + human_sim + pentesterpro = 18 sessions), then
verifies:

  - All three labels appear in the dataset.
  - PR-AUC[with_hp] >= 0.9
  - PR-AUC[ml_only] >= 0.7
  - The canary honeypot has at least one trip (must be pentesterpro by
    the planner's hidden-DOM-reading behavior; bot misses canary by
    design).
  - The heldout report has a per-attacker entry for both bots (proves
    the cross-attacker eval actually ran on the data).

Writes nothing of its own — the orchestrator already wrote run_<ts>.json,
phase4.json, and heldout.json.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQ = ROOT / "data" / "requests.jsonl"
HON = ROOT / "data" / "honeypots.jsonl"
REPORTS = ROOT / "data" / "reports"

N = int(os.environ.get("ALLM_PHASE5_SESSIONS", "6"))


def run(cmd: list[str], check: bool = False) -> int:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=ROOT)
    if check and cp.returncode != 0:
        raise SystemExit(f"failed rc={cp.returncode}: {cmd}")
    return cp.returncode


def main() -> None:
    t0 = time.time()
    run(
        [
            sys.executable, "orchestrator/run_loop.py",
            "--sessions", str(N),
        ],
        check=True,
    )

    req_rows = [json.loads(l) for l in REQ.read_text().splitlines() if l.strip()]
    hon_rows = [json.loads(l) for l in HON.read_text().splitlines() if l.strip()]
    labels = {r["src_label"] for r in req_rows}
    for needed in ("playwright_bot", "human_sim", "pentesterpro"):
        assert needed in labels, f"[phase5] label {needed!r} missing; got {labels}"

    phase4 = json.loads((REPORTS / "phase4.json").read_text())
    pr_hp = phase4["with_hp"]["pr_auc"]
    pr_ml = phase4["ml_only"]["pr_auc"]
    fp_hp = phase4["with_hp"]["fp_per_hour"]
    fp_ml = phase4["ml_only"]["fp_per_hour"]
    assert pr_hp >= 0.9, f"[phase5] with_hp PR-AUC {pr_hp:.3f} < 0.9"
    assert pr_ml >= 0.7, f"[phase5] ml_only PR-AUC {pr_ml:.3f} < 0.7"

    canary_trips = [r for r in hon_rows if r["honeypot"] == "canary"]
    canary_labels = {r["src_label"] for r in canary_trips}
    assert canary_trips, "[phase5] canary never tripped — pentesterpro planner broken?"
    assert "pentesterpro" in canary_labels, (
        f"[phase5] canary trips not attributed to pentesterpro; got {canary_labels}"
    )

    heldout = json.loads((REPORTS / "heldout.json").read_text())
    if "skipped" in heldout:
        raise AssertionError(f"[phase5] heldout skipped: {heldout['skipped']}")
    per_attacker = heldout.get("per_attacker", {})
    for atk in ("playwright_bot", "pentesterpro"):
        assert atk in per_attacker, (
            f"[phase5] heldout report missing entry for {atk}: "
            f"keys={list(per_attacker.keys())}"
        )

    print()
    print(f"PHASE 5 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")
    print(f"  sessions={len({r['session_id'] for r in req_rows})}  "
          f"rows={len(req_rows)}  labels={sorted(labels)}")
    print(f"  with_hp  PR-AUC={pr_hp:.4f}  FP/hr={fp_hp:.3f}")
    print(f"  ml_only  PR-AUC={pr_ml:.4f}  FP/hr={fp_ml:.3f}")
    print(f"  canary trips by source: {sorted(canary_labels)}")
    print(f"  heldout per-attacker:")
    for atk, info in per_attacker.items():
        if "skipped" in info:
            print(f"    {atk:>14}  SKIPPED: {info['skipped']}")
            continue
        flag = "OVERFITS" if info["overfits_attacker"] else "ok"
        print(
            f"    {atk:>14}  in_dist={info['in_dist_recall']:.2f}  "
            f"heldout={info['heldout_recall']:.2f}  [{flag}]"
        )


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
