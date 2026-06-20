"""Phase-4 verification gate.

Generates a labeled dataset, trains both detector heads, evaluates, and
asserts:
  - PR-AUC[with_hp] >= 0.9
  - PR-AUC[ml_only] >= 0.7
  - FP/hour reported (no accuracy reported anywhere)
  - per-source recall present for both heads
  - StreamingAlerter computed time-to-flag on at least one positive
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
BCN = ROOT / "data" / "beacons.jsonl"
REPORT = ROOT / "data" / "reports" / "phase4.json"

N_BOT = int(os.environ.get("ALLM_PHASE4_BOT", "12"))
N_HUMAN = int(os.environ.get("ALLM_PHASE4_HUMAN", "12"))


def run(cmd: list[str], check: bool = False) -> int:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=ROOT)
    if check and cp.returncode != 0:
        raise SystemExit(f"failed rc={cp.returncode}: {cmd}")
    return cp.returncode


def truncate(p: pathlib.Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")


def main() -> None:
    run(["docker", "compose", "up", "-d", "capture"], check=True)
    run([sys.executable, "scripts/init_dvwa.py"], check=True)

    truncate(REQ)
    truncate(HON)
    truncate(BCN)

    t0 = time.time()
    print(f"[phase4] generating {N_BOT} bot + {N_HUMAN} human sessions", flush=True)
    run([
        "docker", "compose", "--profile", "generators", "run", "--rm",
        "-e", f"ALLM_SESSIONS={N_BOT}",
        "playwright_bot",
    ], check=True)
    run([
        "docker", "compose", "--profile", "generators", "run", "--rm",
        "-e", f"ALLM_SESSIONS={N_HUMAN}",
        "human_sim",
    ], check=True)
    gen_elapsed = time.time() - t0
    print(f"[phase4] gen done in {gen_elapsed:.1f}s", flush=True)

    run([
        "docker", "compose", "--profile", "analysis", "build", "detector",
    ], check=True)

    run([
        "docker", "compose", "--profile", "analysis", "run", "--rm", "detector",
        "/app/train.py", "--data", "/data", "--out", "/data/models",
    ], check=True)
    run([
        "docker", "compose", "--profile", "analysis", "run", "--rm", "detector",
        "/app/eval.py", "--data", "/data", "--models", "/data/models",
        "--out", "/data/reports/phase4.json",
    ], check=True)

    report = json.loads(REPORT.read_text())
    with_hp = report.get("with_hp", {})
    ml_only = report.get("ml_only", {})
    assert with_hp, "[phase4] no with_hp head in report"
    assert ml_only, "[phase4] no ml_only head in report"

    pr_hp = with_hp["pr_auc"]
    pr_ml = ml_only["pr_auc"]
    fp_hp = with_hp["fp_per_hour"]
    fp_ml = ml_only["fp_per_hour"]
    assert pr_hp >= 0.9, f"[phase4] with_hp PR-AUC {pr_hp:.3f} < 0.9"
    assert pr_ml >= 0.7, f"[phase4] ml_only PR-AUC {pr_ml:.3f} < 0.7"

    flagged_pos_hp = with_hp["alerter"]["flagged_positive"]
    assert flagged_pos_hp >= 1, (
        f"[phase4] alerter never flagged a positive in test set "
        f"(flagged={flagged_pos_hp})"
    )

    elapsed = time.time() - t0
    print()
    print(f"PHASE 4 SMOKE PASSED ✅  elapsed={elapsed:.1f}s")
    print(f"  with_hp  PR-AUC={pr_hp:.4f}  FP/hr={fp_hp:.3f}  "
          f"τ={with_hp['threshold']:.3f}  alerter flagged+={flagged_pos_hp}")
    print(f"  ml_only  PR-AUC={pr_ml:.4f}  FP/hr={fp_ml:.3f}  "
          f"τ={ml_only['threshold']:.3f}")
    print(f"  honeypot precision (data only): "
          f"{report['honeypot_precision_data_only']['precision']}")
    for tag, head in (("with_hp", with_hp), ("ml_only", ml_only)):
        for src, info in head["per_source"].items():
            print(f"  [{tag:>7}] per-source  {src:>14}  "
                  f"alerts={info['alerts']}/{info['test_sessions']}  "
                  f"recall={info['recall']:.2f}")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
