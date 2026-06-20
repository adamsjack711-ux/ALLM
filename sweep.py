"""
AI-Attack Detector — multi-seed robustness sweep
================================================
The headline numbers in the plan come from a single seed. A single seed can
flatter (or unfairly punish) a model. This runs each detector across several
seeds and reports mean +/- std for the metrics we actually claim, so the
improvements are shown to be stable rather than lucky.

It shells out to the existing scripts (no copy of their logic) with --seed and
parses their printed metrics, then summarizes.

    python sweep.py                 # seeds 0,1,2
    python sweep.py --seeds 0 1 2 3 4
    python sweep.py --epochs 30     # faster, slightly noisier

Dependencies: numpy  (+ the detector scripts in the same dir)
"""

from __future__ import annotations
import argparse
import re
import subprocess
import sys

import numpy as np

PY = sys.executable


def _run(cmd) -> str:
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)} failed:\n{out.stderr[-1500:]}")
    return out.stdout


def _grab(pattern, text, group=1, cast=float):
    m = re.search(pattern, text)
    if not m:
        raise ValueError(f"pattern not found: {pattern!r}")
    return cast(m.group(group))


def sweep_v1(seed, epochs):
    t = _run([PY, "detector_v1.py", "--synthetic", "--seed", str(seed),
              "--epochs", str(epochs)])
    return {
        "v0_aggregate": _grab(r"v0 aggregate GBT.*?PR-AUC\s+([0-9.]+)", t),
        "v1_risk":      _grab(r"v1 multi-label GRU \(risk head\):\s+PR-AUC\s+([0-9.]+)", t),
        "macro_recall": _grab(r"macro-avg recall\s+([0-9.]+)", t),
    }


def sweep_v2(seed, epochs):
    t = _run([PY, "detector_v2.py", "--synthetic", "--seed", str(seed),
              "--epochs", str(epochs)])
    return {
        "aggregate": _grab(r"aggregate-only.*?:\s+([0-9.]+)", t),
        "gru":       _grab(r"GRU-only\s+.*?:\s+([0-9.]+)", t),
        "hybrid":    _grab(r"HYBRID\s+.*?:\s+([0-9.]+)", t),
        "lift":      _grab(r"lift over best single model:\s+([+\-0-9.]+)", t),
    }


def sweep_v3(seed, epochs):
    t = _run([PY, "detector_v3.py", "--demo", "--seed", str(seed),
              "--epochs", str(epochs)])
    return {
        "pr_auc":     _grab(r"PR-AUC:\s+([0-9.]+)", t),
        "fp_per_hour": _grab(r"achieved FP/hour \(test\):\s*([0-9.]+)", t),
        "detect_pct": _grab(r"detected:\s+\d+/\d+\s+\(([0-9.]+)%", t),
        "mttd_s":     _grab(r"mean-time-to-detect:\s+([0-9.]+)\s*s", t),
    }


def summarize(name, rows, fields):
    print(f"\n=== {name}  (n={len(rows)} seeds) ===")
    print(f"  {'metric':<16}{'mean':>9}{'std':>8}{'min':>8}{'max':>8}")
    for f, label in fields:
        vals = np.array([r[f] for r in rows], dtype=float)
        print(f"  {label:<16}{vals.mean():>9.3f}{vals.std():>8.3f}"
              f"{vals.min():>8.3f}{vals.max():>8.3f}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    ap.add_argument("--epochs", type=int, default=40)
    args = ap.parse_args()

    print(f"running robustness sweep over seeds {args.seeds} (epochs={args.epochs})...")
    v1, v2, v3 = [], [], []
    for s in args.seeds:
        print(f"  seed {s}: detector_v1 ...", flush=True); v1.append(sweep_v1(s, args.epochs))
        print(f"  seed {s}: detector_v2 ...", flush=True); v2.append(sweep_v2(s, args.epochs))
        print(f"  seed {s}: detector_v3 ...", flush=True); v3.append(sweep_v3(s, args.epochs))

    summarize("detector_v1 — multi-label", v1, [
        ("v0_aggregate", "v0 aggregate"),
        ("v1_risk", "v1 risk PR-AUC"),
        ("macro_recall", "macro recall"),
    ])
    summarize("detector_v2 — hybrid", v2, [
        ("aggregate", "aggregate PR-AUC"),
        ("gru", "GRU PR-AUC"),
        ("hybrid", "hybrid PR-AUC"),
        ("lift", "lift vs best"),
    ])
    summarize("detector_v3 — serving", v3, [
        ("pr_auc", "PR-AUC"),
        ("fp_per_hour", "FP/hour (test)"),
        ("detect_pct", "detect %"),
        ("mttd_s", "MTTD (s)"),
    ])

    # the headline claim each task rests on
    h = np.array([r["hybrid"] for r in v2]); b = np.array([max(r["aggregate"], r["gru"]) for r in v2])
    print("\n--- headline claims across seeds ---")
    print(f"  task 2: hybrid beats best single model in {int((h > b).sum())}/{len(v2)} seeds "
          f"(mean lift {np.mean(h - b):+.3f})")
    r1 = np.array([r["v1_risk"] for r in v1]); a1 = np.array([r["v0_aggregate"] for r in v1])
    print(f"  task 1: v1 risk >= v0 aggregate in {int((r1 >= a1).sum())}/{len(v1)} seeds")
    print()


if __name__ == "__main__":
    main()
