"""Orchestrator — one cycle of mixed labeled traffic → train → eval → heldout.

Default behavior (`python3 orchestrator/run_loop.py`):
  1. Ensures DVWA is up + DB initialized (idempotent).
  2. Shuffles the generators (`human_sim`, `playwright_bot`, `pentesterpro`)
     so cookies land in random order (a small adversarial step — the
     detector shouldn't lean on "agents always come first").
  3. Runs each generator with `CERNIS_SESSIONS=N` (default 6) inside the
     `generators` profile of docker compose.
  4. Trains both detector heads.
  5. Evaluates and writes phase4-style report.
  6. Held-out attacker eval (per-attacker overfit flag).
  7. Writes a `data/reports/run_<ts>.json` summary.

The plan describes K-cycle loops with security-level rotation. For this
demo invocation the orchestrator runs ONE cycle at the default security
level — enough to drive the pipeline end-to-end. To rotate, restart DVWA
with a new `DVWA_SECURITY_LEVEL` env var between invocations.

Real-human traffic (`human_real`) is captured separately by you browsing
on `http://127.0.0.1:8090/`; the orchestrator never generates that
class.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import random
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
REPORTS = DATA / "reports"

DEFAULT_GENERATORS = [
    ("human_sim", 6),
    ("playwright_bot", 6),
    ("pentesterpro", 6),
]


def run(cmd: list[str], check: bool = False) -> int:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=ROOT)
    if check and cp.returncode != 0:
        raise SystemExit(f"failed rc={cp.returncode}: {cmd}")
    return cp.returncode


def ensure_target_up() -> None:
    run(["docker", "compose", "up", "-d", "--build", "capture"], check=True)
    run(
        [
            "docker", "compose", "--profile", "generators", "build",
            "playwright_bot", "human_sim", "pentesterpro",
        ],
        check=True,
    )
    run([sys.executable, "scripts/init_dvwa.py"], check=True)


def truncate_logs() -> None:
    for name in ("requests.jsonl", "honeypots.jsonl", "beacons.jsonl"):
        p = DATA / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("")


def gen_round(generators: list[tuple[str, int]], seed: int) -> dict:
    random.seed(seed)
    shuffled = list(generators)
    random.shuffle(shuffled)
    timings = []
    t0 = time.time()
    for svc, n in shuffled:
        s0 = time.time()
        rc = run(
            [
                "docker", "compose", "--profile", "generators", "run", "--rm",
                "-e", f"CERNIS_SESSIONS={n}",
                svc,
            ]
        )
        timings.append({"generator": svc, "sessions": n, "rc": rc, "elapsed_s": round(time.time() - s0, 1)})
        if rc != 0:
            raise SystemExit(f"[orchestrator] {svc} failed rc={rc}")
    return {"order": [svc for svc, _ in shuffled], "total_s": round(time.time() - t0, 1), "timings": timings}


def train_and_eval() -> dict:
    run(["docker", "compose", "--profile", "analysis", "build", "detector"], check=True)
    run(
        [
            "docker", "compose", "--profile", "analysis", "run", "--rm",
            "detector", "/app/train.py",
            "--data", "/data", "--out", "/data/models",
        ],
        check=True,
    )
    run(
        [
            "docker", "compose", "--profile", "analysis", "run", "--rm",
            "detector", "/app/eval.py",
            "--data", "/data", "--models", "/data/models",
            "--out", "/data/reports/phase4.json",
        ],
        check=True,
    )
    run(
        [
            "docker", "compose", "--profile", "analysis", "run", "--rm",
            "detector", "/app/heldout.py",
            "--data", "/data",
            "--out", "/data/reports/heldout.json",
        ],
        check=True,
    )
    return {
        "phase4": json.loads((REPORTS / "phase4.json").read_text()),
        "heldout": json.loads((REPORTS / "heldout.json").read_text()),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=6,
                    help="sessions per generator")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--no-truncate", action="store_true",
                    help="keep existing logs (append more data)")
    args = ap.parse_args()

    generators = [(svc, args.sessions) for svc, _ in DEFAULT_GENERATORS]

    ensure_target_up()
    if not args.no_truncate:
        truncate_logs()

    t0 = time.time()
    gen_summary = gen_round(generators, args.seed)
    detector_reports = train_and_eval()
    total_s = round(time.time() - t0, 1)

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_path = REPORTS / f"run_{ts}.json"
    summary = {
        "run_id": ts,
        "elapsed_s": total_s,
        "generators": gen_summary,
        "phase4": detector_reports["phase4"],
        "heldout": detector_reports["heldout"],
    }
    run_path.write_text(json.dumps(summary, indent=2))
    print(f"[orchestrator] wrote {run_path}", flush=True)

    # Brief console summary
    p4 = detector_reports["phase4"]
    print()
    print(f"== run {ts} ==")
    print(f"  total elapsed: {total_s}s")
    for k in ("with_hp", "ml_only"):
        h = p4.get(k, {})
        if h:
            print(
                f"  {k:>7}  PR-AUC={h['pr_auc']:.4f}  "
                f"FP/hr={h['fp_per_hour']:.3f}  "
                f"τ={h['threshold']:.3f}"
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
