"""Phase-3 verification gate.

Expected trip-rates (per session) with N=5 each:
  playwright_bot  invisible_field >= 80%
  playwright_bot  admin_secrets   >= 80%
  human_sim       *all four*       == 0%

The canary honeypot is intentionally not gated for the bot — it
requires reading and following a hidden DOM instruction (LLM-y
behavior). PentesterPro (phase 5, with mock_llm) is expected to
trip it. The playwright_bot has no DOM-instruction parser and so
should miss canary by design.

Writes per-honeypot rates to data/reports/phase3.json.
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
REPORT = ROOT / "data" / "reports" / "phase3.json"

N_BOT = int(os.environ.get("CERNIS_PHASE3_BOT", "5"))
N_HUMAN = int(os.environ.get("CERNIS_PHASE3_HUMAN", "5"))

HONEYPOTS = ["invisible_field", "admin_secrets", "canary", "robots_read"]


def run(cmd: list[str], check: bool = False) -> int:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=ROOT)
    if check and cp.returncode != 0:
        raise SystemExit(f"command failed rc={cp.returncode}: {cmd}")
    return cp.returncode


def truncate(p: pathlib.Path) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("")


def main() -> None:
    run(["docker", "compose", "up", "-d", "--build", "capture"], check=True)
    run(
        [
            "docker", "compose", "--profile", "generators", "build",
            "playwright_bot", "human_sim",
        ],
        check=True,
    )
    run([sys.executable, "scripts/init_dvwa.py"], check=True)

    truncate(REQ)
    truncate(HON)

    t0 = time.time()
    rc1 = run([
        "docker", "compose", "--profile", "generators", "run", "--rm",
        "-e", f"CERNIS_SESSIONS={N_BOT}",
        "playwright_bot",
    ])
    rc2 = run([
        "docker", "compose", "--profile", "generators", "run", "--rm",
        "-e", f"CERNIS_SESSIONS={N_HUMAN}",
        "human_sim",
    ])
    if rc1 or rc2:
        raise SystemExit(f"[phase3] generator failed bot={rc1} human={rc2}")
    elapsed = time.time() - t0

    time.sleep(0.5)
    req_rows = [json.loads(l) for l in REQ.read_text().splitlines() if l.strip()]
    hon_rows = [json.loads(l) for l in HON.read_text().splitlines() if l.strip()]

    sess_label: dict[str, str] = {}
    sess_trips: dict[str, set[str]] = {}
    for r in req_rows:
        sess_label[r["session_id"]] = r["src_label"]
        sess_trips.setdefault(r["session_id"], set())
    for r in hon_rows:
        sess_label.setdefault(r["session_id"], r["src_label"])
        sess_trips.setdefault(r["session_id"], set()).add(r["honeypot"])

    rates: dict[str, dict] = {}
    for label in ("playwright_bot", "human_sim"):
        sids = [s for s, l in sess_label.items() if l == label]
        n = len(sids)
        per = {}
        for hp in HONEYPOTS:
            hit = sum(1 for s in sids if hp in sess_trips[s])
            per[hp] = {
                "hits": hit,
                "sessions": n,
                "rate": round(hit / n, 4) if n else 0.0,
            }
        rates[label] = per

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(rates, indent=2))

    bot = rates["playwright_bot"]
    hum = rates["human_sim"]
    assert bot["invisible_field"]["rate"] >= 0.8, (
        f"bot invisible_field rate {bot['invisible_field']['rate']:.2f} < 0.8"
    )
    assert bot["admin_secrets"]["rate"] >= 0.8, (
        f"bot admin_secrets rate {bot['admin_secrets']['rate']:.2f} < 0.8"
    )
    for hp in HONEYPOTS:
        r = hum[hp]["rate"]
        assert r == 0.0, f"human_sim tripped {hp} at rate {r:.2f} — should be 0"

    print()
    print(f"PHASE 3 SMOKE PASSED ✅  elapsed={elapsed:.1f}s  report={REPORT}")
    for label in ("playwright_bot", "human_sim"):
        per = rates[label]
        cells = "  ".join(
            f"{hp}={per[hp]['hits']}/{per[hp]['sessions']}"
            for hp in HONEYPOTS
        )
        print(f"  {label:>14}  {cells}")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
