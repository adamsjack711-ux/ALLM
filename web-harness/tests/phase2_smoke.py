"""Phase-2 verification gate.

Drives a small fixed budget through both generators and asserts the
labeled dataset is well-formed:
  - both labels (`playwright_bot`, `human_sim`) appear in requests.jsonl
  - no `session_id` is shared between labels (label leakage)
  - at least N distinct sessions per label
  - login was attempted (≥1 row with path `/login.php` per label)
  - the loopback-only target_guard sanity check passes via env smoke

Assumes phase-1 stack is already up (`docker compose up -d --build`).
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "requests.jsonl"

N_BOT = int(os.environ.get("CERNIS_PHASE2_BOT", "3"))
N_HUMAN = int(os.environ.get("CERNIS_PHASE2_HUMAN", "3"))


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, check=False, **kw)


def init_dvwa() -> None:
    cp = run([sys.executable, "scripts/init_dvwa.py"])
    if cp.returncode not in (0,):
        raise SystemExit(f"[phase2] DVWA init failed (rc={cp.returncode})")


def truncate_log() -> None:
    DATA.parent.mkdir(parents=True, exist_ok=True)
    DATA.write_text("")


def docker_run(service: str, sessions: int) -> int:
    return run(
        [
            "docker", "compose", "--profile", "generators",
            "run", "--rm",
            "-e", f"CERNIS_SESSIONS={sessions}",
            service,
        ]
    ).returncode


def read_rows() -> list[dict]:
    if not DATA.exists():
        return []
    return [json.loads(l) for l in DATA.read_text().splitlines() if l.strip()]


def assert_loopback_only() -> None:
    """Verify the guard refuses an external URL — sanity check, not behavior."""
    env = dict(os.environ)
    env["CERNIS_TARGET"] = "http://example.com"
    cp = subprocess.run(
        [sys.executable, "generators/shared/target_guard.py"],
        cwd=ROOT, env=env, capture_output=True,
    )
    if cp.returncode == 0:
        raise AssertionError(
            "[phase2] target_guard accepted external URL — guard is broken"
        )
    print("[phase2] target_guard rejects external URL as expected", flush=True)


def main() -> None:
    assert_loopback_only()
    init_dvwa()
    truncate_log()

    t0 = time.time()
    rc_bot = docker_run("playwright_bot", N_BOT)
    rc_hum = docker_run("human_sim", N_HUMAN)
    if rc_bot != 0 or rc_hum != 0:
        raise SystemExit(f"[phase2] generator failed: bot={rc_bot} human={rc_hum}")

    time.sleep(0.5)
    rows = read_rows()
    by_label: dict[str, list[dict]] = {}
    by_sid: dict[str, set[str]] = {}
    for r in rows:
        by_label.setdefault(r["src_label"], []).append(r)
        by_sid.setdefault(r["session_id"], set()).add(r["src_label"])

    labels = set(by_label)
    assert "playwright_bot" in labels, f"[phase2] no playwright_bot rows; labels={labels}"
    assert "human_sim" in labels, f"[phase2] no human_sim rows; labels={labels}"

    leaks = {sid: ls for sid, ls in by_sid.items() if len(ls) > 1}
    assert not leaks, f"[phase2] cross-label session_ids: {list(leaks.items())[:3]}"

    sids_bot = {r["session_id"] for r in by_label["playwright_bot"]}
    sids_hum = {r["session_id"] for r in by_label["human_sim"]}
    assert len(sids_bot) >= N_BOT, (
        f"[phase2] expected ≥{N_BOT} bot sessions, got {len(sids_bot)}"
    )
    assert len(sids_hum) >= N_HUMAN, (
        f"[phase2] expected ≥{N_HUMAN} human sessions, got {len(sids_hum)}"
    )

    bot_login = [r for r in by_label["playwright_bot"] if r["path"] == "/login.php"]
    hum_login = [r for r in by_label["human_sim"] if r["path"] == "/login.php"]
    assert bot_login, "[phase2] no /login.php from playwright_bot"
    assert hum_login, "[phase2] no /login.php from human_sim"

    elapsed = time.time() - t0
    print()
    print(f"PHASE 2 SMOKE PASSED ✅  elapsed={elapsed:.1f}s  rows={len(rows)}")
    print(
        f"  playwright_bot: sessions={len(sids_bot)} rows={len(by_label['playwright_bot'])}"
    )
    print(
        f"  human_sim     : sessions={len(sids_hum)} rows={len(by_label['human_sim'])}"
    )


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
