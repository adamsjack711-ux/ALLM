"""phase 14c verification gate — spend kill-switch + WebGoat in targets.

Five offline parts. No LLM, no docker. The kill-switch is exercised in
DRY_RUN mode with `CERNIS_DRY_RUN_TOKENS` spoofing token counts and
`CERNIS_MAX_BUDGET_CENTS` setting the cap.

PART A — kill-switch fires when budget would be exceeded
  - 5 cells, each cell projects $0.06 cost via spoofed tokens
  - budget=0.1¢ allows ~1 cell before tripping
  - dry-run log has fewer rows than cells_file
  - stdout reports "SKIP cell" + a budget summary

PART B — no budget set → all cells run
  - Same 5 cells, no MAX_BUDGET env → 5 log rows

PART C — budget=0 → zero cells run
  - The first cell's projected cost (any non-zero) exceeds budget=0
    so the kill-switch fires immediately

PART D — malformed budget → kill-switch disabled with a warning
  - Garbage string ("not-a-number") and negative value both fall back
    to "no cap" — all 5 cells run, stderr carries the warning

PART E — WebGoat in `_TARGETS` + `_LLM_TARGETS`
  - sweep.default_llm_config() now returns 4 × 2 × 1 × 2 = 16 cells
  - target_apps includes "webgoat"
  - sweep.default_config() (deterministic, non-LLM) includes webgoat cells
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from orchestrator import sweep as sweepmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── shared helpers ──────────────────────────────────────────────────


_CELLS = [
    {
        "target_url": "http://capture:8080", "target_app": "dvwa",
        "backend": "openai", "model": "gpt-4o-mini",
        "stealth": False, "sessions": 1,
    },
    {
        "target_url": "http://capture:8080", "target_app": "dvwa",
        "backend": "openai", "model": "gpt-4o-mini",
        "stealth": True, "sessions": 1,
    },
    {
        "target_url": "http://capture:8080", "target_app": "dvwa",
        "backend": "anthropic", "model": "claude-haiku-4-5",
        "stealth": False, "sessions": 1,
    },
    {
        "target_url": "http://capture:8080", "target_app": "dvwa",
        "backend": "anthropic", "model": "claude-haiku-4-5",
        "stealth": True, "sessions": 1,
    },
    {
        "target_url": "http://capture:8080", "target_app": "dvwa",
        "backend": "openai", "model": "gpt-4o",
        "stealth": False, "sessions": 1,
    },
]


def _run_bot(
    td: pathlib.Path, *, budget_env: str | None,
    tokens: str = "1000000/1000000",
) -> tuple[list[dict], str, str]:
    """Run the bot in DRY_RUN with spoofed tokens + optional
    CERNIS_MAX_BUDGET_CENTS. Returns (log_rows, stdout, stderr)."""
    td.mkdir(parents=True, exist_ok=True)
    cells_path = td / "cells.json"
    log_path = td / "dry_run.jsonl"
    cells_path.write_text(json.dumps({"cells": _CELLS}))
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": str(ROOT / "generators" / "shared"),
        "CERNIS_AGENT_CELLS_FILE": str(cells_path),
        "CERNIS_AGENT_DRY_RUN": "1",
        "CERNIS_DRY_RUN_LOG": str(log_path),
        "CERNIS_DRY_RUN_TOKENS": tokens,
    }
    if budget_env is not None:
        env["CERNIS_MAX_BUDGET_CENTS"] = budget_env
    cp = subprocess.run(
        [sys.executable, str(ROOT / "generators" / "real_agent" / "bot.py")],
        env=env, capture_output=True, text=True, timeout=30,
    )
    rows = (
        [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
        if log_path.exists() else []
    )
    if cp.returncode != 0:
        raise AssertionError(
            f"bot exited {cp.returncode}\n"
            f"stdout:\n{cp.stdout}\nstderr:\n{cp.stderr}"
        )
    return rows, cp.stdout, cp.stderr


# ── PART A: kill-switch fires ──────────────────────────────────────


def part_a_killswitch_fires(td: pathlib.Path) -> None:
    print("\n[smoke-p14c] PART A — kill-switch fires when budget would be exceeded")
    # 1M input × 15 cents/M + 1M output × 60 cents/M = 75 cents
    # per session on gpt-4o-mini. Budget 80¢ allows 1 cell to log
    # before the next one trips the cap.
    rows, stdout, _ = _run_bot(td, budget_env="80", tokens="1000000/1000000")
    _assert(0 < len(rows) < 5,
            f"[A] expected 1-4 cells logged before kill-switch; got "
            f"{len(rows)} (full 5 means kill-switch didn't fire)")
    _assert("SKIP cell" in stdout or "would exceed budget" in stdout,
            f"[A] stdout missing SKIP / budget message:\n{stdout}")
    _assert("budget summary" in stdout,
            f"[A] stdout missing budget summary line:\n{stdout}")
    print(f"[smoke-p14c]   {len(rows)}/5 cells logged before kill-switch fired")
    print("[smoke-p14c] PART A passed")


# ── PART B: no budget → all cells run ──────────────────────────────


def part_b_no_budget(td: pathlib.Path) -> None:
    print("\n[smoke-p14c] PART B — no budget set → all cells run")
    rows, stdout, _ = _run_bot(td, budget_env=None, tokens="1000000/1000000")
    _assert(len(rows) == 5,
            f"[B] expected 5 cells logged, got {len(rows)}")
    _assert("budget summary" not in stdout,
            f"[B] stdout should NOT carry budget summary without env "
            f"var:\n{stdout}")
    _assert("SKIP cell" not in stdout,
            f"[B] stdout shouldn't mention SKIP cell:\n{stdout}")
    print("[smoke-p14c] PART B passed")


# ── PART C: budget=0 → zero cells run ──────────────────────────────


def part_c_zero_budget(td: pathlib.Path) -> None:
    print("\n[smoke-p14c] PART C — budget=0 → zero cells run")
    rows, stdout, _ = _run_bot(td, budget_env="0", tokens="1000000/1000000")
    _assert(len(rows) == 0,
            f"[C] expected 0 cells logged, got {len(rows)}")
    _assert("SKIP cell" in stdout,
            f"[C] stdout missing SKIP cell message:\n{stdout}")
    print("[smoke-p14c] PART C passed")


# ── PART D: malformed budget → kill-switch disabled w/ warning ────


def part_d_bad_budget(td: pathlib.Path) -> None:
    print("\n[smoke-p14c] PART D — malformed budget → kill-switch disabled")
    # garbage non-numeric
    rows, _, stderr = _run_bot(
        td / "d1", budget_env="not-a-number", tokens="1000000/1000000",
    )
    _assert(len(rows) == 5,
            f"[D1] non-numeric budget should disable kill-switch, "
            f"got {len(rows)} logged cells")
    _assert("kill-switch DISABLED" in stderr,
            f"[D1] stderr missing DISABLED warning:\n{stderr}")
    # negative value
    rows2, _, stderr2 = _run_bot(
        td / "d2", budget_env="-5", tokens="1000000/1000000",
    )
    _assert(len(rows2) == 5,
            f"[D2] negative budget should disable kill-switch, "
            f"got {len(rows2)} logged cells")
    _assert("kill-switch DISABLED" in stderr2,
            f"[D2] stderr missing DISABLED warning:\n{stderr2}")
    print("[smoke-p14c] PART D passed")


# ── PART E: WebGoat registration ────────────────────────────────────


def part_e_webgoat() -> None:
    print("\n[smoke-p14c] PART E — WebGoat in _TARGETS + _LLM_TARGETS")
    _assert("webgoat" in sweepmod._TARGETS,
            "[E] webgoat missing from _TARGETS")
    _assert(sweepmod._TARGETS["webgoat"]["url"] ==
            "http://capture_webgoat:8080",
            f"[E] webgoat URL wrong: {sweepmod._TARGETS['webgoat']}")
    _assert("webgoat" in sweepmod._LLM_TARGETS,
            f"[E] webgoat missing from _LLM_TARGETS: {sweepmod._LLM_TARGETS}")

    cells = sweepmod.default_llm_config()
    _assert(len(cells) == 16,
            f"[E] expected 16-cell default matrix (4×2×1×2), got "
            f"{len(cells)}")
    target_apps = sorted({c.target_app for c in cells})
    _assert(target_apps == ["crapi", "dvwa", "juice_shop", "webgoat"],
            f"[E] default targets wrong: {target_apps}")

    # Deterministic (non-LLM) sweep grew too — webgoat cells must
    # appear in default_config().
    det_cfg = sweepmod.default_config()
    det_targets = sorted({c.target_app for c in det_cfg.cells})
    _assert("webgoat" in det_targets,
            f"[E] webgoat missing from deterministic sweep targets: "
            f"{det_targets}")
    print(f"[smoke-p14c]   det sweep grew to {len(det_cfg.cells)} cells "
          f"across {len(det_targets)} targets")
    print("[smoke-p14c] PART E passed")


def main() -> None:
    t0 = time.monotonic()
    part_e_webgoat()
    with tempfile.TemporaryDirectory(prefix="cernis_p14c_a_") as td:
        part_a_killswitch_fires(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p14c_b_") as td:
        part_b_no_budget(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p14c_c_") as td:
        part_c_zero_budget(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p14c_d_") as td:
        part_d_bad_budget(pathlib.Path(td))
    print()
    print(f"PHASE-14C SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
