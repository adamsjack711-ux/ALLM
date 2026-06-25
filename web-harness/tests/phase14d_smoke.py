"""phase 14d verification gate — pricing drift + persisted spend + mid-call hard kill.

Four offline parts. No LLM, no docker.

PART A — pricing drift detection (pure import test)
  - staleness_days() honors spoofed `now`
  - is_stale() flips True only beyond STALE_DAYS
  - warn_if_stale() emits one-line stderr message when stale, nothing
    otherwise; returns the matching bool
  - print_table() emits the version banner + every PRICING entry
  - PRICING_TABLE_VERSION + LAST_REVIEWED constants present

PART B — persisted spend, single run
  - Run bot subprocess with CERNIS_DRY_RUN_TOKENS + CERNIS_AGENT_DRY_RUN
    + CERNIS_PERSISTED_SPEND_FILE pointing at a fresh path
  - Verify the file lands with {cents, updated_at, max_budget_cents,
    pricing_table_version, skipped_cells_so_far} and non-zero cents

PART C — persisted spend, cross-run carry-over
  - Second subprocess pointing at the same file with a tight budget
  - Verify the loaded spend triggers the kill-switch immediately:
    no dry-run rows logged in the second invocation; budget summary
    reports carry-over
  - Verify the stderr warning when max_budget_cents in the file
    differs from the env var

PART D — mid-call hard kill (direct callback test)
  - Construct _TokenCounter(backend, model); spoof _spend_state to
    just-below-budget. Calling on_llm_start with no token accumulation
    must pass. Bump _spend_state past budget; on_llm_start must raise
    BudgetExceeded. With budget unset, on_llm_start is always a no-op.
  - realized_cost_cents() returns None when backend/model unset;
    correct math when set.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import importlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "generators" / "real_agent"))

import pricing as pricingmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: pricing drift ───────────────────────────────────────────


def part_a_drift() -> None:
    print("\n[smoke-p14d] PART A — pricing drift detection")
    _assert(hasattr(pricingmod, "PRICING_TABLE_VERSION"),
            "[A] pricingmod missing PRICING_TABLE_VERSION")
    _assert(hasattr(pricingmod, "LAST_REVIEWED"),
            "[A] pricingmod missing LAST_REVIEWED")
    _assert(isinstance(pricingmod.LAST_REVIEWED, dt.date),
            f"[A] LAST_REVIEWED not a date: {type(pricingmod.LAST_REVIEWED)}")
    _assert(pricingmod.STALE_DAYS > 0,
            f"[A] STALE_DAYS not positive: {pricingmod.STALE_DAYS}")

    # staleness_days respects spoofed now
    same_day = pricingmod.staleness_days(now=pricingmod.LAST_REVIEWED)
    _assert(same_day == 0, f"[A] same-day staleness should be 0: {same_day}")
    future = pricingmod.LAST_REVIEWED + dt.timedelta(days=400)
    days = pricingmod.staleness_days(now=future)
    _assert(days == 400, f"[A] staleness 400d expected, got {days}")

    # is_stale flips at boundary
    boundary = pricingmod.LAST_REVIEWED + dt.timedelta(days=pricingmod.STALE_DAYS)
    over = boundary + dt.timedelta(days=1)
    _assert(not pricingmod.is_stale(now=boundary),
            f"[A] is_stale at boundary should be False")
    _assert(pricingmod.is_stale(now=over),
            f"[A] is_stale past boundary should be True")

    # warn_if_stale: emits when stale, silent otherwise
    fresh_buf = io.StringIO()
    fired = pricingmod.warn_if_stale(stream=fresh_buf, now=pricingmod.LAST_REVIEWED)
    _assert(fired is False and fresh_buf.getvalue() == "",
            f"[A] warn_if_stale on fresh day: fired={fired}, "
            f"buf={fresh_buf.getvalue()!r}")

    stale_buf = io.StringIO()
    fired = pricingmod.warn_if_stale(stream=stale_buf, now=over)
    _assert(fired is True,
            f"[A] warn_if_stale on stale day should fire")
    msg = stale_buf.getvalue()
    _assert("pricing" in msg.lower() and "stale" not in msg.lower()
            and pricingmod.LAST_REVIEWED.isoformat() in msg,
            f"[A] warn message wrong: {msg!r}")

    # print_table emits the version banner + every PRICING entry
    tbl_buf = io.StringIO()
    pricingmod.print_table(stream=tbl_buf)
    table_text = tbl_buf.getvalue()
    _assert(f"v{pricingmod.PRICING_TABLE_VERSION}" in table_text,
            f"[A] print_table missing version: {table_text[:200]}")
    for (backend, model) in pricingmod.PRICING:
        _assert(model in table_text,
                f"[A] print_table missing {backend}/{model}: "
                f"{table_text[:400]}")
    print("[smoke-p14d] PART A passed")


# ── PART B + C: persisted spend ─────────────────────────────────────


def _run_bot(
    td: pathlib.Path, *,
    persisted_file: pathlib.Path | None,
    budget_env: str | None,
    tokens: str = "100000/50000",
) -> tuple[list[dict], str, str]:
    """Run bot subprocess in dry-run with one cell. Returns (log_rows,
    stdout, stderr)."""
    td.mkdir(parents=True, exist_ok=True)
    cells_path = td / "cells.json"
    log_path = td / "dry_run.jsonl"
    cells_path.write_text(json.dumps({"cells": [{
        "target_url": "http://capture:8080", "target_app": "dvwa",
        "backend": "openai", "model": "gpt-4o-mini",
        "stealth": False, "sessions": 1,
    }]}))
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": str(ROOT / "generators" / "shared"),
        "CERNIS_AGENT_CELLS_FILE": str(cells_path),
        "CERNIS_AGENT_DRY_RUN": "1",
        "CERNIS_DRY_RUN_LOG": str(log_path),
        "CERNIS_DRY_RUN_TOKENS": tokens,
    }
    if persisted_file is not None:
        env["CERNIS_PERSISTED_SPEND_FILE"] = str(persisted_file)
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


def part_b_persisted_single(td: pathlib.Path) -> None:
    print("\n[smoke-p14d] PART B — persisted spend, single run")
    persisted = td / "persisted.json"
    # 100k input × 15¢/M + 50k output × 60¢/M = 1.5¢ + 3¢ = 4.5¢/cell
    rows, _stdout, _ = _run_bot(
        td, persisted_file=persisted, budget_env="100", tokens="100000/50000",
    )
    _assert(len(rows) == 1, f"[B] expected 1 logged cell, got {len(rows)}")
    _assert(persisted.exists(),
            f"[B] persisted file not created: {persisted}")
    payload = json.loads(persisted.read_text())
    for key in ("cents", "updated_at", "max_budget_cents",
                "pricing_table_version", "skipped_cells_so_far"):
        _assert(key in payload,
                f"[B] persisted payload missing {key!r}: {payload}")
    expected_cents = (100000 * 15 + 50000 * 60) / 1_000_000
    _assert(abs(payload["cents"] - expected_cents) < 1e-6,
            f"[B] persisted cents wrong: {payload['cents']} vs "
            f"{expected_cents}")
    _assert(payload["max_budget_cents"] == 100,
            f"[B] persisted budget wrong: {payload}")
    _assert(payload["pricing_table_version"] ==
            pricingmod.PRICING_TABLE_VERSION,
            f"[B] persisted pricing version wrong: {payload}")
    print(f"[smoke-p14d]   persisted {payload['cents']:.4f}¢ to "
          f"{persisted.name}")
    print("[smoke-p14d] PART B passed")


def part_c_persisted_carry(td: pathlib.Path) -> None:
    print("\n[smoke-p14d] PART C — persisted spend, cross-run carry-over")
    persisted = td / "persisted.json"
    # First run: spend ~4.5¢ under a 100¢ budget. Persists.
    _, stdout1, _ = _run_bot(
        td / "first", persisted_file=persisted, budget_env="100",
        tokens="100000/50000",
    )
    first_payload = json.loads(persisted.read_text())
    first_spent = first_payload["cents"]
    _assert(first_spent > 0, f"[C] first run wrote zero cents: {first_payload}")

    # Second run: tighter budget BELOW the carry-over. Kill-switch
    # should fire immediately; no new dry-run rows logged.
    tight_budget = f"{first_spent - 0.0001:.6f}"
    rows2, stdout2, stderr2 = _run_bot(
        td / "second", persisted_file=persisted, budget_env=tight_budget,
        tokens="100000/50000",
    )
    _assert(len(rows2) == 0,
            f"[C] second run should log 0 cells (already over carried-"
            f"over budget); got {len(rows2)}")
    _assert("budget summary" in stdout2,
            f"[C] second run stdout missing budget summary:\n{stdout2}")
    _assert("persisted budget changed" in stderr2,
            f"[C] expected drift warning when budget differs:\n{stderr2}")

    # Third run with the SAME budget as the first should accept new
    # spend (carry-over + 4.5¢ < 100¢).
    rows3, stdout3, _ = _run_bot(
        td / "third", persisted_file=persisted, budget_env="100",
        tokens="100000/50000",
    )
    _assert(len(rows3) == 1,
            f"[C] third run should log 1 cell with room in budget; got "
            f"{len(rows3)}")
    final_payload = json.loads(persisted.read_text())
    _assert(final_payload["cents"] > first_spent + 0.0001,
            f"[C] third run didn't add to carry-over: first={first_spent}, "
            f"final={final_payload['cents']}")
    print(f"[smoke-p14d]   carry-over: first={first_spent:.4f}¢, "
          f"final={final_payload['cents']:.4f}¢")
    print("[smoke-p14d] PART C passed")


# ── PART D: mid-call hard kill ──────────────────────────────────────


def part_d_mid_call_kill() -> None:
    print("\n[smoke-p14d] PART D — mid-call hard kill (callback test)")
    # We need a fresh bot module per test because MAX_BUDGET_CENTS is
    # captured at import time. Use importlib to reload per scenario.
    def _fresh_bot(env_max_budget: str | None):
        if env_max_budget is None:
            os.environ.pop("CERNIS_MAX_BUDGET_CENTS", None)
        else:
            os.environ["CERNIS_MAX_BUDGET_CENTS"] = env_max_budget
        # Reload pricingmod is not required (it has no env-var state),
        # but bot.py has module-level MAX_BUDGET_CENTS that's recomputed
        # at reload time.
        sys.path.insert(0, str(ROOT / "generators" / "shared"))  # for manifest+target_guard
        import bot  # type: ignore
        importlib.reload(bot)
        return bot

    # Scenario 1: budget unset → on_llm_start always passes
    bot1 = _fresh_bot(None)
    counter = bot1._TokenCounter(backend="openai", model="gpt-4o-mini")
    asyncio.run(counter.on_llm_start())  # must not raise

    # realized_cost_cents() without backend/model is None
    bare = bot1._TokenCounter()
    _assert(bare.realized_cost_cents() is None,
            "[D] bare TokenCounter realized_cost should be None")
    counter.tokens_in, counter.tokens_out = 1000, 1000
    rc = counter.realized_cost_cents()
    expected = (1000 * 15 + 1000 * 60) / 1_000_000
    _assert(rc is not None and abs(rc - expected) < 1e-9,
            f"[D] realized_cost wrong: {rc} vs {expected}")

    # Scenario 2: budget set, room → passes
    bot2 = _fresh_bot("100")
    counter2 = bot2._TokenCounter(backend="openai", model="gpt-4o-mini")
    bot2._spend_state["cents"] = 50.0
    asyncio.run(counter2.on_llm_start())  # 50¢ + 0 < 100¢

    # Scenario 3: budget set, over → BudgetExceeded
    bot3 = _fresh_bot("10")
    counter3 = bot3._TokenCounter(backend="openai", model="gpt-4o-mini")
    bot3._spend_state["cents"] = 9.9
    counter3.tokens_in, counter3.tokens_out = 1000000, 1000000  # ~75¢
    try:
        asyncio.run(counter3.on_llm_start())
        raise AssertionError("[D] on_llm_start should have raised BudgetExceeded")
    except bot3.BudgetExceeded as exc:
        msg = str(exc)
        _assert("budget" in msg.lower(),
                f"[D] BudgetExceeded message wrong: {msg!r}")
    print("[smoke-p14d] PART D passed")


def main() -> None:
    t0 = time.monotonic()
    part_a_drift()
    with tempfile.TemporaryDirectory(prefix="cernis_p14d_b_") as td:
        part_b_persisted_single(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p14d_c_") as td:
        part_c_persisted_carry(pathlib.Path(td))
    part_d_mid_call_kill()
    print()
    print(f"PHASE-14D SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
