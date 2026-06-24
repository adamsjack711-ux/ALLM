"""phase 14b verification gate — per-cell cost accounting for the LLM matrix.

Four offline parts. NO LLM is called. The smoke spoofs token counts via
the `CERNIS_DRY_RUN_TOKENS` env var so the cost-accounting pipeline can
be validated end-to-end without spending any budget.

PART A — pricing.py
  - lookup() returns the right entries for the supported pairs
  - lookup() returns None for unknown (backend, model)
  - estimate_cost_cents() respects token counts and per-pair rates
  - estimate_cost_cents() returns None for unpriced pairs
  - format_cents() handles None, sub-cent, and dollar values cleanly

PART B — bot.py dry-run with spoofed tokens
  - run the bot with CERNIS_AGENT_DRY_RUN=1 + CERNIS_DRY_RUN_TOKENS=600/400
    + a single-cell cells_file
  - assert the dry-run log row carries extra.tokens_in=600,
    extra.tokens_out=400, and a non-None extra.estimated_cost_cents
    matching pricing.estimate_cost_cents("openai","gpt-4o-mini",600,400)
  - assert an unpriced model (made-up name) writes
    extra.estimated_cost_cents=null
  - assert the legacy dry-run (no CERNIS_DRY_RUN_TOKENS) writes
    tokens_in=0, tokens_out=0 with non-None cost (zero) for priced pairs

PART C — orchestrator/sweep.py cost_projection_for_cells
  - 12-cell default matrix → non-zero total_cents + per-cell breakdown
  - unpriced model surfaces in `unpriced_cells`
  - format_cents result lands in `total_formatted`

PART D — dashboard.llm_spend_summary
  - synthetic sessions.jsonl mixes llm_openai_* + llm_anthropic_* +
    non-LLM agent + stale (out-of-window) rows
  - llm_spend_summary respects the 24h window
  - per-backend-model breakdown sums correctly
  - unpriced session count populates when a session's
    estimated_cost_cents is null
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
sys.path.insert(0, str(ROOT / "generators" / "real_agent"))

import pricing as pricingmod  # noqa: E402
from dashboard import app as dashmod  # noqa: E402
from orchestrator import sweep as sweepmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: pricing.py ──────────────────────────────────────────────


def part_a_pricing() -> None:
    print("\n[smoke-p14b] PART A — pricing.py")
    p = pricingmod.lookup("openai", "gpt-4o-mini")
    _assert(p is not None and p["input"] == 15.0 and p["output"] == 60.0,
            f"[A] gpt-4o-mini pricing wrong: {p}")
    _assert(pricingmod.lookup("openai", "nonexistent-model") is None,
            "[A] unknown model didn't return None")
    _assert(pricingmod.lookup("nonexistent", "gpt-4o-mini") is None,
            "[A] unknown backend didn't return None")

    # estimate: 600 input × 15 + 400 output × 60 = 9000 + 24000 = 33000
    # cents-per-million-tokens × tokens / 1M → 0.033 cents
    c = pricingmod.estimate_cost_cents("openai", "gpt-4o-mini", 600, 400)
    expected = (600 * 15.0 + 400 * 60.0) / 1_000_000.0
    _assert(c is not None and abs(c - expected) < 1e-9,
            f"[A] estimate_cost_cents: got {c}, expected {expected}")
    _assert(pricingmod.estimate_cost_cents("openai", "fake", 100, 50) is None,
            "[A] unpriced pair didn't return None")
    _assert(pricingmod.estimate_cost_cents("openai", "gpt-4o-mini", 0, 0) == 0.0,
            "[A] zero tokens didn't give zero cost")

    # format_cents
    _assert(pricingmod.format_cents(None) == "unpriced",
            "[A] format_cents(None) wrong")
    _assert(pricingmod.format_cents(0.5).startswith("$0.00"),
            f"[A] format_cents(sub-cent) wrong: {pricingmod.format_cents(0.5)}")
    _assert(pricingmod.format_cents(500.0) == "$5.00",
            f"[A] format_cents($5) wrong: {pricingmod.format_cents(500.0)}")
    print("[smoke-p14b] PART A passed")


# ── PART B: bot.py dry-run with spoofed tokens ─────────────────────


def _run_bot_dry(
    td: pathlib.Path, cells: list[dict],
    spoofed: str | None = None,
) -> list[dict]:
    """Run the bot with CERNIS_AGENT_DRY_RUN=1 and the given cells_file.
    Optionally inject CERNIS_DRY_RUN_TOKENS. Returns the parsed dry-run log."""
    td.mkdir(parents=True, exist_ok=True)
    cells_path = td / "cells.json"
    log_path = td / "dry_run.jsonl"
    cells_path.write_text(json.dumps({"cells": cells}))
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": str(ROOT / "generators" / "shared"),
        "CERNIS_AGENT_CELLS_FILE": str(cells_path),
        "CERNIS_AGENT_DRY_RUN": "1",
        "CERNIS_DRY_RUN_LOG": str(log_path),
    }
    if spoofed is not None:
        env["CERNIS_DRY_RUN_TOKENS"] = spoofed
    cp = subprocess.run(
        [sys.executable, str(ROOT / "generators" / "real_agent" / "bot.py")],
        env=env, capture_output=True, text=True, timeout=30,
    )
    if cp.returncode != 0:
        raise AssertionError(
            f"bot exited {cp.returncode}\n"
            f"stdout:\n{cp.stdout}\nstderr:\n{cp.stderr}"
        )
    return [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]


def part_b_bot_spoofed(td: pathlib.Path) -> None:
    print("\n[smoke-p14b] PART B — bot.py dry-run with spoofed tokens")

    # (B1) Spoofed tokens land on the payload's extra block
    rows = _run_bot_dry(
        td / "b1",
        cells=[{
            "target_url": "http://capture:8080", "target_app": "dvwa",
            "backend": "openai", "model": "gpt-4o-mini",
            "stealth": False, "sessions": 1,
        }],
        spoofed="600/400",
    )
    _assert(len(rows) == 1, f"[B] expected 1 dry-run row, got {len(rows)}")
    extra = rows[0]["payload"]["extra"]
    _assert(extra.get("tokens_in") == 600,
            f"[B] tokens_in={extra.get('tokens_in')!r}")
    _assert(extra.get("tokens_out") == 400,
            f"[B] tokens_out={extra.get('tokens_out')!r}")
    expected_cost = (600 * 15.0 + 400 * 60.0) / 1_000_000.0
    _assert(extra.get("estimated_cost_cents") is not None
            and abs(extra["estimated_cost_cents"] - expected_cost) < 1e-9,
            f"[B] estimated_cost_cents={extra.get('estimated_cost_cents')!r} "
            f"expected {expected_cost}")

    # (B2) Unpriced model → estimated_cost_cents is null
    rows2 = _run_bot_dry(
        td / "b2",
        cells=[{
            "target_url": "http://capture:8080", "target_app": "dvwa",
            "backend": "openai", "model": "made-up-model",
            "stealth": False, "sessions": 1,
        }],
        spoofed="100/200",
    )
    extra2 = rows2[0]["payload"]["extra"]
    _assert(extra2.get("tokens_in") == 100,
            f"[B2] tokens_in wrong: {extra2}")
    _assert(extra2.get("estimated_cost_cents") is None,
            f"[B2] unpriced model didn't return null cost: "
            f"{extra2.get('estimated_cost_cents')!r}")

    # (B3) Legacy dry-run (no CERNIS_DRY_RUN_TOKENS) writes zeros
    rows3 = _run_bot_dry(
        td / "b3",
        cells=[{
            "target_url": "http://capture:8080", "target_app": "dvwa",
            "backend": "openai", "model": "gpt-4o-mini",
            "stealth": False, "sessions": 1,
        }],
    )
    extra3 = rows3[0]["payload"]["extra"]
    _assert(extra3.get("tokens_in") == 0,
            f"[B3] legacy dry-run should write tokens_in=0, got "
            f"{extra3.get('tokens_in')!r}")
    _assert(extra3.get("estimated_cost_cents") == 0.0,
            f"[B3] legacy dry-run should give zero cost for priced pair, "
            f"got {extra3.get('estimated_cost_cents')!r}")
    print("[smoke-p14b] PART B passed")


# ── PART C: orchestrator sweep cost projection ──────────────────────


def part_c_sweep_projection() -> None:
    print("\n[smoke-p14b] PART C — sweep cost_projection_for_cells")
    cells = sweepmod.default_llm_config()
    _assert(len(cells) >= 1, f"[C] empty matrix: {cells}")
    cost = sweepmod.cost_projection_for_cells(cells)
    for key in ("default_tokens_per_session", "per_cell", "total_cents",
                "total_formatted", "unpriced_cells"):
        _assert(key in cost, f"[C] cost missing {key!r}")
    _assert(len(cost["per_cell"]) == len(cells),
            f"[C] per_cell length wrong: {len(cost['per_cell'])} vs "
            f"{len(cells)}")
    _assert(cost["total_cents"] > 0,
            f"[C] default matrix should have positive cost: "
            f"{cost['total_cents']}")
    _assert(cost["unpriced_cells"] == [],
            f"[C] default matrix has unpriced cells: {cost['unpriced_cells']}")
    _assert(cost["total_formatted"].startswith("$"),
            f"[C] format wrong: {cost['total_formatted']}")

    # Custom matrix with an unpriced model should surface in unpriced_cells
    custom = sweepmod.default_llm_config(
        backends=("openai",),
        models={"openai": ("gpt-4o-mini", "nonexistent-fake-model")},
        target_apps=("dvwa",),
        stealth_axes=(False,),
    )
    cost2 = sweepmod.cost_projection_for_cells(custom)
    _assert("openai/nonexistent-fake-model" in cost2["unpriced_cells"],
            f"[C] unpriced detection failed: {cost2['unpriced_cells']}")
    print(f"[smoke-p14b]   default 12-cell projection: "
          f"{cost['total_formatted']}")
    print("[smoke-p14b] PART C passed")


# ── PART D: dashboard llm_spend_summary ─────────────────────────────


def part_d_llm_spend(td: pathlib.Path) -> None:
    print("\n[smoke-p14b] PART D — dashboard.llm_spend_summary")
    now = time.time()
    rows = [
        # 3 OpenAI sessions in window (priced)
        {"ts": now - 1000, "session_id": "s1", "family": "llm_openai_gpt_4o_mini",
         "class": "agent", "target_app": "dvwa",
         "extra": {"backend": "openai", "model": "gpt-4o-mini",
                   "tokens_in": 600, "tokens_out": 400,
                   "estimated_cost_cents": 0.033}},
        {"ts": now - 800, "session_id": "s2", "family": "llm_openai_gpt_4o_mini",
         "class": "agent", "target_app": "dvwa",
         "extra": {"backend": "openai", "model": "gpt-4o-mini",
                   "tokens_in": 500, "tokens_out": 300,
                   "estimated_cost_cents": 0.025}},
        {"ts": now - 600, "session_id": "s3",
         "family": "llm_anthropic_claude_haiku_4_5",
         "class": "agent", "target_app": "dvwa",
         "extra": {"backend": "anthropic", "model": "claude-haiku-4-5",
                   "tokens_in": 800, "tokens_out": 500,
                   "estimated_cost_cents": 0.264}},
        # 1 unpriced session
        {"ts": now - 400, "session_id": "s4",
         "family": "llm_openai_fake_model",
         "class": "agent", "target_app": "dvwa",
         "extra": {"backend": "openai", "model": "fake_model",
                   "tokens_in": 100, "tokens_out": 50,
                   "estimated_cost_cents": None}},
        # non-LLM session (must be ignored)
        {"ts": now - 200, "session_id": "s5", "family": "playwright_bot",
         "class": "agent", "target_app": "dvwa",
         "extra": {}},
        # stale row (>24h ago)
        {"ts": now - 99999, "session_id": "s_stale",
         "family": "llm_openai_gpt_4o_mini",
         "class": "agent", "target_app": "dvwa",
         "extra": {"backend": "openai", "model": "gpt-4o-mini",
                   "tokens_in": 999, "tokens_out": 999,
                   "estimated_cost_cents": 99.0}},
    ]
    sessions_path = td / "sessions.jsonl"
    sessions_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    summary = dashmod.llm_spend_summary(sessions_path, window_s=86400)
    _assert(summary["n_sessions"] == 4,
            f"[D] n_sessions wrong: {summary['n_sessions']}")
    _assert(summary["unpriced_sessions"] == 1,
            f"[D] unpriced_sessions wrong: {summary['unpriced_sessions']}")
    expected_total = 0.033 + 0.025 + 0.264
    _assert(abs(summary["total_cents"] - expected_total) < 1e-6,
            f"[D] total_cents wrong: {summary['total_cents']} vs "
            f"{expected_total}")

    by_pair = summary["by_backend_model"]
    _assert("openai/gpt-4o-mini" in by_pair,
            f"[D] openai/gpt-4o-mini missing: {sorted(by_pair)}")
    openai_cell = by_pair["openai/gpt-4o-mini"]
    _assert(openai_cell["n_sessions"] == 2,
            f"[D] openai n_sessions wrong: {openai_cell}")
    _assert(openai_cell["tokens_in"] == 1100,
            f"[D] openai tokens_in wrong: {openai_cell}")
    _assert(openai_cell["tokens_out"] == 700,
            f"[D] openai tokens_out wrong: {openai_cell}")
    _assert(by_pair["openai/fake_model"]["unpriced"] is True,
            f"[D] fake_model not flagged unpriced: "
            f"{by_pair['openai/fake_model']}")

    # tail_sessions surfaces the token fields
    tail = dashmod.tail_sessions(sessions_path, n=10)
    s1 = next((t for t in tail if t["session_id"] == "s1"), None)
    _assert(s1 is not None and s1.get("tokens_in") == 600,
            f"[D] tail_sessions doesn't surface tokens_in: {s1}")
    _assert(s1.get("estimated_cost_cents") == 0.033,
            f"[D] tail_sessions doesn't surface cost: {s1}")
    print("[smoke-p14b] PART D passed")


def main() -> None:
    t0 = time.monotonic()
    part_a_pricing()
    with tempfile.TemporaryDirectory(prefix="cernis_p14b_b_") as td:
        part_b_bot_spoofed(pathlib.Path(td))
    part_c_sweep_projection()
    with tempfile.TemporaryDirectory(prefix="cernis_p14b_d_") as td:
        part_d_llm_spend(pathlib.Path(td))
    print()
    print(f"PHASE-14B SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
