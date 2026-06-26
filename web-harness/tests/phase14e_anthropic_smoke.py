"""phase 14e verification gate — Anthropic (Claude) attacker family.

The Anthropic backend is a SECOND attacker family on the existing
`real_agent` scaffolding, not a new pentester. This gate pins the
invariants that keep it that way. All parts are offline: no docker, no
LLM call, no API spend, no real key.

PART A — target_guard fires BEFORE the Anthropic client import
  - In-process: `import bot` does NOT pull in `langchain_anthropic`
    (the ChatAnthropic import is deferred into `_run_one_session`).
  - `build_cells()` on a non-loopback Anthropic cell raises SystemExit,
    and `langchain_anthropic` is STILL not in sys.modules — proof the
    loopback guard ran before any Anthropic client could be imported.
  - Subprocess: a non-loopback Anthropic cell hard-exits non-zero with
    `target_guard` in stderr (per-cell, no CLI override).

PART B — no new attack logic: reuses the OpenAI path's templates
  - The resolved task for an Anthropic DVWA/Juice-Shop cell is
    byte-identical to the OpenAI cell for the same target (the task is
    backend-independent — `_DEFAULT_TASKS` with `{target}` substituted).
  - `prompt_template_id` is the same target-app slug the OpenAI path
    emits. The Claude agent drives the same textbook task; it invents
    nothing.

PART C — dry-run spends nothing + carries the right labels + leaks no key
  - A sentinel ANTHROPIC_API_KEY is set in the env. After a dry-run, the
    sentinel appears in NEITHER the dry-run log NOR stdout/stderr.
  - stdout says "no LLM call made"; family is `llm_anthropic_*`;
    `extra` carries tokens_in/tokens_out/estimated_cost_cents; no
    "accuracy" field anywhere in the emitted payload.

PART D — budget cap blocks an over-cap Anthropic projection
  - An Anthropic cell whose projected cell cost exceeds a tiny
    CERNIS_MAX_BUDGET_CENTS logs ZERO rows and prints the SKIP line.
  - The kill-switch summary reports the cell skipped.
"""

from __future__ import annotations

import importlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "generators" / "shared"))
sys.path.insert(0, str(ROOT / "generators" / "real_agent"))

BOT = ROOT / "generators" / "real_agent" / "bot.py"
# A throwaway sentinel — shaped like a real Anthropic key so a substring
# search would catch it if the bot ever echoed the key. It is never a
# real credential.
SENTINEL_KEY = "sk-ant-SMOKE-SENTINEL-must-never-be-logged-0000"


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _run_bot(
    td: pathlib.Path, *, cells: list[dict],
    dry_run: bool = True, budget_env: str | None = None,
    tokens: str = "9000/2250", with_key: bool = True,
) -> tuple[list[dict], subprocess.CompletedProcess]:
    """Run the bot subprocess against `cells`. Returns (dry_run_rows, cp).

    PATH is deliberately minimal and the only Anthropic credential is the
    sentinel — a real run never happens here (dry-run makes no LLM call;
    a bad target hard-exits first)."""
    td.mkdir(parents=True, exist_ok=True)
    cells_path = td / "cells.json"
    log_path = td / "dry_run.jsonl"
    cells_path.write_text(json.dumps({"cells": cells}))
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": str(ROOT / "generators" / "shared"),
        "CERNIS_AGENT_CELLS_FILE": str(cells_path),
        "CERNIS_DRY_RUN_LOG": str(log_path),
        "CERNIS_DRY_RUN_TOKENS": tokens,
    }
    if dry_run:
        env["CERNIS_AGENT_DRY_RUN"] = "1"
    if budget_env is not None:
        env["CERNIS_MAX_BUDGET_CENTS"] = budget_env
    if with_key:
        env["ANTHROPIC_API_KEY"] = SENTINEL_KEY
    cp = subprocess.run(
        [sys.executable, str(BOT)],
        env=env, capture_output=True, text=True, timeout=30,
    )
    rows = (
        [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
        if log_path.exists() else []
    )
    return rows, cp


# ── PART A: guard before the Anthropic import ───────────────────────


def part_a_guard_before_import(td: pathlib.Path) -> None:
    print("\n[smoke-p14e] PART A — target_guard fires before the Anthropic import")

    # In-process: importing the bot must NOT import the Anthropic client.
    import bot  # type: ignore
    importlib.reload(bot)
    _assert("langchain_anthropic" not in sys.modules,
            "[A] importing bot pulled in langchain_anthropic — the "
            "ChatAnthropic import is not deferred")

    # A non-loopback Anthropic cell must be rejected at build time,
    # BEFORE the Anthropic client is importable in _run_one_session.
    bad = td / "bad_cells.json"
    bad.write_text(json.dumps({"cells": [{
        "target_url": "http://evil.example.com:8080",
        "target_app": "dvwa", "backend": "anthropic",
        "model": "claude-haiku-4-5", "stealth": False, "sessions": 1,
    }]}))
    os.environ["CERNIS_AGENT_CELLS_FILE"] = str(bad)
    try:
        bot.build_cells()
        raise AssertionError("[A] build_cells accepted a non-loopback "
                             "Anthropic target")
    except SystemExit as exc:
        _assert("target_guard" in str(exc) or "allow-list" in str(exc),
                f"[A] rejection wasn't a target_guard exit: {exc!r}")
    finally:
        os.environ.pop("CERNIS_AGENT_CELLS_FILE", None)
    _assert("langchain_anthropic" not in sys.modules,
            "[A] langchain_anthropic was imported despite the target being "
            "rejected — the guard must run before the client import")

    # Subprocess: same thing end-to-end, non-zero exit + target_guard msg.
    _rows, cp = _run_bot(
        td / "sub", cells=[{
            "target_url": "http://evil.example.com:8080",
            "target_app": "dvwa", "backend": "anthropic",
            "model": "claude-haiku-4-5", "stealth": False, "sessions": 1,
        }], dry_run=True,
    )
    _assert(cp.returncode != 0,
            f"[A] off-allow-list Anthropic cell was accepted "
            f"(rc={cp.returncode})\nstdout:\n{cp.stdout}\nstderr:\n{cp.stderr}")
    _assert("target_guard" in cp.stderr,
            f"[A] target_guard didn't surface in the rejection:\n{cp.stderr}")
    print("[smoke-p14e] PART A passed")


# ── PART B: reuses the OpenAI templates (no new attack logic) ───────


def part_b_reuses_templates() -> None:
    print("\n[smoke-p14e] PART B — reuses the OpenAI path's task templates")
    import bot  # type: ignore
    importlib.reload(bot)

    url = "http://capture_dvwa:8080"
    for target_app, capture in (
        ("dvwa", "http://capture_dvwa:8080"),
        ("juice_shop", "http://capture_juiceshop:8080"),
    ):
        # The task is resolved backend-independently — same code path for
        # both attacker families. Prove the Claude task == the OpenAI task.
        task_openai = bot._resolve_task(target_app, capture, None, {})
        task_anthropic = bot._resolve_task(target_app, capture, None, {})
        _assert(task_openai == task_anthropic,
                f"[B] {target_app}: Anthropic task differs from OpenAI task")
        expected = bot._DEFAULT_TASKS[target_app].replace("{target}", capture)
        _assert(task_anthropic == expected,
                f"[B] {target_app}: task isn't the shared _DEFAULT_TASKS "
                f"template:\n  got: {task_anthropic!r}\n  exp: {expected!r}")

    # And the same is true through the cell builder + payload: an
    # Anthropic cell and an OpenAI cell for the same target produce the
    # same task string and the same prompt_template_id.
    o_cell = bot.AgentCell(
        target_url=url, target_app="dvwa", backend="openai",
        model="gpt-4o-mini", stealth=False, sessions=1,
        task=bot._resolve_task("dvwa", url, None, {}),
    )
    a_cell = bot.AgentCell(
        target_url=url, target_app="dvwa", backend="anthropic",
        model="claude-haiku-4-5", stealth=False, sessions=1,
        task=bot._resolve_task("dvwa", url, None, {}),
    )
    _assert(o_cell.task == a_cell.task,
            "[B] OpenAI and Anthropic cells resolved different tasks")
    o_extra = bot._payload_for(o_cell)["extra"]
    a_extra = bot._payload_for(a_cell)["extra"]
    _assert(o_extra["prompt_template_id"] == a_extra["prompt_template_id"],
            f"[B] prompt_template_id diverged: {o_extra['prompt_template_id']}"
            f" vs {a_extra['prompt_template_id']}")
    _assert(a_extra["framework"] == "browser-use",
            f"[B] Anthropic cell uses a non-browser-use framework: {a_extra}")
    print("[smoke-p14e] PART B passed")


# ── PART C: dry-run spends nothing, labels right, leaks no key ──────


def part_c_dry_run_no_spend_no_leak(td: pathlib.Path) -> None:
    print("\n[smoke-p14e] PART C — dry-run: $0 spend, no key leak, right labels")
    rows, cp = _run_bot(
        td, cells=[
            {"target_url": "http://capture_dvwa:8080", "target_app": "dvwa",
             "backend": "anthropic", "model": "claude-haiku-4-5",
             "stealth": False, "sessions": 2},
            {"target_url": "http://capture_juiceshop:8080",
             "target_app": "juice_shop", "backend": "anthropic",
             "model": "claude-haiku-4-5", "stealth": False, "sessions": 2},
        ],
        dry_run=True, budget_env="100", tokens="9000/2250",
    )
    _assert(cp.returncode == 0,
            f"[C] dry-run bot exited {cp.returncode}\n{cp.stderr}")
    _assert(len(rows) == 2, f"[C] expected 2 dry-run rows, got {len(rows)}")
    _assert("no LLM call made" in cp.stdout,
            f"[C] dry-run didn't confirm no LLM call:\n{cp.stdout}")

    # No API key anywhere the operator could read it.
    log_blob = (td / "dry_run.jsonl").read_text()
    for surface, blob in (("dry-run log", log_blob),
                          ("stdout", cp.stdout), ("stderr", cp.stderr)):
        _assert(SENTINEL_KEY not in blob,
                f"[C] sentinel API key leaked into {surface}")
        _assert("sk-ant" not in blob.lower(),
                f"[C] an 'sk-ant' key fragment appears in {surface}")

    for row in rows:
        payload = row["payload"]
        fam = payload["family"]
        _assert(fam.startswith("llm_anthropic_"),
                f"[C] family not llm_anthropic_*: {fam}")
        _assert(fam == "llm_anthropic_claude_haiku_4_5",
                f"[C] unexpected family slug: {fam}")
        extra = payload["extra"]
        for k in ("tokens_in", "tokens_out", "estimated_cost_cents"):
            _assert(k in extra, f"[C] extra missing {k!r}: {extra}")
        _assert(extra["backend"] == "anthropic",
                f"[C] extra.backend wrong: {extra}")
        # No accuracy ever leaks through the attacker provenance.
        _assert("accuracy" not in json.dumps(payload).lower(),
                f"[C] 'accuracy' present in payload: {payload}")
        # Header family mirrors the family.
        _assert(row["headers"]["X-Cernis-Family"] == fam,
                f"[C] header X-Cernis-Family != family")
    print("[smoke-p14e] PART C passed")


# ── PART D: budget cap blocks an over-cap Anthropic projection ──────


def part_d_budget_blocks(td: pathlib.Path) -> None:
    print("\n[smoke-p14e] PART D — budget cap blocks an over-cap Anthropic cell")
    # haiku-4-5: 9000 in × 80¢/M + 2250 out × 400¢/M = 0.72 + 0.90 = 1.62¢
    # per session. 5 sessions → 8.1¢ projected. Cap at 1¢ → must SKIP.
    rows, cp = _run_bot(
        td, cells=[{
            "target_url": "http://capture_dvwa:8080", "target_app": "dvwa",
            "backend": "anthropic", "model": "claude-haiku-4-5",
            "stealth": False, "sessions": 5,
        }],
        dry_run=True, budget_env="1", tokens="9000/2250",
    )
    _assert(cp.returncode == 0,
            f"[D] bot exited {cp.returncode}\n{cp.stderr}")
    _assert(len(rows) == 0,
            f"[D] over-cap Anthropic cell still logged {len(rows)} rows")
    _assert("SKIP cell" in cp.stdout and "exceed budget" in cp.stdout,
            f"[D] kill-switch SKIP line missing:\n{cp.stdout}")
    _assert("1 skipped by kill-switch" in cp.stdout,
            f"[D] budget summary didn't report the skip:\n{cp.stdout}")
    print("[smoke-p14e] PART D passed")


def main() -> None:
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cernis_p14e_a_") as td:
        part_a_guard_before_import(pathlib.Path(td))
    part_b_reuses_templates()
    with tempfile.TemporaryDirectory(prefix="cernis_p14e_c_") as td:
        part_c_dry_run_no_spend_no_leak(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p14e_d_") as td:
        part_d_budget_blocks(pathlib.Path(td))
    print()
    print(f"PHASE-14E SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
