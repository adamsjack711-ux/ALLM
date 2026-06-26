"""phase-bench-7 verification gate — per-prompt-template cost attribution.

Phase 14 stamps `extra.prompt_template_id` on every LLM-agent
provenance row (today: `_slug(target_app)`; future: distinct ids per
task variant). Phase-bench-7 turns that field into a dashboard rollup
so the operator can answer "which prompt template is burning the most
budget?" without joining the data in their head.

Two offline parts.

PART A — `dashboard.llm_spend_summary` rollups
  - Stage a synthetic sessions.jsonl with 4 LLM sessions across 2
    prompt_template_ids × 2 (backend, model) pairs.
  - Verify the rollup carries `by_backend_model` (phase 14b),
    `by_template_backend_model` (new), `by_template` (new aggregated
    across backends/models).
  - Each cell has the expected n_sessions / tokens / cost_cents /
    unpriced fields.
  - The by_template aggregate's cost equals the sum of its
    by_template_backend_model components.
  - Unpriced session marks both the per-pair cell AND the per-template
    aggregate.

PART B — `/api/llm_spend` endpoint surfaces the new keys
  - Start the aiohttp app on a random loopback port.
  - GET /api/llm_spend → response carries the three rollup keys.
  - All sessions inside `window_s` count; stale rows excluded.
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import sys
import tempfile
import time

import aiohttp
from aiohttp import web

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "detector"))

from dashboard import app as dashmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _stage_sessions(td: pathlib.Path) -> pathlib.Path:
    """Synthesize sessions.jsonl with 4 LLM-flavor rows across two
    prompt templates and two (backend, model) pairs.

      template_a / openai / gpt-4o-mini : tokens 600/400 → cost 0.033
      template_a / anthropic / claude-haiku-4-5 : tokens 800/500 → cost 0.264
      template_b / openai / gpt-4o-mini : tokens 200/100 → cost 0.009
      template_b / anthropic / claude-haiku-4-5 : tokens 100/50  → unpriced (None)
    Plus one non-LLM session that must be ignored, and one stale row
    (outside window_s) that must be ignored.
    """
    now = time.time()
    rows = [
        {"ts": now - 100, "session_id": "a-openai", "family": "llm_openai_gpt_4o_mini",
         "class": "agent", "target_app": "dvwa",
         "extra": {"backend": "openai", "model": "gpt-4o-mini",
                   "prompt_template_id": "template_a",
                   "tokens_in": 600, "tokens_out": 400,
                   "estimated_cost_cents": 0.033}},
        {"ts": now - 95,  "session_id": "a-anthr", "family": "llm_anthropic_claude_haiku_4_5",
         "class": "agent", "target_app": "dvwa",
         "extra": {"backend": "anthropic", "model": "claude-haiku-4-5",
                   "prompt_template_id": "template_a",
                   "tokens_in": 800, "tokens_out": 500,
                   "estimated_cost_cents": 0.264}},
        {"ts": now - 90,  "session_id": "b-openai", "family": "llm_openai_gpt_4o_mini",
         "class": "agent", "target_app": "juice_shop",
         "extra": {"backend": "openai", "model": "gpt-4o-mini",
                   "prompt_template_id": "template_b",
                   "tokens_in": 200, "tokens_out": 100,
                   "estimated_cost_cents": 0.009}},
        {"ts": now - 80,  "session_id": "b-anthr-unpriced",
         "family": "llm_anthropic_fake_model",
         "class": "agent", "target_app": "juice_shop",
         "extra": {"backend": "anthropic", "model": "fake_model",
                   "prompt_template_id": "template_b",
                   "tokens_in": 100, "tokens_out": 50,
                   "estimated_cost_cents": None}},
        # non-LLM ignored
        {"ts": now - 50, "session_id": "playwright",
         "family": "playwright_bot", "class": "agent",
         "target_app": "dvwa", "extra": {}},
        # stale row (outside default window)
        {"ts": now - 999999, "session_id": "stale",
         "family": "llm_openai_gpt_4o_mini",
         "class": "agent", "target_app": "dvwa",
         "extra": {"backend": "openai", "model": "gpt-4o-mini",
                   "prompt_template_id": "stale_template",
                   "tokens_in": 9999, "tokens_out": 9999,
                   "estimated_cost_cents": 99.0}},
    ]
    sessions_path = td / "sessions.jsonl"
    sessions_path.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return sessions_path


def part_a_rollups(td: pathlib.Path) -> None:
    print("\n[smoke-pb7] PART A — llm_spend_summary per-template rollup")
    sessions_path = _stage_sessions(td)
    summary = dashmod.llm_spend_summary(sessions_path, window_s=86400)

    # Phase 14b key still present
    _assert("by_backend_model" in summary,
            f"[A] missing by_backend_model: {sorted(summary)}")
    # Phase-bench-7 new keys
    for key in ("by_template_backend_model", "by_template"):
        _assert(key in summary,
                f"[A] missing {key!r}: {sorted(summary)}")

    # n_sessions counts the 4 in-window LLM sessions only
    _assert(summary["n_sessions"] == 4,
            f"[A] n_sessions wrong: {summary['n_sessions']}")
    _assert(summary["unpriced_sessions"] == 1,
            f"[A] unpriced_sessions wrong: {summary['unpriced_sessions']}")

    # by_template_backend_model: 4 entries, one per (template, b, m)
    bytb = summary["by_template_backend_model"]
    expected_keys = {
        "template_a/openai/gpt-4o-mini",
        "template_a/anthropic/claude-haiku-4-5",
        "template_b/openai/gpt-4o-mini",
        "template_b/anthropic/fake_model",
    }
    _assert(set(bytb.keys()) == expected_keys,
            f"[A] by_template_backend_model keys wrong: {sorted(bytb)}")
    for k, cell in bytb.items():
        for col in ("prompt_template_id", "backend", "model",
                    "n_sessions", "tokens_in", "tokens_out",
                    "cost_cents", "unpriced"):
            _assert(col in cell,
                    f"[A] by_template_backend_model[{k}] missing {col}: {cell}")

    a_open = bytb["template_a/openai/gpt-4o-mini"]
    _assert(a_open["tokens_in"] == 600 and a_open["tokens_out"] == 400,
            f"[A] tokens wrong: {a_open}")
    _assert(abs(a_open["cost_cents"] - 0.033) < 1e-9,
            f"[A] cost wrong: {a_open}")
    _assert(a_open["unpriced"] is False,
            f"[A] priced cell marked unpriced: {a_open}")

    b_anthr = bytb["template_b/anthropic/fake_model"]
    _assert(b_anthr["unpriced"] is True,
            f"[A] unpriced cell not marked: {b_anthr}")
    _assert(b_anthr["cost_cents"] == 0.0,
            f"[A] unpriced cell shouldn't accumulate cost: {b_anthr}")

    # by_template: aggregated across (backend, model)
    byt = summary["by_template"]
    _assert(set(byt.keys()) == {"template_a", "template_b"},
            f"[A] by_template keys wrong: {sorted(byt)}")
    for k, cell in byt.items():
        for col in ("prompt_template_id", "n_sessions", "tokens_in",
                    "tokens_out", "cost_cents", "unpriced",
                    "n_backend_model_pairs"):
            _assert(col in cell,
                    f"[A] by_template[{k}] missing {col}: {cell}")

    a = byt["template_a"]
    expected_a_cost = 0.033 + 0.264
    _assert(abs(a["cost_cents"] - expected_a_cost) < 1e-9,
            f"[A] template_a cost wrong: {a['cost_cents']} vs {expected_a_cost}")
    _assert(a["tokens_in"] == 600 + 800 and a["tokens_out"] == 400 + 500,
            f"[A] template_a tokens wrong: {a}")
    _assert(a["n_backend_model_pairs"] == 2,
            f"[A] template_a n_pairs wrong: {a}")
    _assert(a["unpriced"] is False,
            f"[A] template_a all-priced marked unpriced: {a}")

    b = byt["template_b"]
    _assert(b["unpriced"] is True,
            f"[A] template_b has unpriced cell but aggregate not marked: {b}")
    print("[smoke-pb7] PART A passed")


# ── PART B: HTTP endpoint ───────────────────────────────────────────


async def _serve(app):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


async def part_b_endpoint(td: pathlib.Path) -> None:
    print("\n[smoke-pb7] PART B — /api/llm_spend endpoint")
    sessions_path = _stage_sessions(td)
    # `dashmod.make_app` expects a data_dir; put the sessions file there.
    data_dir = td
    if sessions_path != data_dir / "sessions.jsonl":
        (data_dir / "sessions.jsonl").write_text(sessions_path.read_text())
    app = dashmod.make_app(data_dir)
    runner, port = await _serve(app)
    base = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(f"{base}/api/llm_spend") as r:
                _assert(r.status == 200, f"[B] status {r.status}")
                body = await r.json()
                for key in ("by_backend_model", "by_template_backend_model",
                            "by_template"):
                    _assert(key in body,
                            f"[B] response missing {key}: {sorted(body)}")
                _assert("template_a" in body["by_template"],
                        f"[B] template_a missing in by_template")
                _assert("accuracy" not in json.dumps(body).lower(),
                        "[B] accuracy in response body")
    finally:
        await runner.cleanup()
    print("[smoke-pb7] PART B passed")


async def amain() -> None:
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cernis_pb7_a_") as td:
        part_a_rollups(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_pb7_b_") as td:
        await part_b_endpoint(pathlib.Path(td))
    print()
    print(f"PHASE-BENCH-7 SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
