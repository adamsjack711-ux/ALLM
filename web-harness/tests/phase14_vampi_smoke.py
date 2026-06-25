"""phase 14-vampi verification gate — HTTP-only LLM client.

Four offline parts. No LLM, no docker, no API spend. The HTTP bot's
DRY_RUN path validates the matrix-cell flow + target_guard + payload
shape without ever calling out.

PART A — generator matrix-mode dry-run via subprocess
  - 4-cell cells_file (2 backends × 1 model × 2 sessions counts)
  - subprocess bot exits 0 with the dry-run log carrying 4 entries
  - each entry's family matches `llm_<backend>_<model_slug>`
  - each entry's extra.framework=="langchain-httpx" (HTTP-flavor
    distinction from phase 14 browser-use)
  - each entry's target_app=="vampi"
  - off-allow-list URL gets rejected by target_guard before any LLM
    code is touched (same guarantee as phase 14)

PART B — sweep helpers
  - sweep.default_llm_http_config() returns 2 cells (1 target × 2
    backends × 1 model) by default
  - write_llm_http_cells_file round-trip equals the bot's loader
  - cells produced have no `stealth` key (HTTP has no stealth axis)

PART C — parse_action robustness
  - ACTION GET /users/v1 → ('action', method=GET, path=/users/v1, body=None)
  - ACTION POST /users/v1/login {"u":"x","p":"y"} → JSON-parsed body
  - ACTION POST /users/v1 not-json-body → raw string body
  - DONE: explored the API → ('done', summary=...)
  - garbage text → ('confused', raw=...)
  - case-insensitive on the ACTION/DONE prefix

PART D — _build_cells_from_file edge cases
  - missing required field (e.g. no `backend`) → SystemExit
  - unknown backend → SystemExit
  - default model when omitted picks _DEFAULT_MODELS[backend]
  - explicit task overrides; default task uses _DEFAULT_TASKS["vampi"]
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
sys.path.insert(0, str(ROOT / "generators" / "shared"))
sys.path.insert(0, str(ROOT / "generators" / "real_agent_http"))

import bot as httpbot  # noqa: E402
from orchestrator import sweep as sweepmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: dry-run via subprocess ───────────────────────────────────


def part_a_dry_run(td: pathlib.Path) -> None:
    print("\n[smoke-p14vampi] PART A — dry-run via subprocess")
    cells = [
        {"target_url": "http://capture_vampi:8080", "target_app": "vampi",
         "backend": "openai", "model": "gpt-4o-mini", "sessions": 1},
        {"target_url": "http://capture_vampi:8080", "target_app": "vampi",
         "backend": "openai", "model": "gpt-4o-mini", "sessions": 2},
        {"target_url": "http://capture_vampi:8080", "target_app": "vampi",
         "backend": "anthropic", "model": "claude-haiku-4-5", "sessions": 1},
        {"target_url": "http://capture_vampi:8080", "target_app": "vampi",
         "backend": "anthropic", "model": "claude-haiku-4-5", "sessions": 1},
    ]
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
    cp = subprocess.run(
        [sys.executable, str(ROOT / "generators" / "real_agent_http" / "bot.py")],
        env=env, capture_output=True, text=True, timeout=30,
    )
    _assert(cp.returncode == 0,
            f"[A] bot exited {cp.returncode}\n"
            f"stdout:\n{cp.stdout}\nstderr:\n{cp.stderr}")
    rows = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
    _assert(len(rows) == 4,
            f"[A] expected 4 dry-run rows, got {len(rows)}")

    for i, row in enumerate(rows):
        cell_in = cells[i]
        payload = row["payload"]
        expected_family = (
            f"llm_{cell_in['backend']}_"
            f"{cell_in['model'].lower().replace('-', '_').replace('.', '_')}"
        )
        _assert(payload["family"] == expected_family,
                f"[A] cell {i}: family={payload['family']!r} expected "
                f"{expected_family!r}")
        _assert(payload["target_app"] == "vampi",
                f"[A] cell {i}: target_app != vampi")
        _assert(payload["class"] == "agent",
                f"[A] cell {i}: class wrong")
        extra = payload["extra"]
        _assert(extra["framework"] == "langchain-httpx",
                f"[A] cell {i}: extra.framework wrong: {extra['framework']!r}")
        _assert(extra["backend"] == cell_in["backend"],
                f"[A] cell {i}: extra.backend mismatch")
        _assert("max_steps" in extra,
                f"[A] cell {i}: extra missing max_steps")
        _assert("http_timeout_s" in extra,
                f"[A] cell {i}: extra missing http_timeout_s")

    # Off-allow-list URL hard-fails
    bad_cells = td / "bad.json"
    bad_cells.write_text(json.dumps({"cells": [{
        "target_url": "http://evil.example.com:8080",
        "target_app": "vampi", "backend": "openai", "model": "gpt-4o-mini",
        "sessions": 1,
    }]}))
    cp_bad = subprocess.run(
        [sys.executable, str(ROOT / "generators" / "real_agent_http" / "bot.py")],
        env={**env, "CERNIS_AGENT_CELLS_FILE": str(bad_cells)},
        capture_output=True, text=True, timeout=10,
    )
    _assert(cp_bad.returncode != 0,
            f"[A] off-allow-list URL accepted (rc={cp_bad.returncode})")
    _assert("target_guard" in cp_bad.stderr,
            f"[A] target_guard didn't surface: {cp_bad.stderr}")
    print("[smoke-p14vampi] PART A passed")


# ── PART B: sweep helpers ───────────────────────────────────────────


def part_b_sweep(td: pathlib.Path) -> None:
    print("\n[smoke-p14vampi] PART B — sweep matrix builder")
    cells = sweepmod.default_llm_http_config()
    _assert(len(cells) == 2,
            f"[B] default HTTP matrix expected 2 cells (1 target × 2 "
            f"backends × 1 model), got {len(cells)}")
    target_apps = sorted({c.target_app for c in cells})
    _assert(target_apps == ["vampi"],
            f"[B] default HTTP targets wrong: {target_apps}")
    backends = sorted({c.backend for c in cells})
    _assert(backends == ["anthropic", "openai"],
            f"[B] default HTTP backends wrong: {backends}")

    for c in cells:
        entry = c.to_cellsfile_entry()
        _assert("stealth" not in entry,
                f"[B] HTTP entry should not carry stealth: {entry}")
        _assert(entry["target_url"] == "http://capture_vampi:8080",
                f"[B] HTTP entry target_url wrong: {entry}")

    # round-trip through the bot's loader
    cells_file = td / "http_cells.json"
    sweepmod.write_llm_http_cells_file(cells, cells_file)
    loaded = httpbot._build_cells_from_file(cells_file)
    _assert(len(loaded) == len(cells),
            f"[B] round-trip length mismatch: {len(loaded)} vs {len(cells)}")
    for orig, got in zip(cells, loaded):
        _assert(orig.target_url == got.target_url,
                f"[B] round-trip target_url drift")
        _assert(orig.backend == got.backend and orig.model == got.model,
                f"[B] round-trip backend/model drift")
    print("[smoke-p14vampi] PART B passed")


# ── PART C: parse_action ────────────────────────────────────────────


def part_c_parser() -> None:
    print("\n[smoke-p14vampi] PART C — parse_action")
    cases = [
        ("ACTION: GET /users/v1",
         "action", {"method": "GET", "path": "/users/v1", "body": None}),
        ('ACTION: POST /users/v1/login {"u":"x","p":"y"}',
         "action", {"method": "POST", "path": "/users/v1/login",
                    "body": {"u": "x", "p": "y"}}),
        ("ACTION: POST /users/v1 not-json-body",
         "action", {"method": "POST", "path": "/users/v1",
                    "body": "not-json-body"}),
        ("action: get /books/v1",  # case-insensitive
         "action", {"method": "GET", "path": "/books/v1", "body": None}),
        ("DONE: explored the API",
         "done", {"summary": "explored the API"}),
        ("garbage text with no action", "confused", None),
    ]
    for reply, kind, expected in cases:
        got_kind, got = httpbot.parse_action(reply)
        _assert(got_kind == kind,
                f"[C] parse_action({reply!r}) kind={got_kind!r} expected {kind!r}")
        if expected is not None:
            for k, v in expected.items():
                _assert(got.get(k) == v,
                        f"[C] parse_action({reply!r}).{k}={got.get(k)!r} "
                        f"expected {v!r}")
    print("[smoke-p14vampi] PART C passed")


# ── PART D: _build_cells_from_file edge cases ──────────────────────


def part_d_loader_edges(td: pathlib.Path) -> None:
    print("\n[smoke-p14vampi] PART D — _build_cells_from_file edge cases")
    # Missing required field
    bad = td / "bad_no_backend.json"
    bad.write_text(json.dumps({"cells": [{
        "target_url": "http://capture_vampi:8080", "target_app": "vampi",
        "model": "gpt-4o-mini", "sessions": 1,
    }]}))
    try:
        httpbot._build_cells_from_file(bad)
        raise AssertionError("[D] missing backend should SystemExit")
    except SystemExit:
        pass

    # Unknown backend
    bad2 = td / "bad_backend.json"
    bad2.write_text(json.dumps({"cells": [{
        "target_url": "http://capture_vampi:8080", "target_app": "vampi",
        "backend": "google", "model": "gemini-pro", "sessions": 1,
    }]}))
    try:
        httpbot._build_cells_from_file(bad2)
        raise AssertionError("[D] unknown backend should SystemExit")
    except SystemExit:
        pass

    # Default model picked when omitted
    ok = td / "default_model.json"
    ok.write_text(json.dumps({"cells": [{
        "target_url": "http://capture_vampi:8080", "target_app": "vampi",
        "backend": "anthropic", "sessions": 1,
    }]}))
    cells = httpbot._build_cells_from_file(ok)
    _assert(cells[0].model == "claude-haiku-4-5",
            f"[D] default model wrong: {cells[0].model}")

    # Explicit task overrides; default task uses _DEFAULT_TASKS["vampi"]
    custom = td / "custom_task.json"
    custom.write_text(json.dumps({"cells": [{
        "target_url": "http://capture_vampi:8080", "target_app": "vampi",
        "backend": "openai", "sessions": 1,
        "task": "Custom mission for {target}",
    }]}))
    custom_cells = httpbot._build_cells_from_file(custom)
    _assert("Custom mission" in custom_cells[0].task,
            f"[D] custom task not used: {custom_cells[0].task!r}")
    _assert("{target}" not in custom_cells[0].task,
            f"[D] {{target}} not substituted: {custom_cells[0].task!r}")

    default_t = td / "default_task.json"
    default_t.write_text(json.dumps({"cells": [{
        "target_url": "http://capture_vampi:8080", "target_app": "vampi",
        "backend": "openai", "sessions": 1,
    }]}))
    default_cells = httpbot._build_cells_from_file(default_t)
    _assert("VAmPI" in default_cells[0].task,
            f"[D] default VAmPI task not used: {default_cells[0].task!r}")
    print("[smoke-p14vampi] PART D passed")


def main() -> None:
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cernis_p14vampi_a_") as td:
        part_a_dry_run(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p14vampi_b_") as td:
        part_b_sweep(pathlib.Path(td))
    part_c_parser()
    with tempfile.TemporaryDirectory(prefix="cernis_p14vampi_d_") as td:
        part_d_loader_edges(pathlib.Path(td))
    print()
    print(f"PHASE-14-VAMPI SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
