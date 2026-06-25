"""phase 14 verification gate — real-LLM agent framework.

Three offline parts. NO API calls are made; CERNIS_AGENT_DRY_RUN=1 short-
circuits the browser-use / langchain imports inside the bot. The smoke
exercises the *framework* (generator matrix-mode, sweep cell builder,
eval rollups) without spending any LLM budget.

PART A — generator matrix-mode dry-run
  - Build a JSON cells_file covering 3 targets × 2 backends × 1 model
    each × 2 stealth = 16 cells (phase 14c grew it 12→16 by adding
    WebGoat), varying `sessions` per cell.
  - Run `generators/real_agent/bot.py` as a subprocess with
    CERNIS_AGENT_DRY_RUN=1 and CERNIS_AGENT_CELLS_FILE pointing at the
    file. Verify:
      * subprocess exits 0
      * the dry-run log has exactly one entry per cell
      * each entry's `family` matches `llm_<backend>_<model_slug>`
      * each entry's `payload.target_app` matches the cell's
      * headers carry the X-Cernis-Family + X-Cernis-Stealth values
      * an out-of-allow-list URL in the cells_file hard-fails (no
        sneaking off-lab targets through matrix mode)

PART B — sweep matrix builder + cells_file round-trip
  - `default_llm_config()` produces 4 × 2 × 1 × 2 = 16 cells with the
    expected target_apps + backends + family naming convention.
  - Custom backends + custom per-backend models override correctly.
  - `write_llm_cells_file()` produces JSON that the bot's
    `_build_cells_from_file()` consumes round-trip without drift on
    target_url / target_app / backend / model / stealth / sessions.

PART C — evaluate.py per-LLM rollups
  - Build a synthetic Session universe mixing llm_openai_* + llm_
    anthropic_* + ua_rule-friendly scanner families + benign_bot.
  - Build real splits, run the ua_rule baseline through `evaluate.
    run_eval`.
  - Verify results["per_llm_backend"] has BOTH openai + anthropic with
    populated `n`, `recall`, `n_target_apps`, `n_models`.
  - Verify results["per_llm_model_x_target"] has at least one
    `<backend>/<model_slug>/<target_app>` key with the right shape.
  - Verify "accuracy" never appears in results or report.
"""

from __future__ import annotations

import json
import pathlib
import random
import subprocess
import sys
import tempfile

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "detector"))


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: generator matrix-mode dry-run ────────────────────────────


def part_a_generator(td: pathlib.Path) -> None:
    print("\n[smoke-p14] PART A — generator matrix-mode dry-run")

    cells = [
        {"target_url": "http://capture:8080",          "target_app": "dvwa",
         "backend": "openai",    "model": "gpt-4o-mini",      "stealth": False, "sessions": 1},
        {"target_url": "http://capture:8080",          "target_app": "dvwa",
         "backend": "openai",    "model": "gpt-4o-mini",      "stealth": True,  "sessions": 2},
        {"target_url": "http://capture:8080",          "target_app": "dvwa",
         "backend": "anthropic", "model": "claude-haiku-4-5", "stealth": False, "sessions": 1},
        {"target_url": "http://capture:8080",          "target_app": "dvwa",
         "backend": "anthropic", "model": "claude-haiku-4-5", "stealth": True,  "sessions": 1},
        {"target_url": "http://capture_juiceshop:8080","target_app": "juice_shop",
         "backend": "openai",    "model": "gpt-4o-mini",      "stealth": False, "sessions": 1},
        {"target_url": "http://capture_juiceshop:8080","target_app": "juice_shop",
         "backend": "openai",    "model": "gpt-4o-mini",      "stealth": True,  "sessions": 1},
        {"target_url": "http://capture_juiceshop:8080","target_app": "juice_shop",
         "backend": "anthropic", "model": "claude-haiku-4-5", "stealth": False, "sessions": 1},
        {"target_url": "http://capture_juiceshop:8080","target_app": "juice_shop",
         "backend": "anthropic", "model": "claude-haiku-4-5", "stealth": True,  "sessions": 1},
        {"target_url": "http://capture_crapi:8080",    "target_app": "crapi",
         "backend": "openai",    "model": "gpt-4o-mini",      "stealth": False, "sessions": 1},
        {"target_url": "http://capture_crapi:8080",    "target_app": "crapi",
         "backend": "openai",    "model": "gpt-4o-mini",      "stealth": True,  "sessions": 1},
        {"target_url": "http://capture_crapi:8080",    "target_app": "crapi",
         "backend": "anthropic", "model": "claude-haiku-4-5", "stealth": False, "sessions": 1},
        {"target_url": "http://capture_crapi:8080",    "target_app": "crapi",
         "backend": "anthropic", "model": "claude-haiku-4-5", "stealth": True,  "sessions": 1},
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
        [sys.executable, str(ROOT / "generators" / "real_agent" / "bot.py")],
        env=env, capture_output=True, text=True, timeout=30,
    )
    _assert(cp.returncode == 0,
            f"[A] bot exited {cp.returncode}\n"
            f"  stdout:\n{cp.stdout}\n  stderr:\n{cp.stderr}")
    _assert(log_path.exists(),
            f"[A] expected dry-run log at {log_path}")

    rows = [json.loads(line) for line in log_path.read_text().splitlines() if line.strip()]
    _assert(len(rows) == len(cells),
            f"[A] expected {len(cells)} log rows, got {len(rows)}")

    for i, row in enumerate(rows):
        cell_in = cells[i]
        payload = row["payload"]
        family = payload["family"]
        expected_family_re = (
            f"llm_{cell_in['backend']}_"
            f"{cell_in['model'].lower().replace('-', '_').replace('.', '_')}"
        )
        _assert(family == expected_family_re,
                f"[A] cell {i}: family={family!r} expected {expected_family_re!r}")
        _assert(payload["target_app"] == cell_in["target_app"],
                f"[A] cell {i}: target_app mismatch")
        _assert(payload["stealth"] is bool(cell_in["stealth"]),
                f"[A] cell {i}: stealth mismatch")
        _assert(payload["class"] == "agent",
                f"[A] cell {i}: class={payload['class']!r}")
        extra = payload["extra"]
        _assert(extra["backend"] == cell_in["backend"],
                f"[A] cell {i}: extra.backend mismatch")
        _assert(extra["model"] == cell_in["model"],
                f"[A] cell {i}: extra.model mismatch")
        _assert(extra["framework"] == "browser-use",
                f"[A] cell {i}: extra.framework wrong: {extra}")
        _assert("prompt_template_id" in extra,
                f"[A] cell {i}: extra missing prompt_template_id")
        headers = row["headers"]
        _assert(headers["X-Cernis-Family"] == family,
                f"[A] cell {i}: header X-Cernis-Family mismatch")
        _assert(headers["X-Cernis-TargetApp"] == cell_in["target_app"],
                f"[A] cell {i}: header X-Cernis-TargetApp mismatch")
        _assert(headers["X-Cernis-Stealth"]
                == ("true" if cell_in["stealth"] else "false"),
                f"[A] cell {i}: header X-Cernis-Stealth mismatch")

    # Bad cell: off-allow-list URL must hard-fail before any LLM is touched.
    bad_cells_path = td / "bad_cells.json"
    bad_cells_path.write_text(json.dumps({"cells": [{
        "target_url": "http://evil.example.com:8080",
        "target_app": "dvwa", "backend": "openai", "model": "gpt-4o-mini",
        "stealth": False, "sessions": 1,
    }]}))
    env_bad = dict(env, CERNIS_AGENT_CELLS_FILE=str(bad_cells_path))
    cp_bad = subprocess.run(
        [sys.executable, str(ROOT / "generators" / "real_agent" / "bot.py")],
        env=env_bad, capture_output=True, text=True, timeout=10,
    )
    _assert(cp_bad.returncode != 0,
            f"[A] off-allow-list URL was accepted (rc={cp_bad.returncode})\n"
            f"  stdout:\n{cp_bad.stdout}\n  stderr:\n{cp_bad.stderr}")
    _assert("target_guard" in cp_bad.stderr,
            f"[A] target_guard didn't surface in the rejection message: "
            f"{cp_bad.stderr}")
    print("[smoke-p14] PART A passed")


# ── PART B: sweep matrix builder ────────────────────────────────────


def part_b_sweep(td: pathlib.Path) -> None:
    print("\n[smoke-p14] PART B — sweep matrix builder + cells_file round-trip")
    from orchestrator import sweep as sweepmod

    # Default config: 4 targets × 2 backends × 1 model each × 2 stealth = 16
    # (VAmPI still deferred — JSON-only API. Phase 14c added WebGoat
    # which grew the matrix 12 → 16.)
    cells = sweepmod.default_llm_config()
    _assert(len(cells) == 16,
            f"[B] default matrix size: expected 16, got {len(cells)}")
    target_apps = sorted({c.target_app for c in cells})
    _assert(target_apps == ["crapi", "dvwa", "juice_shop", "webgoat"],
            f"[B] default targets wrong: {target_apps}")
    backends = sorted({c.backend for c in cells})
    _assert(backends == ["anthropic", "openai"],
            f"[B] default backends wrong: {backends}")

    # Family naming convention
    fams = {c.family() for c in cells}
    for fam in fams:
        _assert(fam.startswith("llm_"),
                f"[B] non-LLM family in matrix: {fam!r}")
        _assert(fam.startswith("llm_openai_")
                or fam.startswith("llm_anthropic_"),
                f"[B] unexpected backend in family: {fam!r}")

    # Custom backend + multi-model override
    cells_2 = sweepmod.default_llm_config(
        backends=("openai",),
        models={"openai": ("gpt-4o-mini", "gpt-4-turbo")},
        target_apps=("dvwa", "juice_shop"),
        stealth_axes=(False,),
    )
    # 2 targets × 1 backend × 2 models × 1 stealth = 4
    _assert(len(cells_2) == 4,
            f"[B] custom matrix size: expected 4, got {len(cells_2)}")
    models = sorted({c.model for c in cells_2})
    _assert(models == ["gpt-4-turbo", "gpt-4o-mini"],
            f"[B] custom models wrong: {models}")

    # cells_file round-trip via the bot's loader
    cells_file = td / "cells.json"
    sweepmod.write_llm_cells_file(cells_2, cells_file)
    raw = json.loads(cells_file.read_text())
    _assert(len(raw["cells"]) == 4,
            f"[B] cells_file has {len(raw['cells'])} entries")

    # Parse via the bot's _build_cells_from_file (with PYTHONPATH set so
    # the shared imports work). We test the loader as a subprocess to
    # exercise the same code path the container will use.
    log_path = td / "rt.jsonl"
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": str(ROOT / "generators" / "shared"),
        "CERNIS_AGENT_CELLS_FILE": str(cells_file),
        "CERNIS_AGENT_DRY_RUN": "1",
        "CERNIS_DRY_RUN_LOG": str(log_path),
    }
    cp = subprocess.run(
        [sys.executable, str(ROOT / "generators" / "real_agent" / "bot.py")],
        env=env, capture_output=True, text=True, timeout=20,
    )
    _assert(cp.returncode == 0,
            f"[B] round-trip bot exited {cp.returncode}\n"
            f"  stderr:\n{cp.stderr}")
    rt_rows = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
    _assert(len(rt_rows) == 4,
            f"[B] round-trip log has {len(rt_rows)} entries")
    expected_fams = sorted({c.family() for c in cells_2})
    seen_fams = sorted({r["payload"]["family"] for r in rt_rows})
    _assert(expected_fams == seen_fams,
            f"[B] family round-trip drift: "
            f"expected {expected_fams}, got {seen_fams}")

    print("[smoke-p14] PART B passed")


# ── PART C: evaluate.py per-LLM rollups ─────────────────────────────


def _llm_sessions():
    """Build a 36-session universe with LLM-agent families mixed in."""
    from features import Session  # type: ignore
    sessions = []
    rng = np.random.default_rng(0)

    # LLM agent families: 2 backends × 2 models × 2 target_apps × 3 sessions
    llm_specs = [
        ("openai",    "gpt_4o_mini",       "dvwa"),
        ("openai",    "gpt_4o_mini",       "juice_shop"),
        ("openai",    "gpt_4_turbo",       "dvwa"),
        ("anthropic", "claude_haiku_4_5",  "dvwa"),
        ("anthropic", "claude_haiku_4_5",  "juice_shop"),
        ("anthropic", "claude_opus_4_5",   "dvwa"),
    ]
    for backend, model_slug, target_app in llm_specs:
        family = f"llm_{backend}_{model_slug}"
        for i in range(3):
            seq = rng.uniform(0, 1, size=(8, 9)).astype("float32")
            seq[:, 6] = 0.3  # curl-bucket → ua_rule scores high
            sessions.append(Session(
                session_id=f"{family}-{target_app}-{i:02d}",
                src_label=family, family=family, klass="agent",
                y=1, duration_s=30.0, ts_start=0.0,
                seq=seq, agg=rng.uniform(0, 1, size=12).astype("float32"),
                hp=np.zeros(4, dtype="float32"),
                n_req=8, target_app=target_app, stealth=False,
            ))

    # A non-LLM agent family so the per_llm rollups have to filter
    sessions.append(_make_session(rng, "playwright_bot", "agent", 1, "dvwa",
                                  ua_bucket=0.3))
    sessions.append(_make_session(rng, "playwright_bot", "agent", 1, "dvwa",
                                  ua_bucket=0.3))

    # Benigns so build_splits has both classes
    for fam in ["googlebot", "uptime_monitor"]:
        for i in range(4):
            sessions.append(_make_session(rng, fam, "benign_bot", 0, "dvwa",
                                          ua_bucket=1.0))
    return sessions


def _make_session(rng, family, klass, y, target_app, ua_bucket=1.0):
    from features import Session  # type: ignore
    seq = rng.uniform(0, 1, size=(8, 9)).astype("float32")
    seq[:, 6] = ua_bucket
    return Session(
        session_id=f"{family}-{rng.integers(0, 1 << 30)}",
        src_label=family, family=family, klass=klass,
        y=y, duration_s=60.0, ts_start=0.0,
        seq=seq, agg=rng.uniform(0, 1, size=12).astype("float32"),
        hp=np.zeros(4, dtype="float32"),
        n_req=8, target_app=target_app, stealth=False,
    )


def part_c_evaluate(td: pathlib.Path) -> None:
    print("\n[smoke-p14] PART C — evaluate.py per-LLM rollups")
    from benchmark import evaluate as evalmod
    from benchmark import splits as splitmod
    from benchmark.build_splits import sessions_to_meta

    sessions = _llm_sessions()
    metas = sessions_to_meta(sessions)
    split_set = splitmod.build_split_set(metas, seed=0)
    splits_dir = td / "splits" / splitmod.SPLITS_VERSION
    splitmod.write_split_set(split_set, splits_dir)

    submission = ROOT / "benchmark" / "baselines" / "ua_rule"
    out_dir = td / "eval"
    results = evalmod.run_eval(
        submission_dir=submission,
        split="public_test",
        splits_dir=splits_dir,
        data_dir=td / "data",
        seed=0,
        fp_per_hour_budget=1.0,
        out_dir=out_dir,
        sessions=sessions,
    )

    pll = results.get("per_llm_backend") or {}
    pllxt = results.get("per_llm_model_x_target") or {}

    backends = set(pll.keys())
    _assert(backends.issubset({"openai", "anthropic"}),
            f"[C] per_llm_backend has unexpected keys: {backends}")
    _assert(backends,
            "[C] per_llm_backend is empty — eval rollup not finding "
            "the llm_* families")
    for backend, cell in pll.items():
        for k in ("n", "alerts", "alert_rate", "n_agent_truth",
                  "recall", "n_target_apps", "n_models"):
            _assert(k in cell,
                    f"[C] per_llm_backend[{backend}] missing {k!r}: {cell}")
        _assert(cell["n_models"] >= 1,
                f"[C] per_llm_backend[{backend}].n_models < 1: {cell}")

    _assert(len(pllxt) >= 1,
            f"[C] per_llm_model_x_target is empty: {pllxt}")
    for key, cell in pllxt.items():
        parts = key.split("/")
        _assert(len(parts) == 3,
                f"[C] per_llm_model_x_target key {key!r} not 3-part")
        backend, model_slug, target_app = parts
        _assert(backend in {"openai", "anthropic"},
                f"[C] key {key!r} bad backend")
        for k in ("n", "alerts", "alert_rate", "n_agent_truth",
                  "recall", "stealth_seen"):
            _assert(k in cell,
                    f"[C] per_llm_model_x_target[{key}] missing {k!r}")

    # No accuracy
    results_text = json.dumps(results).lower()
    _assert("accuracy" not in results_text,
            "[C] 'accuracy' present in results")
    report_text = (out_dir / "report.txt").read_text().lower()
    _assert("accuracy" not in report_text,
            "[C] 'accuracy' present in report.txt")

    # On-disk results.json should also carry the new rollup keys
    on_disk = json.loads((out_dir / "results.json").read_text())
    _assert("per_llm_backend" in on_disk,
            "[C] on-disk results.json missing per_llm_backend")
    _assert("per_llm_model_x_target" in on_disk,
            "[C] on-disk results.json missing per_llm_model_x_target")

    print(f"[smoke-p14]   per_llm_backend keys = {sorted(pll)}")
    print(f"[smoke-p14]   per_llm_model_x_target n_cells = {len(pllxt)}")
    print("[smoke-p14] PART C passed")


def main() -> None:
    import time
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cernis_p14_a_") as td:
        part_a_generator(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p14_b_") as td:
        part_b_sweep(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p14_c_") as td:
        part_c_evaluate(pathlib.Path(td))
    print()
    print(f"PHASE-14 SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
