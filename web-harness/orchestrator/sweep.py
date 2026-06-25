"""Orchestrator sweep: {target} × {family} × {security_level} × {stealth}.

The spec asks for "sweep {target} x {family} x {security_level} x {stealth},
with benign traffic running continuously and interleaved." Phase 5's
run_loop.py runs one cycle of a fixed three-generator interleave; phase
10 sweep runs the full combinatorial cross-product over the four axes
that phases 6–9 added to the manifest.

Layout:
  - `default_config()` returns a `SweepConfig` with sensible axis values
    (DVWA + Juice Shop + VAmPI; the 4 agent families; security levels
    low/medium/high; stealth false/true). Skips combinations that don't
    make sense (e.g. selenium against vampi — no DOM matters).
  - `build_sweep_plan(config)` is pure Python and lists the cells to
    execute. Testable without docker.
  - `execute_sweep(plan)` drives `docker compose run --rm` per cell.
    Needs docker; runs out-of-process on the operator's machine.
  - `build_sweep_report(data_dir, plan)` reads the resulting JSONL,
    invokes train + eval + heldout as subprocesses, joins the sweep
    plan to the manifest rows for a per-cell census, and writes one
    `data/reports/sweep_<ts>.json` summary. Pure-Python, testable on
    synth data.

The benign families (googlebot / uptime / rss / unfurl / ci) run
continuously *underneath* the sweep — kicked off once at the start
and left running. The orchestrator does not gate cell execution on
benign service health.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import json
import pathlib
import subprocess
import sys
import time
from typing import Iterable

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
REPORTS = DATA / "reports"


# ----------------------------------------------------------------------
# Sweep plan model
# ----------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class SweepCell:
    target_app: str        # dvwa / juice_shop / webgoat / vampi
    family: str            # playwright_bot / sqlmap / selenium_bot / puppeteer_bot
    security_level: str    # low / medium / high / na
    stealth: bool
    sessions: int
    service: str           # docker compose service name to `run --rm`


@dataclasses.dataclass
class SweepConfig:
    cells: list[SweepCell]
    benign_families: list[str]
    benign_sessions_per_family: int

    def to_summary(self) -> dict:
        return {
            "n_cells": len(self.cells),
            "axes": {
                "target_app": sorted({c.target_app for c in self.cells}),
                "family": sorted({c.family for c in self.cells}),
                "security_level": sorted({c.security_level for c in self.cells}),
                "stealth": sorted({c.stealth for c in self.cells}),
            },
            "benign_families": self.benign_families,
            "benign_sessions_per_family": self.benign_sessions_per_family,
        }


# Maps target_app → {CERNIS_TARGET URL, supported families}. Selenium and
# Puppeteer drive browsers, which only makes sense against HTML targets;
# VAmPI is JSON-only so we skip the browser families there. sqlmap,
# playwright_bot, and the phase 11 scanner family run against everything
# (raw_httpx / ffuf / nikto / scrapy are non-browser and target-agnostic).
_TARGETS: dict[str, dict] = {
    "dvwa": {
        "url": "http://capture:8080",
        "families": {"playwright_bot", "sqlmap", "selenium_bot",
                     "puppeteer_bot", "raw_httpx", "ffuf", "scrapy", "nikto"},
    },
    "juice_shop": {
        "url": "http://capture_juiceshop:8080",
        "families": {"playwright_bot", "sqlmap", "selenium_bot",
                     "puppeteer_bot", "raw_httpx", "ffuf", "scrapy", "nikto"},
    },
    # phase 14c: WebGoat lands in the target registry. The Java-app
    # lesson UI is fully HTML so every browser-driven family applies;
    # the OWASP Top-10 lessons cover SQLi / XSS / IDOR / etc. so the
    # non-browser scanners (sqlmap / ffuf / nikto / scrapy / raw_httpx)
    # also have real surface. capture_webgoat lives under the existing
    # `multitarget` compose profile, alongside capture_juiceshop +
    # capture_vampi.
    "webgoat": {
        "url": "http://capture_webgoat:8080",
        "families": {"playwright_bot", "sqlmap", "selenium_bot",
                     "puppeteer_bot", "raw_httpx", "ffuf", "scrapy", "nikto"},
    },
    "vampi": {
        "url": "http://capture_vampi:8080",
        "families": {"sqlmap", "raw_httpx", "ffuf"},
    },
    # phase 12: crAPI has a React SPA frontend + a JSON API surface, so
    # browser-driven families ARE useful (they exercise the SPA + the
    # XHR-to-API path), and the non-browser scanners hit the API directly.
    # No DVWA-style server-rendered SQLi forms — sqlmap mostly probes
    # query params on the API endpoints.
    "crapi": {
        "url": "http://capture_crapi:8080",
        "families": {"playwright_bot", "sqlmap", "selenium_bot",
                     "puppeteer_bot", "raw_httpx", "ffuf", "scrapy", "nikto"},
    },
}

_FAMILY_SERVICES: dict[tuple[str, bool], str] = {
    # phase 7 — browser bots + sqlmap (stealth twins via phase 9)
    ("playwright_bot", False): "playwright_bot",
    ("playwright_bot", True):  "playwright_bot_stealth",
    ("sqlmap",         False): "sqlmap_bot",
    ("sqlmap",         True):  "sqlmap_stealth",
    ("selenium_bot",   False): "selenium_bot",
    ("selenium_bot",   True):  "selenium_bot_stealth",
    ("puppeteer_bot",  False): "puppeteer_bot",
    ("puppeteer_bot",  True):  "puppeteer_bot_stealth",
    # phase 11 — scanner family (single image per family, CERNIS_STEALTH
    # picks the mode at run time, so no separate stealth service)
    ("raw_httpx",      False): "raw_httpx_bot",
    ("raw_httpx",      True):  "raw_httpx_bot",
    ("ffuf",           False): "ffuf_bot",
    ("ffuf",           True):  "ffuf_bot",
    ("scrapy",         False): "scrapy_bot",
    ("scrapy",         True):  "scrapy_bot",
    ("nikto",          False): "nikto_bot",
    ("nikto",          True):  "nikto_bot",
}

_DEFAULT_BENIGN = [
    "benign_googlebot", "benign_uptime", "benign_rss",
    "benign_unfurl", "benign_ci",
]


# ----------------------------------------------------------------------
# Phase 14: LLM-agent cell matrix
# ----------------------------------------------------------------------
#
# Real-LLM cells are deliberately segregated from the deterministic
# scanner / browser-bot families above. The deterministic families run
# under the default `docker compose --profile generators up`; the LLM
# matrix only runs when `--include-llm` is explicitly passed AND the
# operator has set OPENAI_API_KEY / ANTHROPIC_API_KEY. The framework
# always supports `--llm-dry-run` for enumeration-without-API-spend.

_DEFAULT_LLM_BACKENDS = ("openai", "anthropic")
_DEFAULT_LLM_MODELS = {
    "openai": ("gpt-4o-mini",),
    "anthropic": ("claude-haiku-4-5",),
}

# Browser-driven LLM cells against HTML targets present in `_TARGETS`.
# VAmPI is JSON-only — excluded because a browser-use agent there adds
# no detection signal beyond what sqlmap / raw_httpx already produce.
# Phase 14c adds WebGoat to this list now that it's registered in
# `_TARGETS`; the default matrix grew 12→16 cells.
_LLM_TARGETS = ("dvwa", "juice_shop", "webgoat", "crapi")


@dataclasses.dataclass(frozen=True)
class LlmSweepCell:
    target_app: str
    target_url: str
    backend: str
    model: str
    stealth: bool
    sessions: int

    def family(self) -> str:
        """Mirror the family naming convention from
        generators/real_agent/bot.py::_family_name so the sweep can
        report on what the capture proxy will see."""
        import re as _re
        slug = lambda s: _re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")
        return f"llm_{slug(self.backend)}_{slug(self.model)}"

    def to_cellsfile_entry(self) -> dict:
        """Shape the bot's `_build_cells_from_file` expects."""
        return {
            "target_url": self.target_url,
            "target_app": self.target_app,
            "backend": self.backend,
            "model": self.model,
            "stealth": self.stealth,
            "sessions": self.sessions,
        }


def default_llm_config(
    *,
    backends: Iterable[str] = _DEFAULT_LLM_BACKENDS,
    models: dict[str, Iterable[str]] | None = None,
    target_apps: Iterable[str] = _LLM_TARGETS,
    stealth_axes: tuple[bool, ...] = (False, True),
    sessions_per_cell: int = 2,
) -> list[LlmSweepCell]:
    """Build the LLM-agent cell matrix. Default: 4 targets × 2 backends
    × 1 model each × 2 stealth = 16 cells. Caller can override any
    axis; passing `models={"openai": ("gpt-4o-mini", "gpt-4-turbo")}`
    multiplies the matrix per backend."""
    models = dict(models or _DEFAULT_LLM_MODELS)
    cells: list[LlmSweepCell] = []
    for target_app in target_apps:
        if target_app not in _TARGETS:
            raise ValueError(
                f"unknown target_app {target_app!r}; expected one of "
                f"{sorted(_TARGETS)}"
            )
        url = _TARGETS[target_app]["url"]
        for backend in backends:
            for model in models.get(backend, ()):
                for stealth in stealth_axes:
                    cells.append(LlmSweepCell(
                        target_app=target_app, target_url=url,
                        backend=backend, model=model,
                        stealth=stealth, sessions=sessions_per_cell,
                    ))
    return cells


def cost_projection_for_cells(cells: Iterable[LlmSweepCell]) -> dict:
    """Phase 14b: pre-run cost projection across the LLM matrix.

    Sums DEFAULT_TOKENS_PER_SESSION × per-cell session count × public
    list pricing per (backend, model). Returns the per-cell breakdown
    plus total + an `unpriced_cells` list so the operator sees which
    (backend, model) pairs weren't in the pricing table.

    The projection is deliberately conservative — meant as an upper-
    bound sanity check before paying budget, NOT an accountant's
    invoice. Actual per-session cost is captured at provenance time
    and aggregated by the dashboard.
    """
    # Lazy import: the orchestrator runs outside the generator
    # container, so the pricing module lives under a sibling path.
    pricing_path = ROOT / "generators" / "real_agent"
    if str(pricing_path) not in sys.path:
        sys.path.insert(0, str(pricing_path))
    import pricing as pricingmod  # type: ignore

    per_cell: list[dict] = []
    total_cents = 0.0
    unpriced: list[str] = []
    for c in cells:
        per_session = pricingmod.estimate_session_projection(c.backend, c.model)
        cell_cents = (per_session * c.sessions) if per_session is not None else None
        per_cell.append({
            "target_app": c.target_app,
            "backend": c.backend,
            "model": c.model,
            "stealth": c.stealth,
            "sessions": c.sessions,
            "estimated_cost_cents_per_session": per_session,
            "estimated_cost_cents_total": cell_cents,
        })
        if cell_cents is None:
            unpriced.append(f"{c.backend}/{c.model}")
        else:
            total_cents += cell_cents
    return {
        "default_tokens_per_session": pricingmod.DEFAULT_TOKENS_PER_SESSION,
        "per_cell": per_cell,
        "total_cents": total_cents,
        "total_formatted": pricingmod.format_cents(total_cents),
        "unpriced_cells": sorted(set(unpriced)),
    }


def write_llm_cells_file(
    cells: Iterable[LlmSweepCell], path: pathlib.Path,
) -> None:
    """Emit the JSON shape that `real_agent/bot.py` consumes via
    CERNIS_AGENT_CELLS_FILE. The bot will validate each entry through
    target_guard at startup."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(
        {"cells": [c.to_cellsfile_entry() for c in cells]},
        indent=2,
    ))


def execute_llm_sweep(
    cells: list[LlmSweepCell],
    *,
    dry_run: bool = False,
    cells_file: pathlib.Path | None = None,
) -> dict:
    """Run the LLM matrix as a SINGLE `real_agent` invocation that
    reads CERNIS_AGENT_CELLS_FILE. Returns a summary dict.

    `dry_run=True` sets CERNIS_AGENT_DRY_RUN=1 inside the container,
    so target_guard validation still happens but no LLM is called.
    Use this to verify the cell-file is well-formed against the
    bundled targets before spending API budget.

    `cells_file` defaults to `data/llm_cells.json` so the artifact is
    inspectable post-run.
    """
    cells_file = cells_file or (DATA / "llm_cells.json")
    write_llm_cells_file(cells, cells_file)
    env_flags = [
        "-e", f"CERNIS_AGENT_CELLS_FILE=/data/{cells_file.name}",
        # NB: CERNIS_TARGET is unused in matrix mode, but target_guard
        # still calls get_target() in single-cell mode — set it to one
        # of the allow-listed URLs so a future code path that falls
        # back to single-cell doesn't crash.
        "-e", f"CERNIS_TARGET={cells[0].target_url}" if cells else "",
    ]
    if dry_run:
        env_flags.extend(["-e", "CERNIS_AGENT_DRY_RUN=1"])
    cmd = [
        "docker", "compose", "--profile", "real-agent",
        "run", "--rm",
        *[f for f in env_flags if f],
        "-v", f"{cells_file.parent.absolute()}:/data:ro",
        "real_agent",
    ]
    t0 = time.time()
    rc = _run(cmd)
    return {
        "n_cells": len(cells),
        "cells_file": str(cells_file),
        "dry_run": dry_run,
        "rc": rc,
        "elapsed_s": round(time.time() - t0, 1),
    }


def default_config(
    sessions_per_cell: int = 2,
    benign_sessions: int = 3,
    security_levels: tuple[str, ...] = ("low", "medium"),
) -> SweepConfig:
    """Sensible matrix. Skips selenium / puppeteer against VAmPI
    (no DOM = pointless) and skips sqlmap stealth × high security (sqlmap
    at level=1/risk=1 against DVWA high yields nothing useful anyway).
    """
    cells: list[SweepCell] = []
    for target_app, target_meta in _TARGETS.items():
        for (family, stealth), service in _FAMILY_SERVICES.items():
            if family not in target_meta["families"]:
                continue
            for sec in security_levels:
                # narrow trim: sqlmap stealth × high security yields
                # nothing — skip to save lab time
                if family == "sqlmap" and stealth and sec == "high":
                    continue
                # VAmPI doesn't have DVWA-style security levels
                if target_app == "vampi" and sec != "low":
                    continue
                cells.append(SweepCell(
                    target_app=target_app,
                    family=family,
                    security_level=("na" if target_app == "vampi" else sec),
                    stealth=stealth,
                    sessions=sessions_per_cell,
                    service=service,
                ))
    return SweepConfig(
        cells=cells,
        benign_families=list(_DEFAULT_BENIGN),
        benign_sessions_per_family=benign_sessions,
    )


def build_sweep_plan(config: SweepConfig) -> list[SweepCell]:
    """Return the ordered list of cells to execute. Pure function."""
    return list(config.cells)


# ----------------------------------------------------------------------
# Execution (docker)
# ----------------------------------------------------------------------

def _run(cmd: list[str], cwd: pathlib.Path = ROOT, check: bool = False) -> int:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=cwd)
    if check and cp.returncode != 0:
        raise SystemExit(f"failed rc={cp.returncode}: {cmd}")
    return cp.returncode


def start_benign(config: SweepConfig) -> None:
    """Spin up the benign services once; they run for the duration of
    the sweep. Each writes a few sessions per minute."""
    _run(["docker", "compose", "--profile", "benign", "up", "-d", "--build"],
         check=True)


def _target_url(target_app: str) -> str:
    return _TARGETS[target_app]["url"]


def execute_sweep(plan: Iterable[SweepCell]) -> list[dict]:
    """Run each cell sequentially via `docker compose run --rm`.

    Returns a list of per-cell run results: cell + rc + elapsed.
    Cells continue after a failure (the smoke / eval already tolerates
    partial data).
    """
    results: list[dict] = []
    for cell in plan:
        t0 = time.time()
        cmd = [
            "docker", "compose", "run", "--rm",
            "-e", f"CERNIS_TARGET={_target_url(cell.target_app)}",
            "-e", f"CERNIS_TARGET_APP={cell.target_app}",
            "-e", f"DVWA_SECURITY_LEVEL={cell.security_level}",
            "-e", f"CERNIS_SESSIONS={cell.sessions}",
            "-e", f"CERNIS_STEALTH={'true' if cell.stealth else 'false'}",
            cell.service,
        ]
        rc = _run(cmd)
        results.append({
            "cell": dataclasses.asdict(cell),
            "rc": rc,
            "elapsed_s": round(time.time() - t0, 1),
        })
    return results


# ----------------------------------------------------------------------
# Report assembly (subprocess train + eval + heldout, plus per-cell census)
# ----------------------------------------------------------------------

def _run_analyzer(args: list[str], cwd: pathlib.Path = ROOT) -> None:
    cp = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if cp.returncode != 0:
        raise SystemExit(
            f"[sweep] {' '.join(args[:3])} failed rc={cp.returncode}\n"
            f"stdout:\n{cp.stdout}\nstderr:\n{cp.stderr}"
        )


def _load_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def per_cell_census(
    plan: list[SweepCell], sessions_path: pathlib.Path,
) -> list[dict]:
    """Join the sweep plan to the actual provenance rows in
    sessions.jsonl: for each cell, count how many sessions matched
    its (target_app, family, security_level, stealth) signature.
    """
    rows = _load_jsonl(sessions_path)
    census: list[dict] = []
    for cell in plan:
        matched = [
            r for r in rows
            if r.get("target_app") == cell.target_app
            and r.get("family") == cell.family
            and (r.get("security_level") == cell.security_level
                 or cell.security_level == "na")
            and bool(r.get("stealth")) == cell.stealth
        ]
        census.append({
            **dataclasses.asdict(cell),
            "sessions_planned": cell.sessions,
            "sessions_observed": len(matched),
            "any_provenance_seen": bool(matched),
        })
    return census


def build_sweep_report(
    data_dir: pathlib.Path,
    plan: list[SweepCell],
    *,
    fp_per_hour_budget: float = 1.0,
    detector_dir: pathlib.Path | None = None,
) -> dict:
    """Train + eval + heldout on the merged data, then attach per-cell
    census. Writes nothing; returns the report dict."""
    detector_dir = detector_dir or (ROOT / "detector")
    models_dir = data_dir / "models"
    reports_dir = data_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    _run_analyzer([sys.executable, str(detector_dir / "train.py"),
                   "--data", str(data_dir),
                   "--out", str(models_dir),
                   "--epochs", "80", "--patience", "10"])

    eval_out = reports_dir / "sweep_eval.json"
    _run_analyzer([sys.executable, str(detector_dir / "eval.py"),
                   "--data", str(data_dir),
                   "--models", str(models_dir),
                   "--out", str(eval_out),
                   "--fp-per-hour-budget", str(fp_per_hour_budget)])
    eval_report = json.loads(eval_out.read_text())

    heldout_out = reports_dir / "sweep_heldout.json"
    _run_analyzer([sys.executable, str(detector_dir / "heldout.py"),
                   "--data", str(data_dir),
                   "--out", str(heldout_out),
                   "--fp-per-hour-budget", str(fp_per_hour_budget)])
    heldout_report = json.loads(heldout_out.read_text())

    sessions_path = data_dir / "sessions.jsonl"
    census = per_cell_census(plan, sessions_path)
    summary = {
        "n_cells_planned": len(plan),
        "n_cells_with_data": sum(1 for c in census if c["any_provenance_seen"]),
        "axes_planned": {
            "target_app": sorted({c.target_app for c in plan}),
            "family": sorted({c.family for c in plan}),
            "security_level": sorted({c.security_level for c in plan}),
            "stealth": sorted({c.stealth for c in plan}),
        },
        "fp_per_hour_budget": fp_per_hour_budget,
    }
    return {
        "summary": summary,
        "per_cell_census": census,
        "eval": eval_report,
        "heldout": heldout_report,
    }


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sessions", type=int, default=2,
                    help="sessions per (target, family, sec_level, stealth) cell")
    ap.add_argument("--benign-sessions", type=int, default=3)
    ap.add_argument("--security-levels", default="low,medium")
    ap.add_argument("--fp-budget", type=float, default=1.0)
    ap.add_argument("--skip-docker", action="store_true",
                    help="don't bring up benign / run cells — only build the "
                         "report from existing data/. Useful for retry after "
                         "an aborted sweep.")
    ap.add_argument("--out", type=pathlib.Path, default=None,
                    help="path for sweep_<ts>.json; default data/reports/sweep_<ts>.json")
    # phase 14: real-LLM cells (opt-in, off by default to avoid surprise API spend)
    ap.add_argument("--include-llm", action="store_true",
                    help="Append the LLM-agent matrix (4 targets × N backends × "
                         "M models × 2 stealth) to the sweep. OFF by default — "
                         "real-LLM cells cost API budget.")
    ap.add_argument("--llm-backends", default=",".join(_DEFAULT_LLM_BACKENDS),
                    help="comma-separated backends for the LLM matrix "
                         "(default openai,anthropic)")
    ap.add_argument("--llm-models", default="",
                    help="comma-separated backend:model overrides, e.g. "
                         "openai:gpt-4o-mini,anthropic:claude-haiku-4-5. "
                         "Empty → built-in defaults per backend.")
    ap.add_argument("--llm-sessions", type=int, default=2,
                    help="sessions per LLM cell (default 2)")
    ap.add_argument("--llm-dry-run", action="store_true",
                    help="enumerate the LLM matrix and run the real_agent "
                         "container with CERNIS_AGENT_DRY_RUN=1 (target_guard "
                         "validation only; zero API calls). Useful before "
                         "paying budget.")
    args = ap.parse_args(argv)

    sec_levels = tuple(s.strip() for s in args.security_levels.split(",") if s.strip())
    config = default_config(
        sessions_per_cell=args.sessions,
        benign_sessions=args.benign_sessions,
        security_levels=sec_levels,
    )
    plan = build_sweep_plan(config)
    print(f"[sweep] config: {json.dumps(config.to_summary(), indent=2)}")

    # phase 14: LLM matrix enumeration (build always; execute only if asked)
    llm_cells: list[LlmSweepCell] = []
    llm_run: dict | None = None
    if args.include_llm or args.llm_dry_run:
        backends = tuple(b.strip() for b in args.llm_backends.split(",") if b.strip())
        models_override: dict[str, list[str]] = {b: [] for b in backends}
        for token in (args.llm_models or "").split(","):
            token = token.strip()
            if not token:
                continue
            if ":" not in token:
                raise SystemExit(
                    f"[sweep] --llm-models entry {token!r} must be backend:model"
                )
            b, m = token.split(":", 1)
            b = b.strip()
            models_override.setdefault(b, []).append(m.strip())
        for b in backends:
            if not models_override.get(b):
                models_override[b] = list(_DEFAULT_LLM_MODELS.get(b, ()))
        llm_cells = default_llm_config(
            backends=backends, models=models_override,
            sessions_per_cell=args.llm_sessions,
        )
        # Phase 14b: pre-run cost projection. Print BEFORE
        # execute_llm_sweep so the operator sees the bill before
        # paying (even with --llm-dry-run, this is the value).
        pre_run_cost = cost_projection_for_cells(llm_cells)
        print(f"[sweep] LLM matrix: {len(llm_cells)} cells "
              f"(backends={list(backends)}, dry_run={args.llm_dry_run})")
        print(f"[sweep] PROJECTED SPEND: {pre_run_cost['total_formatted']}"
              + (f"  (unpriced models: {pre_run_cost['unpriced_cells']})"
                 if pre_run_cost["unpriced_cells"] else ""))

    cell_results: list[dict] = []
    if not args.skip_docker:
        start_benign(config)
        cell_results = execute_sweep(plan)
        if llm_cells:
            llm_run = execute_llm_sweep(llm_cells, dry_run=args.llm_dry_run)

    report = build_sweep_report(
        DATA, plan, fp_per_hour_budget=args.fp_budget,
    )
    report["config"] = config.to_summary()
    report["cell_run_results"] = cell_results
    if llm_cells:
        cost = cost_projection_for_cells(llm_cells)
        report["llm_matrix"] = {
            "n_cells": len(llm_cells),
            "axes": {
                "target_app": sorted({c.target_app for c in llm_cells}),
                "backend": sorted({c.backend for c in llm_cells}),
                "model": sorted({c.model for c in llm_cells}),
                "stealth": sorted({c.stealth for c in llm_cells}),
            },
            "families_planned": sorted({c.family() for c in llm_cells}),
            "cost_projection": cost,
            "run": llm_run,
        }
        print(
            f"[sweep] LLM cost projection: {cost['total_formatted']} "
            f"(total) across {len(llm_cells)} cells; "
            f"unpriced: {cost['unpriced_cells'] or 'none'}"
        )

    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = args.out or (REPORTS / f"sweep_{ts}.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))
    print(f"[sweep] wrote {out_path}")

    s = report["summary"]
    print(f"[sweep] {s['n_cells_with_data']}/{s['n_cells_planned']} cells "
          f"produced data; PR-AUC[with_hp]="
          f"{report['eval'].get('with_hp', {}).get('pr_auc'):.4f}  "
          f"FP/hr="
          f"{report['eval'].get('with_hp', {}).get('fp_per_hour'):.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
