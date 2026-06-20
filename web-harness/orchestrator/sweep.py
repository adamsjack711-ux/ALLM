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


# Maps target_app → {ALLM_TARGET URL, supported families}. Selenium and
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
    # phase 11 — scanner family (single image per family, ALLM_STEALTH
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
            "-e", f"ALLM_TARGET={_target_url(cell.target_app)}",
            "-e", f"ALLM_TARGET_APP={cell.target_app}",
            "-e", f"DVWA_SECURITY_LEVEL={cell.security_level}",
            "-e", f"ALLM_SESSIONS={cell.sessions}",
            "-e", f"ALLM_STEALTH={'true' if cell.stealth else 'false'}",
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
    args = ap.parse_args(argv)

    sec_levels = tuple(s.strip() for s in args.security_levels.split(",") if s.strip())
    config = default_config(
        sessions_per_cell=args.sessions,
        benign_sessions=args.benign_sessions,
        security_levels=sec_levels,
    )
    plan = build_sweep_plan(config)
    print(f"[sweep] config: {json.dumps(config.to_summary(), indent=2)}")

    cell_results: list[dict] = []
    if not args.skip_docker:
        start_benign(config)
        cell_results = execute_sweep(plan)

    report = build_sweep_report(
        DATA, plan, fp_per_hour_budget=args.fp_budget,
    )
    report["config"] = config.to_summary()
    report["cell_run_results"] = cell_results

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
