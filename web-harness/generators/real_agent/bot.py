"""Real autonomous LLM-driven browser agent (phase-bench-1 PART B, expanded
to a matrix-driven cell runner in phase 14).

This is the ONE generator in the lab that talks to a cloud LLM. It runs
`browser-use` (Playwright-driven LLM agent) against the bundled targets via
the per-target capture proxy. Everything else in the lab is deterministic
and offline; this generator is gated behind its own compose profile
(`profiles: ["real-agent"]`) so it does not start under the default
`docker compose up`.

Two execution modes:

  - **single-cell** (phase-bench-1, the default) — the original behavior.
    CERNIS_TARGET + CERNIS_TARGET_APP + CERNIS_AGENT_BACKEND +
    CERNIS_AGENT_MODEL pick one cell; CERNIS_SESSIONS sets the repeat
    count.

  - **matrix** (phase 14) — `CERNIS_AGENT_CELLS_FILE=/path/to/cells.json`
    drives a matrix of (target_app, backend, model, stealth) cells in a
    single container run. Each cell is validated against `target_guard`
    independently. Format:

        {
          "cells": [
            {"target_url": "http://capture:8080",
             "target_app": "dvwa",
             "backend": "openai",
             "model": "gpt-4o-mini",
             "stealth": false,
             "sessions": 2,
             "task": "Open {target}. Log in admin/password ..."}
          ]
        }

    `task` is optional; if omitted, the built-in per-target default in
    `_DEFAULT_TASKS` is used (with `{target}` substituted).

Guarantees, enforced in this file:

  1. `target_guard.assert_loopback_target(...)` runs *before* any
     browser-use / LLM import, **per cell**. If any cell's URL points
     anywhere other than the allow-list, the process exits non-zero
     before a single LLM token is requested for any cell.

  2. The API key is read from the environment (OPENAI_API_KEY or
     ANTHROPIC_API_KEY). It is never printed, never logged, never
     written to any file. The startup banner names only the backend +
     model.

  3. Every browser request carries the X-Cernis-* label headers via the
     Playwright BrowserContext, so the capture proxy persists
     class=agent / family=llm_<backend>_<model_slug> / target_app /
     stealth on each row.

  4. Per-session provenance is POSTed to the proxy's /__provenance once
     the session cookie is minted, recording the LLM model +
     browser-use version in `extra`.

The family name encodes the cell (e.g. `llm_openai_gpt_4o_mini`,
`llm_anthropic_claude_haiku_4_5`) so existing per_family rollups in
`benchmark/evaluate.py` automatically surface per-(backend, model)
breakdowns. The phase 14 eval also adds explicit `per_llm_backend` and
`per_llm_model_x_target` rollups that key off the `llm_` prefix.

Required env vars (single-cell mode):
  CERNIS_TARGET           e.g. http://capture:8080 (must be allow-listed)
  OPENAI_API_KEY          if any cell uses backend=openai
  ANTHROPIC_API_KEY       if any cell uses backend=anthropic

Optional env vars:
  CERNIS_AGENT_CELLS_FILE path to a JSON file with `{"cells": [...]}`.
                          When set, drives matrix mode. Each cell's
                          per-cell env vars (backend/model/stealth/task)
                          override the single-cell defaults below.
  CERNIS_AGENT_BACKEND    openai | anthropic (default openai)
  CERNIS_AGENT_MODEL      model name (defaults: gpt-4o-mini / claude-haiku-4-5)
  CERNIS_AGENT_TASK       free-text prompt (single-cell mode)
  CERNIS_AGENT_TASKS_FILE JSON {"target_app": "...", "_default": "..."}
                          used as fallback when a matrix cell omits
                          `task` and the built-in default for that
                          target_app isn't what you want.
  CERNIS_TARGET_APP       label (default dvwa)
  CERNIS_SESSIONS         independent sessions per cell (default 1)
  CERNIS_STEALTH          1/true → stealth axis on the manifest (default false)
  CERNIS_AGENT_DRY_RUN    1 → skip browser run; emit cell plan to
                          /tmp/cernis_real_agent_dry_run.jsonl. Used by
                          the smoke; also useful to enumerate what a
                          cells_file would actually run before paying
                          API budget.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import os
import pathlib
import re
import sys
import time
from typing import Optional

sys.path.insert(0, "/app/shared")
from manifest import (  # noqa: E402
    build_payload, headers_for, record_provenance_playwright,
)
from target_guard import assert_loopback_target, get_target  # noqa: E402

GENERATOR_NAME = "real_agent"
GENERATOR_VERSION = "0.3.0"  # phase 14b: per-session cost accounting

DRY_RUN = os.environ.get("CERNIS_AGENT_DRY_RUN", "").strip() == "1"
DRY_RUN_LOG = pathlib.Path(
    os.environ.get("CERNIS_DRY_RUN_LOG",
                   "/tmp/cernis_real_agent_dry_run.jsonl")
)


def _dry_run_tokens() -> tuple[int, int]:
    """Phase 14b: spoofed token counts for the smoke. Format is
    `<input>/<output>` integers; returns (0, 0) when unset so the
    legacy dry-run path stays unchanged. The smoke uses this to
    verify the cost-accounting pipeline without an LLM call."""
    raw = os.environ.get("CERNIS_DRY_RUN_TOKENS", "").strip()
    if not raw or "/" not in raw:
        return 0, 0
    a, b = raw.split("/", 1)
    try:
        return int(a), int(b)
    except ValueError:
        return 0, 0


# Local pricing module (sibling file). Import is at module-load time;
# pricing is a pure-Python dict + helpers with no third-party deps.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pricing as pricingmod  # noqa: E402

_DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-haiku-4-5",
}

_VALID_BACKENDS = frozenset({"openai", "anthropic"})

# Per-target default task templates. `{target}` is substituted at
# cell-run time. VAmPI is intentionally absent — the JSON-only API has
# no DOM, so a browser-use agent against it adds zero detection signal
# beyond what the existing sqlmap / raw_httpx generators already give.
# A dedicated HTTP-only LLM client for VAmPI is a phase-14-followup
# item.
_DEFAULT_TASKS: dict[str, str] = {
    "dvwa": (
        "Open {target}. Log in with username `admin` and password "
        "`password`. After login, visit two pages in the navigation "
        "menu, then stop."
    ),
    "juice_shop": (
        "Open {target}. Register a fresh account with a throwaway "
        "email + password, log in, then browse three product pages "
        "and add one item to the basket."
    ),
    "webgoat": (
        "Open {target}/WebGoat/start.mvc. Register a fresh account "
        "with a throwaway email + password, log in, then open the "
        "lesson menu and navigate to two different lessons."
    ),
    "crapi": (
        "Open {target}. Sign up for a new account, log in, then "
        "browse the vehicles page and the community forum page."
    ),
}


# ----------------------------------------------------------------------
# Cell model
# ----------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class AgentCell:
    target_url: str         # full URL passed to assert_loopback_target
    target_app: str         # label persisted in the manifest
    backend: str            # openai | anthropic
    model: str              # e.g. gpt-4o-mini
    stealth: bool
    sessions: int
    task: str               # final task string after default-substitution
    security_level: str = "low"

    def family(self) -> str:
        return _family_name(self.backend, self.model)


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(s: str) -> str:
    """Lowercase + non-alnum-collapse — turns `gpt-4o-mini` into
    `gpt_4o_mini`, `claude-haiku-4-5` into `claude_haiku_4_5`."""
    return _SLUG_RE.sub("_", s.lower()).strip("_")


def _family_name(backend: str, model: str) -> str:
    """Family naming convention for LLM-agent sessions. Keeps the `llm_`
    prefix so the eval rollup can pivot on it; encodes both backend and
    model so the existing per_family rollup gives per-cell visibility
    without any schema change."""
    return f"llm_{_slug(backend)}_{_slug(model)}"


# ----------------------------------------------------------------------
# Cell-file loading + defaults
# ----------------------------------------------------------------------

def _tasks_overlay() -> dict[str, str]:
    """Load CERNIS_AGENT_TASKS_FILE if set. Format:
       {"target_app": "task ...", "_default": "task ..."}
    Returns {} on any error so the built-in _DEFAULT_TASKS still
    govern.
    """
    path = os.environ.get("CERNIS_AGENT_TASKS_FILE", "").strip()
    if not path:
        return {}
    try:
        return json.loads(pathlib.Path(path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[real_agent] CERNIS_AGENT_TASKS_FILE unreadable "
              f"({type(exc).__name__}); falling back to defaults",
              flush=True)
        return {}


def _resolve_task(
    target_app: str, target_url: str,
    explicit: Optional[str], overlay: dict[str, str],
) -> str:
    """Pick the task for one cell. Precedence: explicit `task` on the
    cell > overlay file's per-target entry > built-in default >
    overlay's `_default` > built-in DVWA default."""
    if explicit:
        return explicit.replace("{target}", target_url)
    if target_app in overlay:
        return overlay[target_app].replace("{target}", target_url)
    if target_app in _DEFAULT_TASKS:
        return _DEFAULT_TASKS[target_app].replace("{target}", target_url)
    if "_default" in overlay:
        return overlay["_default"].replace("{target}", target_url)
    return _DEFAULT_TASKS["dvwa"].replace("{target}", target_url)


def _truthy(v: object) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in ("1", "true", "yes")


def _build_cells_from_env() -> list[AgentCell]:
    """Single-cell mode: build exactly one cell from the legacy env
    vars (back-compat with phase-bench-1)."""
    target = get_target()
    target_app = os.environ.get("CERNIS_TARGET_APP", "dvwa")
    backend = os.environ.get("CERNIS_AGENT_BACKEND", "openai").strip().lower()
    model = os.environ.get("CERNIS_AGENT_MODEL") or _DEFAULT_MODELS.get(backend, "")
    stealth = _truthy(os.environ.get("CERNIS_STEALTH"))
    sessions = int(os.environ.get("CERNIS_SESSIONS", "1"))
    explicit_task = os.environ.get("CERNIS_AGENT_TASK") or None
    overlay = _tasks_overlay()
    sec = os.environ.get("DVWA_SECURITY_LEVEL", "low")
    return [AgentCell(
        target_url=target, target_app=target_app,
        backend=backend, model=model, stealth=stealth, sessions=sessions,
        task=_resolve_task(target_app, target, explicit_task, overlay),
        security_level=sec,
    )]


def _build_cells_from_file(path: pathlib.Path) -> list[AgentCell]:
    """Matrix mode: load `{"cells": [...]}` and validate each entry."""
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict) or "cells" not in raw:
        raise SystemExit(
            f"[real_agent] {path} must be a JSON object with a 'cells' list"
        )
    overlay = _tasks_overlay()
    cells: list[AgentCell] = []
    for i, item in enumerate(raw["cells"]):
        if not isinstance(item, dict):
            raise SystemExit(f"[real_agent] cells[{i}] is not a dict")
        try:
            target_url = assert_loopback_target(str(item["target_url"]))
            target_app = str(item["target_app"])
            backend = str(item["backend"]).strip().lower()
        except KeyError as exc:
            raise SystemExit(
                f"[real_agent] cells[{i}] missing required field: {exc}"
            )
        if backend not in _VALID_BACKENDS:
            raise SystemExit(
                f"[real_agent] cells[{i}] backend={backend!r} not in "
                f"{sorted(_VALID_BACKENDS)}"
            )
        model = str(item.get("model") or _DEFAULT_MODELS[backend])
        stealth = _truthy(item.get("stealth"))
        sessions = int(item.get("sessions", 1))
        task = _resolve_task(
            target_app, target_url,
            explicit=item.get("task"), overlay=overlay,
        )
        sec = str(item.get("security_level", "low"))
        cells.append(AgentCell(
            target_url=target_url, target_app=target_app,
            backend=backend, model=model, stealth=stealth,
            sessions=sessions, task=task, security_level=sec,
        ))
    return cells


def build_cells() -> list[AgentCell]:
    """Dispatch on CERNIS_AGENT_CELLS_FILE: matrix mode if set, else
    single-cell mode reading the legacy env vars."""
    cells_file = os.environ.get("CERNIS_AGENT_CELLS_FILE", "").strip()
    if cells_file:
        path = pathlib.Path(cells_file)
        if not path.exists():
            raise SystemExit(
                f"[real_agent] CERNIS_AGENT_CELLS_FILE={path} does not exist"
            )
        return _build_cells_from_file(path)
    return _build_cells_from_env()


# ----------------------------------------------------------------------
# API key + browser-use version helpers (deferred imports)
# ----------------------------------------------------------------------

def _api_key_for(backend: str) -> str:
    """Read the API key without ever putting it through stdout/stderr."""
    if backend == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        var = "OPENAI_API_KEY"
    elif backend == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        var = "ANTHROPIC_API_KEY"
    else:
        print(f"[real_agent] unknown backend {backend!r}", file=sys.stderr)
        raise SystemExit(2)
    if not key:
        print(f"[real_agent] required env var {var} is not set",
              file=sys.stderr)
        raise SystemExit(2)
    return key


def _browser_use_version() -> str:
    try:
        import browser_use  # type: ignore
        return getattr(browser_use, "__version__", "unknown")
    except Exception:
        return "unimported"


# ----------------------------------------------------------------------
# Cell execution
# ----------------------------------------------------------------------

def _payload_for(cell: AgentCell, *, tokens_in: int = 0, tokens_out: int = 0) -> dict:
    """Build the per-session provenance payload.

    `tokens_in` / `tokens_out` come from the per-session
    TokenCounterCallback after the agent.run() returns. In DRY_RUN
    they come from `CERNIS_DRY_RUN_TOKENS=<in>/<out>` so the smoke
    can verify the cost-accounting pipeline without an LLM call.
    """
    cost_cents = pricingmod.estimate_cost_cents(
        cell.backend, cell.model, tokens_in, tokens_out,
    )
    return build_payload(
        klass="agent",
        family=cell.family(),
        target_app=cell.target_app,
        security_level=cell.security_level,
        stealth=cell.stealth,
        generator=GENERATOR_NAME,
        generator_version=GENERATOR_VERSION,
        generator_config={
            "backend": cell.backend, "model": cell.model,
            "stealth": cell.stealth, "target_app": cell.target_app,
        },
        extra={
            "backend": cell.backend,
            "model": cell.model,
            "framework": "browser-use",
            "framework_version": _browser_use_version(),
            "prompt_template_id": _slug(cell.target_app),
            # phase 14b: per-session cost accounting. cost_cents is
            # None for unpriced (backend, model) pairs; the dashboard
            # renders that as 'unpriced'.
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "estimated_cost_cents": cost_cents,
        },
    )


class _TokenCounter:
    """Async langchain BaseCallbackHandler that sums prompt_tokens +
    completion_tokens across every LLM call inside one session.

    Defined inline (rather than imported from a top-level class) so the
    bot module can load without langchain installed — the smoke + the
    dry-run path don't touch this code at all."""

    def __init__(self) -> None:
        self.tokens_in = 0
        self.tokens_out = 0

    def _accumulate(self, response) -> None:
        llm_output = getattr(response, "llm_output", None) or {}
        usage = llm_output.get("token_usage") or llm_output.get("usage") or {}
        # OpenAI uses prompt_tokens / completion_tokens; Anthropic uses
        # input_tokens / output_tokens. Honor both keys.
        self.tokens_in += int(
            usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0) or 0
        )
        self.tokens_out += int(
            usage.get("completion_tokens", 0) or usage.get("output_tokens", 0) or 0
        )

    async def on_llm_end(self, response, **kwargs) -> None:  # noqa: D401
        self._accumulate(response)

    async def on_chat_model_end(self, response, **kwargs) -> None:  # noqa: D401
        self._accumulate(response)


async def _run_one_session(cell: AgentCell) -> None:
    """One agent session against one cell. Heavy imports happen here so
    the dry-run + sanity paths don't drag the playwright/browser-use
    deps in.

    The X-Cernis-* request headers are built from a token-less payload
    (the capture proxy only needs class/family/target/stealth on each
    row). The per-session provenance row posted at the end carries the
    actual token counts captured by `_TokenCounter`.
    """
    base_payload = _payload_for(cell)  # for request headers only
    extra_headers = headers_for(base_payload)

    from browser_use import Agent, BrowserSession  # noqa: PLC0415
    api_key = _api_key_for(cell.backend)
    counter = _TokenCounter()
    if cell.backend == "openai":
        from langchain_openai import ChatOpenAI  # noqa: PLC0415
        llm = ChatOpenAI(model=cell.model, api_key=api_key, callbacks=[counter])
    else:
        from langchain_anthropic import ChatAnthropic  # noqa: PLC0415
        llm = ChatAnthropic(model=cell.model, api_key=api_key, callbacks=[counter])
    del api_key

    session = BrowserSession(extra_http_headers=extra_headers, headless=True)
    agent = Agent(task=cell.task, llm=llm, browser_session=session)
    try:
        await agent.run()
        # Build the provenance payload AFTER the agent finishes so we
        # can attach the realized token counts + estimated cost.
        prov_payload = _payload_for(
            cell, tokens_in=counter.tokens_in, tokens_out=counter.tokens_out,
        )
        try:
            ctx = getattr(session, "context", None)
            ctx_request = getattr(ctx, "request", None) if ctx else None
            if ctx_request is not None:
                await record_provenance_playwright(
                    ctx_request, cell.target_url, prov_payload,
                )
        except Exception as exc:  # noqa: BLE001 — provenance is best-effort
            print(
                f"[real_agent] provenance post skipped: {type(exc).__name__}",
                flush=True,
            )
    finally:
        try:
            await session.close()
        except Exception:
            pass


async def _run_cell(cell: AgentCell) -> None:
    projection = pricingmod.estimate_session_projection(cell.backend, cell.model)
    label = (
        f"target={cell.target_app}({cell.target_url}) "
        f"backend={cell.backend} model={cell.model} "
        f"stealth={cell.stealth} sessions={cell.sessions} "
        f"family={cell.family()} "
        f"projected_cost={pricingmod.format_cents(projection * cell.sessions if projection is not None else None)}"
    )
    print(f"[real_agent] cell  {label}", flush=True)

    if DRY_RUN:
        # phase 14b: honor spoofed token counts via CERNIS_DRY_RUN_TOKENS=<in>/<out>
        # so the smoke can verify the cost-accounting pipeline without an LLM
        # call. The legacy dry-run path (no env var) still writes zero tokens.
        tokens_in, tokens_out = _dry_run_tokens()
        payload = _payload_for(cell, tokens_in=tokens_in, tokens_out=tokens_out)
        DRY_RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
        with DRY_RUN_LOG.open("a") as f:
            f.write(json.dumps({
                "cell": dataclasses.asdict(cell),
                "payload": payload,
                "headers": headers_for(payload),
            }, sort_keys=True) + "\n")
        print(
            f"[real_agent]   DRY_RUN: logged payload + headers to "
            f"{DRY_RUN_LOG}, no LLM call made"
            + (f" (spoofed tokens {tokens_in}/{tokens_out})"
               if (tokens_in or tokens_out) else ""),
            flush=True,
        )
        return

    for i in range(cell.sessions):
        t0 = time.time()
        try:
            await _run_one_session(cell)
            print(
                f"[real_agent]   session {i + 1}/{cell.sessions} ok "
                f"in {time.time() - t0:.1f}s",
                flush=True,
            )
        except Exception as exc:  # noqa: BLE001
            # Don't echo exc args — some LLM clients put the api key
            # in their error messages.
            print(
                f"[real_agent]   session {i + 1}/{cell.sessions} failed: "
                f"{type(exc).__name__}",
                flush=True,
            )


async def main() -> None:
    cells = build_cells()
    print(
        f"[real_agent] phase 14 matrix runner v{GENERATOR_VERSION} "
        f"n_cells={len(cells)} dry_run={DRY_RUN}",
        flush=True,
    )
    if DRY_RUN and DRY_RUN_LOG.exists():
        # Truncate the log so a fresh dry-run starts clean. The smoke
        # depends on knowing it has only the rows from this invocation.
        DRY_RUN_LOG.unlink()
    for cell in cells:
        await _run_cell(cell)


if __name__ == "__main__":
    asyncio.run(main())
