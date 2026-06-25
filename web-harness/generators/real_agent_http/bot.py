"""HTTP-only LLM client for VAmPI (phase 14-vampi).

VAmPI is a JSON-only API with no DOM, so the browser-use-driven
`real_agent` bot adds zero detection signal beyond what sqlmap /
raw_httpx already produce. This generator is the same family of "real
LLM driving a target" but uses an httpx tool-call loop instead of a
Playwright browser:

    ┌─────────┐                ┌──────────────┐
    │  LLM    │  ── ACTION ──> │ httpx tool   │ ── HTTP ──> capture_vampi
    │ (OpenAI │                │ (this file)  │
    │  /Anthr)│  <── RESP ──── │              │
    └─────────┘                └──────────────┘

Loop semantics:
  1. Prompt the LLM with the task + the tool schema (METHOD path body).
  2. Parse the LLM's response for either `ACTION: <method> <path>
     [json_body]` or `DONE: <summary>`.
  3. On ACTION: execute via httpx (with X-Cernis-* labels), feed the
     response status + body excerpt back.
  4. Loop until DONE or MAX_STEPS reached.

The capture proxy persists `class=agent` / `family=llm_<backend>_
<model_slug>` / `target_app=vampi` per request, with
`extra.framework="langchain-httpx"` distinguishing the HTTP flavor
from the browser-use flavor's `extra.framework="browser-use"` on
downstream slicing.

Family naming intentionally reuses the `llm_<backend>_<model_slug>`
convention from phase 14 so the existing per_llm_backend / per_llm_
model_x_target rollups in `benchmark/evaluate.py` automatically pick
this generator up. To separate HTTP vs browser sessions at consumer
time, group by `extra.framework`.

Guarantees enforced (parallel to phase 14 real_agent):
  1. target_guard.assert_loopback_target(...) per cell BEFORE any LLM
     import. Off-allow-list URLs hard-exit.
  2. API key never logged or written anywhere; banner names backend +
     model only.
  3. X-Cernis-* labels on every request through `httpx.Client`'s
     per-client headers.
  4. Per-session provenance POSTed via httpx after first response.

DRY_RUN: when CERNIS_AGENT_DRY_RUN=1, the LLM isn't called and no
HTTP requests fire. The bot writes the planned payload + headers to
/tmp/cernis_real_agent_http_dry_run.jsonl. CERNIS_DRY_RUN_TOKENS spoofs
token counts the same way as phase 14b.

Required env vars (matrix mode):
  CERNIS_AGENT_CELLS_FILE  JSON {"cells": [{target_url, target_app,
                           backend, model, sessions, task?}, ...]}
  OPENAI_API_KEY           if any cell uses backend=openai
  ANTHROPIC_API_KEY        if any cell uses backend=anthropic

Optional env vars:
  CERNIS_AGENT_DRY_RUN     1 → skip LLM + HTTP, log payload only
  CERNIS_DRY_RUN_TOKENS    `<in>/<out>` spoofs token counts (phase 14b)
  CERNIS_MAX_STEPS         max tool-call loops per session (default 12)
  CERNIS_HTTP_TIMEOUT_S    per-request timeout (default 10s)
"""

from __future__ import annotations

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
    build_payload, headers_for, record_provenance_httpx,
)
from target_guard import assert_loopback_target  # noqa: E402

# Local pricing module — sibling to real_agent/pricing.py. Hard-coded
# path so the bot runs from the real_agent_http/ directory inside the
# container without a sys.path hack.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "real_agent"))
import pricing as pricingmod  # noqa: E402

GENERATOR_NAME = "real_agent_http"
GENERATOR_VERSION = "0.1.0"

DRY_RUN = os.environ.get("CERNIS_AGENT_DRY_RUN", "").strip() == "1"
DRY_RUN_LOG = pathlib.Path(
    os.environ.get("CERNIS_DRY_RUN_LOG",
                   "/tmp/cernis_real_agent_http_dry_run.jsonl")
)
MAX_STEPS = int(os.environ.get("CERNIS_MAX_STEPS", "12"))
HTTP_TIMEOUT_S = float(os.environ.get("CERNIS_HTTP_TIMEOUT_S", "10"))


def _dry_run_tokens() -> tuple[int, int]:
    """Phase 14b: spoofed token counts for smokes."""
    raw = os.environ.get("CERNIS_DRY_RUN_TOKENS", "").strip()
    if not raw or "/" not in raw:
        return 0, 0
    a, b = raw.split("/", 1)
    try:
        return int(a), int(b)
    except ValueError:
        return 0, 0


_DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-haiku-4-5",
}

_VALID_BACKENDS = frozenset({"openai", "anthropic"})

# Per-target default task templates. Keep them imperative and focused
# on the API's known shape — the LLM does better with a concrete
# objective than a generic "explore" prompt.
_DEFAULT_TASKS: dict[str, str] = {
    "vampi": (
        "Explore the VAmPI API at {target}. The API has user and book "
        "endpoints under /users/v1/ and /books/v1/. Register a new "
        "user with a throwaway username + email + password, log in to "
        "obtain a token, list users, and list books. Use ACTION lines "
        "for each HTTP call, then say DONE when finished."
    ),
}


# ----------------------------------------------------------------------
# Cell model — mirrors real_agent's AgentCell with target_url etc.
# ----------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class HttpCell:
    target_url: str
    target_app: str
    backend: str
    model: str
    sessions: int
    task: str

    def family(self) -> str:
        return _family_name(self.backend, self.model)


_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slug(s: str) -> str:
    return _SLUG_RE.sub("_", s.lower()).strip("_")


def _family_name(backend: str, model: str) -> str:
    """Same convention as phase 14 real_agent so existing eval rollups
    pick HTTP-flavor sessions up automatically. extra.framework
    distinguishes HTTP vs browser at consumer time."""
    return f"llm_{_slug(backend)}_{_slug(model)}"


def _truthy(v: object) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in ("1", "true", "yes")


def _resolve_task(target_app: str, target_url: str,
                  explicit: Optional[str]) -> str:
    if explicit:
        return explicit.replace("{target}", target_url)
    if target_app in _DEFAULT_TASKS:
        return _DEFAULT_TASKS[target_app].replace("{target}", target_url)
    return _DEFAULT_TASKS["vampi"].replace("{target}", target_url)


def _build_cells_from_file(path: pathlib.Path) -> list[HttpCell]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict) or "cells" not in raw:
        raise SystemExit(
            f"[real_agent_http] {path} must be a JSON object with a 'cells' list"
        )
    cells: list[HttpCell] = []
    for i, item in enumerate(raw["cells"]):
        if not isinstance(item, dict):
            raise SystemExit(f"[real_agent_http] cells[{i}] is not a dict")
        try:
            target_url = assert_loopback_target(str(item["target_url"]))
            target_app = str(item["target_app"])
            backend = str(item["backend"]).strip().lower()
        except KeyError as exc:
            raise SystemExit(
                f"[real_agent_http] cells[{i}] missing required field: {exc}"
            )
        if backend not in _VALID_BACKENDS:
            raise SystemExit(
                f"[real_agent_http] cells[{i}] backend={backend!r} not in "
                f"{sorted(_VALID_BACKENDS)}"
            )
        model = str(item.get("model") or _DEFAULT_MODELS[backend])
        sessions = int(item.get("sessions", 1))
        task = _resolve_task(target_app, target_url, item.get("task"))
        cells.append(HttpCell(
            target_url=target_url, target_app=target_app,
            backend=backend, model=model, sessions=sessions, task=task,
        ))
    return cells


def build_cells() -> list[HttpCell]:
    path_str = os.environ.get("CERNIS_AGENT_CELLS_FILE", "").strip()
    if not path_str:
        raise SystemExit(
            "[real_agent_http] CERNIS_AGENT_CELLS_FILE is required "
            "(matrix mode only — no single-cell legacy fallback)"
        )
    path = pathlib.Path(path_str)
    if not path.exists():
        raise SystemExit(
            f"[real_agent_http] CERNIS_AGENT_CELLS_FILE={path} does not exist"
        )
    return _build_cells_from_file(path)


# ----------------------------------------------------------------------
# Payload + tool-call loop
# ----------------------------------------------------------------------


def _api_key_for(backend: str) -> str:
    if backend == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
        var = "OPENAI_API_KEY"
    else:
        key = os.environ.get("ANTHROPIC_API_KEY", "")
        var = "ANTHROPIC_API_KEY"
    if not key:
        print(f"[real_agent_http] required env var {var} is not set",
              file=sys.stderr)
        raise SystemExit(2)
    return key


def _payload_for(cell: HttpCell, *, tokens_in: int = 0, tokens_out: int = 0) -> dict:
    cost_cents = pricingmod.estimate_cost_cents(
        cell.backend, cell.model, tokens_in, tokens_out,
    )
    return build_payload(
        klass="agent",
        family=cell.family(),
        target_app=cell.target_app,
        stealth=False,  # HTTP flavor has no stealth axis — there's no
                       # browser fingerprint to mask
        generator=GENERATOR_NAME,
        generator_version=GENERATOR_VERSION,
        generator_config={
            "backend": cell.backend, "model": cell.model,
            "target_app": cell.target_app,
        },
        extra={
            "backend": cell.backend,
            "model": cell.model,
            "framework": "langchain-httpx",
            "framework_version": GENERATOR_VERSION,
            "prompt_template_id": _slug(cell.target_app),
            "tokens_in": tokens_in,
            "tokens_out": tokens_out,
            "estimated_cost_cents": cost_cents,
            "max_steps": MAX_STEPS,
            "http_timeout_s": HTTP_TIMEOUT_S,
        },
    )


# Action parser. The LLM is asked to respond with one of:
#   ACTION: <METHOD> <path> [json-body]
#   DONE: <freeform summary>
# We parse loosely — strip whitespace, lowercase methods, accept missing
# json body.
_ACTION_RE = re.compile(
    r"^\s*ACTION:\s*(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s*(.*)$",
    re.IGNORECASE,
)
_DONE_RE = re.compile(r"^\s*DONE:\s*(.*)$", re.IGNORECASE)


def parse_action(reply: str) -> tuple[str, dict]:
    """Parse an LLM reply into ('action', {method, path, body}) or
    ('done', {summary}) or ('confused', {raw}). Exposed for the
    smoke."""
    for line in reply.splitlines():
        m = _ACTION_RE.match(line)
        if m:
            method, path, body_raw = m.group(1).upper(), m.group(2), m.group(3).strip()
            body = None
            if body_raw:
                try:
                    body = json.loads(body_raw)
                except json.JSONDecodeError:
                    body = body_raw  # passed as raw string when not JSON
            return "action", {"method": method, "path": path, "body": body}
        m = _DONE_RE.match(line)
        if m:
            return "done", {"summary": m.group(1).strip()}
    return "confused", {"raw": reply.strip()[:400]}


def _build_system_prompt(cell: HttpCell) -> str:
    return (
        "You are an HTTP API explorer. You can issue one HTTP request "
        "per turn. Format every turn as a single line:\n"
        "  ACTION: <METHOD> <path> [json-body]\n"
        "where METHOD is GET/POST/PUT/DELETE/PATCH and `path` is "
        "absolute, e.g. /users/v1/login. Supply a JSON body when the "
        "endpoint expects one. When you've completed the task, reply "
        "with `DONE: <one-sentence summary>`.\n\n"
        f"Task: {cell.task}\n\n"
        "After each ACTION the user will reply with the HTTP status "
        f"code and a short response body excerpt. Do at most {MAX_STEPS} "
        "ACTION steps before saying DONE."
    )


def _run_one_session(
    cell: HttpCell, payload: dict,
) -> Optional[float]:
    """Real LLM tool-use loop against the target. Returns realized cost
    in cents. Imports langchain + httpx lazily so the dry-run path
    stays light."""
    import httpx  # noqa: PLC0415
    from langchain_core.messages import HumanMessage, SystemMessage  # noqa: PLC0415

    api_key = _api_key_for(cell.backend)
    if cell.backend == "openai":
        from langchain_openai import ChatOpenAI  # noqa: PLC0415
        llm = ChatOpenAI(model=cell.model, api_key=api_key)
    else:
        from langchain_anthropic import ChatAnthropic  # noqa: PLC0415
        llm = ChatAnthropic(model=cell.model, api_key=api_key)
    del api_key

    extra_headers = headers_for(payload)
    tokens_in = 0
    tokens_out = 0
    messages = [SystemMessage(content=_build_system_prompt(cell))]
    realized_cost: Optional[float] = None

    with httpx.Client(
        base_url=cell.target_url,
        headers={**extra_headers, "User-Agent": "cernis-llm-httpx/0.1"},
        timeout=HTTP_TIMEOUT_S,
        follow_redirects=True,
    ) as client:
        # Post provenance once before the loop — gives the capture
        # proxy a row to attach subsequent request rows to.
        try:
            record_provenance_httpx(client, cell.target_url, payload)
        except Exception as exc:  # noqa: BLE001
            print(
                f"[real_agent_http] provenance post skipped: "
                f"{type(exc).__name__}", flush=True,
            )

        for step in range(MAX_STEPS):
            response = llm.invoke(messages)
            usage = getattr(response, "response_metadata", {}).get(
                "token_usage", {}
            ) or {}
            tokens_in += int(
                usage.get("prompt_tokens", 0)
                or usage.get("input_tokens", 0) or 0
            )
            tokens_out += int(
                usage.get("completion_tokens", 0)
                or usage.get("output_tokens", 0) or 0
            )
            kind, parsed = parse_action(response.content)
            if kind == "done":
                break
            if kind == "confused":
                # Tell the LLM its reply didn't parse and let it
                # try again. Counts toward MAX_STEPS.
                messages.append(response)
                messages.append(HumanMessage(
                    content="reply didn't parse. Use ACTION: <METHOD> "
                            "<path> [json] or DONE: <summary>."
                ))
                continue
            method, path, body = parsed["method"], parsed["path"], parsed["body"]
            try:
                if method == "GET":
                    r = client.get(path)
                elif method == "DELETE":
                    r = client.delete(path)
                elif isinstance(body, dict):
                    r = client.request(method, path, json=body)
                else:
                    r = client.request(method, path, content=body or "")
                status = r.status_code
                excerpt = r.text[:400]
            except Exception as exc:  # noqa: BLE001
                status = -1
                excerpt = f"<httpx error: {type(exc).__name__}>"
            messages.append(response)
            messages.append(HumanMessage(
                content=f"HTTP {status}\n{excerpt}"
            ))

    realized_cost = pricingmod.estimate_cost_cents(
        cell.backend, cell.model, tokens_in, tokens_out,
    )
    # Post a SECOND provenance row at the end with the realized token
    # counts attached so the operator's bill matches the cost ledger.
    final_payload = _payload_for(cell, tokens_in=tokens_in, tokens_out=tokens_out)
    try:
        with httpx.Client(
            base_url=cell.target_url,
            headers={**headers_for(final_payload),
                     "User-Agent": "cernis-llm-httpx/0.1"},
            timeout=HTTP_TIMEOUT_S,
        ) as final_client:
            record_provenance_httpx(final_client, cell.target_url, final_payload)
    except Exception as exc:  # noqa: BLE001
        print(
            f"[real_agent_http] final provenance post skipped: "
            f"{type(exc).__name__}", flush=True,
        )
    return realized_cost


def _run_cell(cell: HttpCell) -> None:
    projection = pricingmod.estimate_session_projection(cell.backend, cell.model)
    label = (
        f"target={cell.target_app}({cell.target_url}) "
        f"backend={cell.backend} model={cell.model} "
        f"sessions={cell.sessions} family={cell.family()} "
        f"projected_cost="
        f"{pricingmod.format_cents(projection * cell.sessions if projection is not None else None)}"
    )
    print(f"[real_agent_http] cell  {label}", flush=True)

    if DRY_RUN:
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
            f"[real_agent_http]   DRY_RUN: logged payload to {DRY_RUN_LOG}, "
            f"no LLM/HTTP call made"
            + (f" (spoofed tokens {tokens_in}/{tokens_out})"
               if (tokens_in or tokens_out) else ""),
            flush=True,
        )
        return

    base_payload = _payload_for(cell)
    for i in range(cell.sessions):
        t0 = time.time()
        try:
            cost = _run_one_session(cell, base_payload)
            print(
                f"[real_agent_http]   session {i + 1}/{cell.sessions} ok "
                f"in {time.time() - t0:.1f}s "
                f"(cost={pricingmod.format_cents(cost)})",
                flush=True,
            )
        except Exception as exc:  # noqa: BLE001
            print(
                f"[real_agent_http]   session {i + 1}/{cell.sessions} "
                f"failed: {type(exc).__name__}",
                flush=True,
            )


def main() -> None:
    cells = build_cells()
    # Optional drift warning — phase 14d adds warn_if_stale to pricing.
    # Defensive `hasattr` so phase 14-vampi can land independently of
    # phase 14d's merge order.
    if hasattr(pricingmod, "warn_if_stale"):
        pricingmod.warn_if_stale()
    print(
        f"[real_agent_http] phase 14-vampi v{GENERATOR_VERSION} "
        f"n_cells={len(cells)} dry_run={DRY_RUN} "
        f"max_steps={MAX_STEPS} timeout={HTTP_TIMEOUT_S}s",
        flush=True,
    )
    if DRY_RUN and DRY_RUN_LOG.exists():
        DRY_RUN_LOG.unlink()
    for cell in cells:
        _run_cell(cell)


if __name__ == "__main__":
    main()
