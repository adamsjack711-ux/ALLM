"""Real autonomous LLM-driven browser agent (phase-bench-1, PART B).

This is the ONE generator in the lab that talks to a cloud LLM. It runs
`browser-use` (Playwright-driven LLM agent) against the bundled DVWA via
the capture proxy. Everything else in the lab is deterministic and
offline; this generator is gated behind its own compose profile
(`profiles: ["real-agent"]`) so it does not start under the default
`docker compose up`.

Guarantees, enforced in this file:

1. target_guard.get_target() runs *before* any browser-use / LLM import.
   If CERNIS_TARGET points anywhere other than the allow-list, the
   process exits non-zero before a single LLM token is requested.

2. The API key is read from the environment (OPENAI_API_KEY or
   ANTHROPIC_API_KEY). It is never printed, never logged, never written
   to any file. The startup banner names only the backend + model.

3. Every browser request carries the X-Cernis-* label headers via the
   Playwright BrowserContext, so the capture proxy persists class=agent
   / family=llm_browser_agent / target_app / stealth on each row.

4. Per-session provenance is POSTed to the proxy's /__provenance once
   the session cookie is minted, recording the LLM model + browser-use
   version in `extra`.

Required env vars:
  CERNIS_TARGET           e.g. http://capture:8080 (must be allow-listed)
  OPENAI_API_KEY          if CERNIS_AGENT_BACKEND=openai (default)
  ANTHROPIC_API_KEY       if CERNIS_AGENT_BACKEND=anthropic

Optional env vars:
  CERNIS_AGENT_BACKEND    openai | anthropic (default openai)
  CERNIS_AGENT_MODEL      model name (defaults: gpt-4o-mini / claude-haiku-4-5)
  CERNIS_AGENT_TASK       free-text prompt (default: log in + visit 2 pages)
  CERNIS_TARGET_APP       label (default dvwa)
  CERNIS_SESSIONS         independent sessions to run (default 1)
  CERNIS_STEALTH          1/true → stealth axis on the manifest (default false)
  CERNIS_AGENT_DRY_RUN    1 → skip the actual browser run (smoke-test hook)
"""

from __future__ import annotations

import asyncio
import os
import sys
import time

sys.path.insert(0, "/app/shared")
from manifest import (  # noqa: E402
    build_payload, headers_for, record_provenance_playwright,
)
from target_guard import get_target  # noqa: E402

# target_guard exits non-zero (before any LLM import) if CERNIS_TARGET
# is missing or points off the allow-list. This is the *only* control
# preventing an injected/jailbroken prompt from steering the browser
# anywhere besides the bundled targets.
LABEL = "llm_browser_agent"
TARGET = get_target()
TARGET_APP = os.environ.get("CERNIS_TARGET_APP", "dvwa")
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
SESSIONS = int(os.environ.get("CERNIS_SESSIONS", "1"))
STEALTH = os.environ.get("CERNIS_STEALTH", "false").strip().lower() in (
    "1", "true", "yes",
)
DRY_RUN = os.environ.get("CERNIS_AGENT_DRY_RUN", "").strip() == "1"

BACKEND = os.environ.get("CERNIS_AGENT_BACKEND", "openai").strip().lower()
_DEFAULT_MODELS = {
    "openai": "gpt-4o-mini",
    "anthropic": "claude-haiku-4-5",
}
MODEL = os.environ.get("CERNIS_AGENT_MODEL") or _DEFAULT_MODELS.get(BACKEND, "")

DEFAULT_TASK = (
    f"Open {TARGET}. Log in with username `admin` and password `password`. "
    f"After login, visit two pages in the navigation menu, then stop."
)
TASK = os.environ.get("CERNIS_AGENT_TASK") or DEFAULT_TASK


def _api_key_for(backend: str) -> str:
    """Read the API key without ever putting it through stdout/stderr."""
    if backend == "openai":
        key = os.environ.get("OPENAI_API_KEY", "")
    elif backend == "anthropic":
        key = os.environ.get("ANTHROPIC_API_KEY", "")
    else:
        print(f"[real_agent] unknown CERNIS_AGENT_BACKEND={backend!r}", file=sys.stderr)
        raise SystemExit(2)
    if not key:
        var = "OPENAI_API_KEY" if backend == "openai" else "ANTHROPIC_API_KEY"
        print(f"[real_agent] required env var {var} is not set", file=sys.stderr)
        raise SystemExit(2)
    return key


def _browser_use_version() -> str:
    try:
        import browser_use  # type: ignore
        return getattr(browser_use, "__version__", "unknown")
    except Exception:
        return "unimported"


async def _run_one() -> None:
    """Run a single agent session. Lazy-imports browser-use + langchain
    so module import (and target_guard validation) stay cheap and
    decoupled from the heavy LLM/browser stack."""
    payload = build_payload(
        klass="agent",
        family=LABEL,
        target_app=TARGET_APP,
        security_level=SECURITY_LEVEL,
        stealth=STEALTH,
        generator="real_agent",
        generator_version="0.1.0",
        generator_config={
            "backend": BACKEND, "model": MODEL, "stealth": STEALTH,
        },
        extra={
            "backend": BACKEND,
            "model": MODEL,
            "framework": "browser-use",
            "framework_version": _browser_use_version(),
        },
    )
    extra_headers = headers_for(payload)

    from browser_use import Agent, BrowserSession  # noqa: PLC0415

    api_key = _api_key_for(BACKEND)
    if BACKEND == "openai":
        from langchain_openai import ChatOpenAI  # noqa: PLC0415
        llm = ChatOpenAI(model=MODEL, api_key=api_key)
    else:
        from langchain_anthropic import ChatAnthropic  # noqa: PLC0415
        llm = ChatAnthropic(model=MODEL, api_key=api_key)
    # api_key is in the closed-over llm now; drop our local reference
    # so it can't accidentally end up in a logged traceback.
    del api_key

    session = BrowserSession(
        extra_http_headers=extra_headers,
        headless=True,
    )
    agent = Agent(task=TASK, llm=llm, browser_session=session)
    try:
        await agent.run()
        # Provenance row: post it from the same browser context so the
        # cernis_sid cookie travels with it and keys correctly.
        try:
            ctx = getattr(session, "context", None)
            ctx_request = getattr(ctx, "request", None) if ctx else None
            if ctx_request is not None:
                await record_provenance_playwright(ctx_request, TARGET, payload)
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


async def main() -> None:
    print(
        f"[real_agent] target={TARGET} backend={BACKEND} model={MODEL} "
        f"sessions={SESSIONS} stealth={STEALTH} dry_run={DRY_RUN}",
        flush=True,
    )
    if DRY_RUN:
        print(
            "[real_agent] CERNIS_AGENT_DRY_RUN=1 set — skipping browser run "
            "(target_guard already validated; no LLM call made)",
            flush=True,
        )
        return
    for i in range(SESSIONS):
        t0 = time.time()
        try:
            await _run_one()
            print(
                f"[real_agent] session {i + 1}/{SESSIONS} ok in {time.time() - t0:.1f}s",
                flush=True,
            )
        except Exception as exc:  # noqa: BLE001
            # Don't include the exception args in the log line — some
            # LLM clients echo the api key back in error messages.
            print(
                f"[real_agent] session {i + 1}/{SESSIONS} failed: {type(exc).__name__}",
                flush=True,
            )


if __name__ == "__main__":
    asyncio.run(main())
