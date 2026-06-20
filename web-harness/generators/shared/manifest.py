"""Per-session provenance helper for traffic generators.

Every generator should call `record_provenance(...)` once per session,
after its first request has minted an `allm_sid` cookie. The capture
proxy upserts a row into `data/sessions.jsonl` keyed by that sid:

    {ts, session_id, src_label, class, family, target_app,
     security_level, stealth, generator, generator_version,
     generator_config_sha, extra}

The same labels also flow through every per-request log row via the
X-Allm-* headers each generator already sets on its session.

The helper uses httpx because it's a lighter dep than Playwright's
context client and works for non-browser generators too. Browser-based
generators can call `record_provenance_from_context()` to reuse the
Playwright APIRequestContext (sharing the same `allm_sid` cookie).
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Optional


def config_sha(cfg: dict) -> str:
    """Stable short hash of a generator config dict."""
    blob = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.blake2b(blob, digest_size=4).hexdigest()


def build_payload(
    *,
    klass: str,
    family: str,
    target_app: str,
    security_level: str = "na",
    stealth: bool = False,
    generator: str,
    generator_version: str,
    generator_config: Optional[dict] = None,
    extra: Optional[dict] = None,
) -> dict:
    cfg = generator_config or {}
    return {
        "class": klass,
        "family": family,
        "target_app": target_app,
        "security_level": security_level,
        "stealth": stealth,
        "generator": generator,
        "generator_version": generator_version,
        "generator_config_sha": config_sha(cfg),
        "extra": extra or {},
    }


def headers_for(payload: dict) -> dict:
    """The same labels mirrored into X-Allm-* headers on every request.

    Generators set these on each HTTP request so the capture proxy can
    persist them per-row (which is what the detector reads), independent
    of the one-shot provenance POST.
    """
    return {
        "X-Allm-Source": payload["family"],
        "X-Allm-Class": payload["class"],
        "X-Allm-Family": payload["family"],
        "X-Allm-TargetApp": payload["target_app"],
        "X-Allm-SecurityLevel": payload["security_level"],
        "X-Allm-Stealth": "true" if payload["stealth"] else "false",
    }


def record_provenance_httpx(
    client: Any, target: str, payload: dict, *, timeout: float = 5.0
) -> None:
    """POST the provenance row via an httpx.Client (sync) or AsyncClient.

    The client should already have made at least one request to `target`
    so that an `allm_sid` cookie is in its jar; the proxy uses that
    cookie to key the row. We don't fail the generator if the proxy is
    momentarily unavailable — the request log is the source of truth and
    a missing provenance row just means eval falls back to legacy
    label-schema derivation.
    """
    url = f"{target.rstrip('/')}/__provenance"
    headers = headers_for(payload) | {"Content-Type": "application/json"}
    try:
        client.post(url, content=json.dumps(payload).encode(), headers=headers, timeout=timeout)
    except Exception as exc:  # noqa: BLE001 — non-fatal by design
        print(f"[manifest] provenance POST failed (continuing): {exc}", flush=True)


async def record_provenance_playwright(
    ctx_request: Any, target: str, payload: dict, *, timeout_ms: int = 5000
) -> None:
    """POST provenance via a Playwright APIRequestContext bound to the
    same BrowserContext as the session — so the existing `allm_sid`
    cookie travels with it."""
    url = f"{target.rstrip('/')}/__provenance"
    try:
        await ctx_request.post(
            url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=timeout_ms,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"[manifest] provenance POST failed (continuing): {exc}", flush=True)


def env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")
