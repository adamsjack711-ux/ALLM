"""Capture reverse proxy for the allm-web-harness lab.

Sits between traffic generators and DVWA. Phase 3 adds a honeypot layer
(see honeypots.py). All session+log plumbing now lives in a middleware
so honeypot routes share it with the proxied traffic.

For each request the middleware:
  - reads the body once, stashes it on `request['_body_in']`
  - mints / re-uses an `allm_sid` session cookie
  - resolves the source label (header on :8080, hard-coded on :8090)
  - runs the form-POST honeypot check before any forwarding
  - on response, sets the session cookie if new and writes one redacted
    row to data/requests.jsonl (skipping the two telemetry endpoints,
    which have their own log).

No body content is written; sensitive headers are dropped before write.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import pathlib
import time
import uuid
from typing import Optional

import aiohttp
from aiohttp import web

import honeypots

UPSTREAM = os.environ.get("UPSTREAM", "http://dvwa:80").rstrip("/")
# Each capture container fronts one target. ALLM_TARGET_APP is the
# label that flows into the per-row `target_app` column when the
# generator didn't set X-Allm-TargetApp itself (e.g. human_real
# browsing, or legacy generators).
TARGET_APP = os.environ.get("ALLM_TARGET_APP", "dvwa")
DATA_DIR = pathlib.Path(os.environ.get("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
REQ_LOG = DATA_DIR / "requests.jsonl"
BEACON_LOG = DATA_DIR / "beacons.jsonl"
SESSIONS_LOG = DATA_DIR / "sessions.jsonl"
BEACON_JS = pathlib.Path(__file__).with_name("beacon.js").read_bytes()

TELEMETRY_PATHS = ("/__beacon.js", "/__beacon", "/__provenance")

# Back-compat mapping: existing generators (phases 1-5) only set
# X-Allm-Source. Derive class/family for them so eval code can group by
# the new label-schema axes without per-row guards.
_LEGACY_SRC_TO_LABEL: dict[str, tuple[str, str]] = {
    "playwright_bot": ("agent", "playwright_bot"),
    "pentesterpro": ("agent", "pentesterpro"),
    "human_sim": ("human", "human_sim"),
    "human_real": ("human", "human_real"),
}

_session_last_seen: dict[str, float] = {}
_log_lock = asyncio.Lock()
_beacon_lock = asyncio.Lock()
_sessions_lock = asyncio.Lock()


def safe_header_set(headers) -> str:
    names = sorted({k.lower() for k in headers.keys()})
    return hashlib.sha1(",".join(names).encode()).hexdigest()[:8]


def make_session_id() -> str:
    return uuid.uuid4().hex


def get_or_mint_sid(request: web.Request) -> tuple[str, bool]:
    sid = request.cookies.get("allm_sid")
    if sid and len(sid) >= 16:
        return sid, False
    return make_session_id(), True


async def write_request_log(row: dict) -> None:
    line = json.dumps(row, separators=(",", ":")) + "\n"
    async with _log_lock:
        with REQ_LOG.open("a") as f:
            f.write(line)


async def write_beacon_log(row: dict) -> None:
    line = json.dumps(row, separators=(",", ":")) + "\n"
    async with _beacon_lock:
        with BEACON_LOG.open("a") as f:
            f.write(line)


async def write_session_log(row: dict) -> None:
    line = json.dumps(row, separators=(",", ":")) + "\n"
    async with _sessions_lock:
        with SESSIONS_LOG.open("a") as f:
            f.write(line)


def _label_schema_from_request(request: web.Request, src_label: str) -> dict:
    """Pull the X-Allm-* label-schema headers off a request.

    Falls back to deriving class/family from src_label for legacy
    generators (phases 1-5) that only set X-Allm-Source. The fallback
    target_app stays "dvwa" because phase 1 is DVWA-only; this constant
    moves to a header lookup in phase 2 when multi-target lands.
    """
    cls = request.headers.get("X-Allm-Class")
    fam = request.headers.get("X-Allm-Family")
    if cls is None or fam is None:
        derived = _LEGACY_SRC_TO_LABEL.get(src_label)
        if derived is not None:
            cls = cls or derived[0]
            fam = fam or derived[1]
    stealth_raw = request.headers.get("X-Allm-Stealth", "").lower()
    return {
        "class": cls or "unknown",
        "family": fam or src_label,
        "target_app": request.headers.get("X-Allm-TargetApp", TARGET_APP),
        "security_level": request.headers.get("X-Allm-SecurityLevel", "na"),
        "stealth": stealth_raw in ("1", "true", "yes"),
    }


@web.middleware
async def session_and_log_middleware(request: web.Request, handler):
    started = time.time()
    body_in = await request.read()
    sid, is_new = get_or_mint_sid(request)
    label = request.app["label_for"](request)
    request["_body_in"] = body_in
    request["_sid"] = sid
    request["_is_new"] = is_new
    request["_label"] = label

    await request.app["honeypot"].check_form_post(request, body_in, sid, label)

    try:
        resp = await handler(request)
    except web.HTTPException as exc:
        resp = exc

    if is_new and not resp.cookies.get("allm_sid"):
        resp.set_cookie("allm_sid", sid, httponly=True, path="/", samesite="Lax")

    if request.path in TELEMETRY_PATHS:
        return resp

    now = time.time()
    last = _session_last_seen.get(sid)
    delta_ms = None if last is None else int((now - last) * 1000)
    _session_last_seen[sid] = now

    resp_len = 0
    body = getattr(resp, "body", None)
    if isinstance(body, (bytes, bytearray)):
        resp_len = len(body)

    ctype_full = resp.content_type or ""
    ctype = ctype_full.split(";", 1)[0].strip().lower()

    schema = _label_schema_from_request(request, label)
    log_row = {
        "ts": started,
        "session_id": sid,
        "src_ip": request.remote,
        "src_label": label,
        "method": request.method,
        "path": request.path,
        "qs_len": len(request.query_string),
        "status": resp.status,
        "req_bytes": len(body_in),
        "resp_bytes": resp_len,
        "ua": request.headers.get("User-Agent", "")[:300],
        "header_hash": safe_header_set(request.headers),
        "header_count": len(request.headers),
        "delta_ms": delta_ms,
        "is_new_session": is_new,
        "has_auth_header": any(k.lower() == "authorization" for k in request.headers),
        "has_cookie_header": any(k.lower() == "cookie" for k in request.headers),
        "content_type": ctype,
        "elapsed_ms": int((time.time() - started) * 1000),
        "class": schema["class"],
        "family": schema["family"],
        "target_app": schema["target_app"],
        "security_level": schema["security_level"],
        "stealth": schema["stealth"],
    }
    await write_request_log(log_row)
    return resp


async def serve_beacon_js(request: web.Request) -> web.Response:
    return web.Response(
        body=BEACON_JS,
        content_type="application/javascript",
        headers={"Cache-Control": "no-store"},
    )


async def receive_beacon(request: web.Request) -> web.Response:
    sid = request["_sid"]
    label = request["_label"]
    body_in = request["_body_in"]
    try:
        payload = json.loads(body_in.decode("utf-8", "replace"))
    except Exception:
        payload = {"_raw_invalid": True}
    if not isinstance(payload, dict):
        payload = {"_raw": str(payload)[:200]}
    row = {
        "ts": time.time(),
        "session_id": sid,
        "src_ip": request.remote,
        "src_label": label,
        "ua": request.headers.get("User-Agent", "")[:300],
        "event": payload,
    }
    await write_beacon_log(row)
    return web.Response(status=204)


_PROVENANCE_STR_FIELDS = (
    "class", "family", "target_app", "security_level",
    "generator", "generator_version", "generator_config_sha",
)


async def record_provenance(request: web.Request) -> web.Response:
    """Per-session provenance row.

    Generators POST {family, class, target_app, security_level, stealth,
    generator, generator_version, generator_config_sha, extra} after
    their first request mints a session cookie. We write a single row to
    sessions.jsonl keyed by the resolved session_id. Eval joins this
    against requests.jsonl to recover ts_start / ts_end per session.
    """
    sid = request["_sid"]
    label = request["_label"]
    body_in = request["_body_in"]
    try:
        payload = json.loads(body_in.decode("utf-8", "replace"))
    except Exception:
        return web.json_response({"error": "invalid_json"}, status=400)
    if not isinstance(payload, dict):
        return web.json_response({"error": "not_object"}, status=400)

    row = {
        "ts": time.time(),
        "session_id": sid,
        "src_label": label,
        "stealth": bool(payload.get("stealth", False)),
        "extra": payload.get("extra") or {},
    }
    for f in _PROVENANCE_STR_FIELDS:
        v = payload.get(f)
        row[f] = str(v) if v is not None else ""
    await write_session_log(row)
    return web.Response(status=204)


async def honeypot_robots(request: web.Request) -> web.Response:
    return await request.app["honeypot"].handle_robots(
        request, request["_sid"], request["_label"]
    )


async def honeypot_canary(request: web.Request) -> web.Response:
    return await request.app["honeypot"].handle_canary(
        request, request["_sid"], request["_label"]
    )


async def honeypot_tarpit(request: web.Request) -> web.Response:
    return await request.app["honeypot"].handle_tarpit(
        request, request["_sid"], request["_label"]
    )


def should_inject(content_type: str, body: bytes) -> bool:
    if "text/html" not in content_type.lower():
        return False
    return b"</body>" in body or b"</BODY>" in body


def inject_beacon(body: bytes) -> bytes:
    snippet = b'<script src="/__beacon.js"></script>'
    if b"</body>" in body:
        return body.replace(b"</body>", snippet + b"</body>", 1)
    return body.replace(b"</BODY>", snippet + b"</BODY>", 1)


async def proxy_handler(request: web.Request) -> web.StreamResponse:
    sid = request["_sid"]
    body_in = request["_body_in"]
    is_new = request["_is_new"]

    upstream_url = f"{UPSTREAM}{request.rel_url}"
    fwd_headers: dict[str, str] = {}
    for k, v in request.headers.items():
        if k.lower() in ("host", "content-length"):
            continue
        fwd_headers[k] = v
    fwd_headers["X-Forwarded-For"] = request.remote or ""
    fwd_headers["X-Forwarded-Proto"] = "http"
    if is_new and "Cookie" not in fwd_headers:
        fwd_headers["Cookie"] = f"allm_sid={sid}"
    elif is_new:
        fwd_headers["Cookie"] = fwd_headers["Cookie"] + f"; allm_sid={sid}"

    client = request.app["client"]
    try:
        async with client.request(
            request.method,
            upstream_url,
            headers=fwd_headers,
            data=body_in if body_in else None,
            allow_redirects=False,
            timeout=aiohttp.ClientTimeout(total=30),
        ) as upstream:
            resp_body = await upstream.read()
            status = upstream.status
            resp_headers: dict[str, str] = {}
            drop = {"content-length", "content-encoding", "transfer-encoding", "connection"}
            for k, v in upstream.headers.items():
                if k.lower() in drop:
                    continue
                resp_headers[k] = v
            ctype = upstream.headers.get("Content-Type", "")
    except aiohttp.ClientError as exc:
        resp_body = f"upstream error: {type(exc).__name__}".encode()
        status = 502
        resp_headers = {"Content-Type": "text/plain"}
        ctype = "text/plain"

    if should_inject(ctype, resp_body):
        resp_body = inject_beacon(resp_body)
        resp_body = request.app["honeypot"].inject_html(resp_body)

    return web.Response(status=status, body=resp_body, headers=resp_headers)


def make_app(*, label: Optional[str], default_from_header: bool) -> web.Application:
    app = web.Application(
        client_max_size=16 * 1024 * 1024,
        middlewares=[session_and_log_middleware],
    )

    def label_for(request: web.Request) -> str:
        if label is not None:
            return label
        return request.headers.get("X-Allm-Source", "unknown")

    app["label_for"] = label_for
    app["honeypot"] = honeypots.HoneypotLayer(DATA_DIR)

    async def on_startup(app):
        app["client"] = aiohttp.ClientSession()

    async def on_cleanup(app):
        await app["client"].close()

    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)

    app.router.add_get("/__beacon.js", serve_beacon_js)
    app.router.add_post("/__beacon", receive_beacon)
    app.router.add_post("/__provenance", record_provenance)
    app.router.add_get("/robots.txt", honeypot_robots)
    app.router.add_route("*", "/__canary", honeypot_canary)
    app.router.add_route("*", "/__admin_secrets", honeypot_tarpit)
    app.router.add_route("*", "/__admin_secrets/{tail:.*}", honeypot_tarpit)
    app.router.add_route("*", "/{tail:.*}", proxy_handler)
    return app


async def run() -> None:
    internal = make_app(label=None, default_from_header=True)
    human = make_app(label="human_real", default_from_header=False)

    internal_runner = web.AppRunner(internal)
    human_runner = web.AppRunner(human)
    await internal_runner.setup()
    await human_runner.setup()
    internal_site = web.TCPSite(internal_runner, "0.0.0.0", 8080)
    human_site = web.TCPSite(human_runner, "0.0.0.0", 8090)
    await internal_site.start()
    await human_site.start()

    print(f"[capture] upstream={UPSTREAM} data_dir={DATA_DIR}", flush=True)
    print("[capture] internal listener: 0.0.0.0:8080", flush=True)
    print("[capture] human    listener: 0.0.0.0:8090", flush=True)

    stop = asyncio.Event()
    try:
        await stop.wait()
    finally:
        await internal_runner.cleanup()
        await human_runner.cleanup()


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        pass
