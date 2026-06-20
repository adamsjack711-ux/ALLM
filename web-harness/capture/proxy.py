"""Capture reverse proxy for the cernis-web-harness lab.

Sits between traffic generators and DVWA. Phase 3 adds a honeypot layer
(see honeypots.py). All session+log plumbing now lives in a middleware
so honeypot routes share it with the proxied traffic.

For each request the middleware:
  - reads the body once, stashes it on `request['_body_in']`
  - mints / re-uses an `cernis_sid` session cookie
  - resolves the source label (header on :8080, hard-coded on :8090)
  - runs the form-POST honeypot check before any forwarding
  - on response, sets the session cookie if new and writes one redacted
    row to data/requests.jsonl (skipping the two telemetry endpoints,
    which have their own log).

No body content is written; sensitive headers are dropped before write.

phase-bench-1 (human-real channel): the :8090 listener is the only
ingress for real consented human browsing. A consent_gate middleware
runs in front of session_and_log_middleware on that listener:
  - GET  /__consent          → serve the consent landing page
  - POST /__consent/accept   → mint consent_id + sid, write one row each
                                to data/consent.jsonl and sessions.jsonl,
                                set httponly cookies, 302 to upstream root
  - every other path: 403 with link to /__consent until cernis_consent
    cookie is present.

Rows captured on the human channel drop the source IP entirely and
replace the raw User-Agent with a coarse browser-family + device-type
bucket — derived once and discarded. See capture/redaction.py.
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
from redaction import redact_ip, ua_bucket

UPSTREAM = os.environ.get("UPSTREAM", "http://dvwa:80").rstrip("/")
# Each capture container fronts one target. CERNIS_TARGET_APP is the
# label that flows into the per-row `target_app` column when the
# generator didn't set X-Cernis-TargetApp itself (e.g. human_real
# browsing, or legacy generators).
TARGET_APP = os.environ.get("CERNIS_TARGET_APP", "dvwa")
SECURITY_LEVEL = os.environ.get("DVWA_SECURITY_LEVEL", "low")
DATA_DIR = pathlib.Path(os.environ.get("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
REQ_LOG = DATA_DIR / "requests.jsonl"
BEACON_LOG = DATA_DIR / "beacons.jsonl"
SESSIONS_LOG = DATA_DIR / "sessions.jsonl"
CONSENT_LOG = DATA_DIR / "consent.jsonl"
BEACON_JS = pathlib.Path(__file__).with_name("beacon.js").read_bytes()
CONSENT_HTML = pathlib.Path(__file__).with_name("consent.html").read_bytes()

# Bumped whenever consent.html's terms change so consent rows can be
# joined back to the exact wording the user agreed to.
CONSENT_TEXT_VERSION = "v1"

TELEMETRY_PATHS = (
    "/__beacon.js", "/__beacon", "/__provenance",
    "/__consent", "/__consent/accept",
)

# Back-compat mapping: existing generators (phases 1-5) only set
# X-Cernis-Source. Derive class/family for them so eval code can group by
# the new label-schema axes without per-row guards.
_LEGACY_SRC_TO_LABEL: dict[str, tuple[str, str]] = {
    "playwright_bot": ("agent", "playwright_bot"),
    "pentesterpro": ("agent", "pentesterpro"),
    "human_sim": ("human", "human_sim"),
    "human_real": ("human", "human_real"),
}

_session_last_seen: dict[str, float] = {}
# phase 11: schema cache per session. Some attack tools (nikto) can't set
# per-request headers, so they bootstrap one labelled request via httpx +
# then run the scan with no per-request label headers. The cache lets the
# proxy inherit the bootstrap session's class / family / target_app /
# security_level / stealth fields onto the scan's request rows so the
# eval per-family and per-target_app slices stay clean.
_session_schema_cache: dict[str, dict] = {}
_session_src_label_cache: dict[str, str] = {}
_log_lock = asyncio.Lock()
_beacon_lock = asyncio.Lock()
_sessions_lock = asyncio.Lock()
_consent_lock = asyncio.Lock()


def safe_header_set(headers) -> str:
    names = sorted({k.lower() for k in headers.keys()})
    return hashlib.sha1(",".join(names).encode()).hexdigest()[:8]


def make_session_id() -> str:
    return uuid.uuid4().hex


def get_or_mint_sid(request: web.Request) -> tuple[str, bool]:
    sid = request.cookies.get("cernis_sid")
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


async def write_consent_log(row: dict) -> None:
    line = json.dumps(row, separators=(",", ":")) + "\n"
    async with _consent_lock:
        with CONSENT_LOG.open("a") as f:
            f.write(line)


def _label_schema_from_request(request: web.Request, src_label: str) -> dict:
    """Pull the X-Cernis-* label-schema headers off a request.

    Falls back to deriving class/family from src_label for legacy
    generators (phases 1-5) that only set X-Cernis-Source. The fallback
    target_app stays "dvwa" because phase 1 is DVWA-only; this constant
    moves to a header lookup in phase 2 when multi-target lands.
    """
    cls = request.headers.get("X-Cernis-Class")
    fam = request.headers.get("X-Cernis-Family")
    if cls is None or fam is None:
        derived = _LEGACY_SRC_TO_LABEL.get(src_label)
        if derived is not None:
            cls = cls or derived[0]
            fam = fam or derived[1]
    stealth_raw = request.headers.get("X-Cernis-Stealth", "").lower()
    return {
        "class": cls or "unknown",
        "family": fam or src_label,
        "target_app": request.headers.get("X-Cernis-TargetApp", TARGET_APP),
        "security_level": request.headers.get("X-Cernis-SecurityLevel", "na"),
        "stealth": stealth_raw in ("1", "true", "yes"),
    }


def _has_cernis_label_headers(request: web.Request) -> bool:
    """True if the request explicitly carries any X-Cernis-* label header."""
    for k in request.headers.keys():
        if k.lower().startswith("x-cernis-"):
            return True
    return False


@web.middleware
async def session_and_log_middleware(request: web.Request, handler):
    started = time.time()
    body_in = await request.read()
    sid, is_new = get_or_mint_sid(request)
    label = request.app["label_for"](request)
    # phase 11: if this request didn't carry an X-Cernis-Source but an
    # earlier request on the same session did, inherit it. Tools like
    # nikto that can't set per-request headers bootstrap with a labeled
    # session and then scan; the cache keeps the proxy's per-row labels
    # consistent across the whole session.
    if label in ("", "unknown") and not request.app.get("force_label"):
        cached_label = _session_src_label_cache.get(sid)
        if cached_label:
            label = cached_label
    elif label not in ("", "unknown") and _has_cernis_label_headers(request):
        _session_src_label_cache[sid] = label
    request["_body_in"] = body_in
    request["_sid"] = sid
    request["_is_new"] = is_new
    request["_label"] = label

    await request.app["honeypot"].check_form_post(request, body_in, sid, label)

    try:
        resp = await handler(request)
    except web.HTTPException as exc:
        resp = exc

    if is_new and not resp.cookies.get("cernis_sid"):
        resp.set_cookie("cernis_sid", sid, httponly=True, path="/", samesite="Lax")

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

    # Schema cache: first time we see an explicitly-labeled request on
    # this sid, write the schema into the cache. Subsequent requests on
    # the same sid that DIDN'T set their own X-Cernis-* headers inherit
    # the cached schema so the per-row class/family/target_app stays
    # consistent across the session.
    if _has_cernis_label_headers(request):
        schema = _label_schema_from_request(request, label)
        _session_schema_cache.setdefault(sid, schema)
    else:
        cached_schema = _session_schema_cache.get(sid)
        schema = cached_schema or _label_schema_from_request(request, label)
    # phase-bench-1: anonymize the human channel at write time. Raw IP
    # is dropped; raw UA is replaced with a coarse browser+device bucket
    # (the only UA-derived signal the detector needs). Other channels
    # are unchanged — they only carry generator traffic between
    # containers.
    raw_ua = request.headers.get("User-Agent", "")[:300]
    if request.app.get("is_human_channel"):
        src_ip_val: Optional[str] = redact_ip(request.remote)
        ua_val = ua_bucket(raw_ua)
    else:
        src_ip_val = request.remote
        ua_val = raw_ua

    log_row = {
        "ts": started,
        "session_id": sid,
        "src_ip": src_ip_val,
        "src_label": label,
        "method": request.method,
        "path": request.path,
        "qs_len": len(request.query_string),
        "status": resp.status,
        "req_bytes": len(body_in),
        "resp_bytes": resp_len,
        "ua": ua_val,
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


# ── phase-bench-1: consent gate (human-real channel only) ───────────

_BLOCKED_BODY = (
    b"<!doctype html><html><body style='font-family:sans-serif;max-width:560px;"
    b"margin:4em auto;padding:0 1em'>"
    b"<h1>Consent required</h1>"
    b"<p>This lab listener only records consented sessions. "
    b"Visit <a href=\"/__consent\">/__consent</a> to read the terms and opt in.</p>"
    b"</body></html>"
)


async def serve_consent(request: web.Request) -> web.Response:
    return web.Response(
        body=CONSENT_HTML,
        content_type="text/html",
        headers={"Cache-Control": "no-store"},
    )


async def accept_consent(request: web.Request) -> web.Response:
    """Mint consent + session, persist them, set cookies, redirect to root.

    Two rows are written here, none later: one to data/consent.jsonl
    (records the agreement itself), one to data/sessions.jsonl (acts as
    the per-session provenance row so eval can join on session_id
    without waiting for a /__provenance POST from a generator).

    The raw User-Agent is derived into a coarse bucket at this point and
    immediately discarded — neither the raw UA nor the source IP ever
    persists for human-real traffic.
    """
    raw_ua = request.headers.get("User-Agent", "")
    bucket = ua_bucket(raw_ua)
    if "-" in bucket:
        browser_family, device_type = bucket.split("-", 1)
    else:
        browser_family, device_type = bucket, "unknown"

    consent_id = uuid.uuid4().hex
    sid = make_session_id()
    now = time.time()

    consent_row = {
        "ts": now,
        "consent_id": consent_id,
        "consent_text_version": CONSENT_TEXT_VERSION,
        "ua_bucket": bucket,
    }
    await write_consent_log(consent_row)

    # Synthetic provenance — class/family/target/etc. mirror what a
    # generator would POST to /__provenance. The consent_text_version
    # doubles as `generator_version` so sweeps can group by it.
    provenance_payload = {
        "class": "human",
        "family": "human_real",
        "target_app": TARGET_APP,
        "security_level": SECURITY_LEVEL,
        "stealth": False,
        "generator": "human_real",
        "generator_version": CONSENT_TEXT_VERSION,
        "extra": {
            "browser_family": browser_family,
            "device_type": device_type,
            "consent_id": consent_id,
        },
    }
    cfg_blob = json.dumps(provenance_payload, sort_keys=True, separators=(",", ":")).encode()
    session_row = {
        "ts": now,
        "session_id": sid,
        "src_label": "human_real",
        "class": "human",
        "family": "human_real",
        "target_app": TARGET_APP,
        "security_level": SECURITY_LEVEL,
        "stealth": False,
        "generator": "human_real",
        "generator_version": CONSENT_TEXT_VERSION,
        "generator_config_sha": hashlib.blake2b(cfg_blob, digest_size=4).hexdigest(),
        "extra": provenance_payload["extra"],
    }
    await write_session_log(session_row)

    resp = web.Response(status=302, headers={"Location": "/"})
    resp.set_cookie(
        "cernis_consent", consent_id,
        httponly=True, path="/", samesite="Lax",
    )
    resp.set_cookie(
        "cernis_sid", sid,
        httponly=True, path="/", samesite="Lax",
    )
    return resp


@web.middleware
async def consent_gate_middleware(request: web.Request, handler):
    """Front of the human-channel middleware chain.

    /__consent + /__consent/accept short-circuit here so the downstream
    session/logging middleware never runs for them (no sid is minted,
    no row is written). Every other path is rejected with 403 until the
    cernis_consent cookie is present.
    """
    if request.path == "/__consent" and request.method == "GET":
        return await serve_consent(request)
    if request.path == "/__consent/accept" and request.method == "POST":
        return await accept_consent(request)
    if not request.cookies.get("cernis_consent"):
        return web.Response(
            status=403,
            body=_BLOCKED_BODY,
            content_type="text/html",
            headers={"Cache-Control": "no-store"},
        )
    return await handler(request)


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
        fwd_headers["Cookie"] = f"cernis_sid={sid}"
    elif is_new:
        fwd_headers["Cookie"] = fwd_headers["Cookie"] + f"; cernis_sid={sid}"

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


def make_app(
    *,
    label: Optional[str],
    default_from_header: bool,
    is_human_channel: bool = False,
) -> web.Application:
    # Consent gate runs ahead of session_and_log_middleware on the human
    # channel — its purpose is to terminate the request before any sid
    # is minted or any row is written if consent is missing.
    middlewares = (
        [consent_gate_middleware, session_and_log_middleware]
        if is_human_channel
        else [session_and_log_middleware]
    )
    app = web.Application(
        client_max_size=16 * 1024 * 1024,
        middlewares=middlewares,
    )

    def label_for(request: web.Request) -> str:
        if label is not None:
            return label
        return request.headers.get("X-Cernis-Source", "unknown")

    app["label_for"] = label_for
    app["is_human_channel"] = is_human_channel
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
    internal = make_app(label=None, default_from_header=True, is_human_channel=False)
    human = make_app(label="human_real", default_from_header=False, is_human_channel=True)

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
