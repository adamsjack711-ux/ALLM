"""phase 15 verification gate — live dashboard.

Three offline parts. No docker, no real lab data.

PART A — pure data-access functions against synthetic fixtures
  - tail_sessions returns last-N newest-first with the expected
    redaction (extra → extra_keys only)
  - sessions_by_family respects the window_s cutoff and counts by
    (target_app, stealth, class) correctly
  - requests_rate computes req/s + status buckets over the window
  - dedupe_leaderboard collapses same-key entries to the latest by
    submitted_at; mixed-key entries survive
  - leaderboard_view groups by (splits_version, split, seed) and sorts
    each group by primary[sort_by] desc with NaN sinking
  - read_alert_fatigue handles missing / malformed files cleanly
  - find_latest_sweep picks the lex-greatest sweep_*.json

PART B — aiohttp app end-to-end
  - spin up `make_app(td)` on a random loopback port
  - hit /api/health, /api/meta, /api/sessions/recent,
    /api/sessions/by_family, /api/requests/rate, /api/leaderboard,
    /api/alert_fatigue, /api/sweep
  - GET / returns the inline HTML (Content-Type text/html, has the
    panel headers)
  - verify each JSON endpoint's shape matches what the JS frontend
    expects to render

PART C — accuracy scrubber
  - poison the leaderboard with `accuracy` in a primary block
  - /api/leaderboard returns HTTP 500 (assert_no_accuracy raised)
  - all other endpoints still 200
"""

from __future__ import annotations

import asyncio
import json
import pathlib
import sys
import tempfile
import time

import aiohttp
from aiohttp import web

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dashboard import app as dashmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── fixture builders ────────────────────────────────────────────────


def _stage_data(td: pathlib.Path) -> dict[str, pathlib.Path]:
    """Write a realistic-looking data/ tree with sessions, requests,
    leaderboard, alert_fatigue, and one sweep report."""
    data = td / "data"
    data.mkdir()
    (data / "host").mkdir()
    (data / "reports").mkdir()

    now = time.time()

    # sessions.jsonl — 8 rows. Stale rows go FIRST (the lab appends
    # chronologically; tail_sessions reads tail-of-file so the recent
    # rows must be at the end).
    sess_rows = [
        # stale — outside the default 300s window
        {"ts": now - 9999, "session_id": "stale-01",
         "class": "agent", "family": "playwright_bot",
         "target_app": "dvwa", "stealth": False,
         "generator": "playwright_bot", "extra": {}},
        {"ts": now - 9998, "session_id": "stale-02",
         "class": "agent", "family": "playwright_bot",
         "target_app": "dvwa", "stealth": False,
         "generator": "playwright_bot", "extra": {}},
        # recent — within the 300s window, chronological ascending
        {"ts": now - 30,  "session_id": "abcd1234ef00",
         "class": "agent", "family": "playwright_bot",
         "target_app": "dvwa", "security_level": "low",
         "stealth": False, "generator": "playwright_bot",
         "extra": {"backend": "playwright"}},
        {"ts": now - 25,  "session_id": "abcd1234ef01",
         "class": "agent", "family": "llm_openai_gpt_4o_mini",
         "target_app": "dvwa", "security_level": "low",
         "stealth": True, "generator": "real_agent",
         "extra": {"backend": "openai", "model": "gpt-4o-mini"}},
        {"ts": now - 20,  "session_id": "abcd1234ef02",
         "class": "agent", "family": "llm_openai_gpt_4o_mini",
         "target_app": "juice_shop", "stealth": False,
         "generator": "real_agent",
         "extra": {"backend": "openai", "model": "gpt-4o-mini"}},
        {"ts": now - 15,  "session_id": "abcd1234ef03",
         "class": "benign_bot", "family": "googlebot",
         "target_app": "dvwa", "stealth": False,
         "generator": "benign_bots",
         "extra": {}},
        {"ts": now - 10,  "session_id": "abcd1234ef04",
         "class": "benign_bot", "family": "googlebot",
         "target_app": "dvwa", "stealth": False,
         "generator": "benign_bots", "extra": {}},
        {"ts": now - 5,   "session_id": "abcd1234ef05",
         "class": "human", "family": "human_real",
         "target_app": "dvwa", "stealth": False,
         "generator": "human_real", "extra": {}},
    ]
    (data / "sessions.jsonl").write_text(
        "\n".join(json.dumps(r) for r in sess_rows) + "\n"
    )

    # requests.jsonl — 12 rows: 3 status codes × 4 (family, target) pairs
    req_rows = [
        {"ts": now - 5, "src_label": "playwright_bot",
         "target_app": "dvwa", "method": "GET",
         "path": "/index.php", "status": 200},
        {"ts": now - 4, "src_label": "playwright_bot",
         "target_app": "dvwa", "method": "GET",
         "path": "/foo", "status": 404},
        {"ts": now - 3, "src_label": "playwright_bot",
         "target_app": "dvwa", "method": "GET",
         "path": "/bar", "status": 500},
        {"ts": now - 2, "src_label": "googlebot",
         "target_app": "dvwa", "method": "GET",
         "path": "/", "status": 200},
        {"ts": now - 1, "src_label": "googlebot",
         "target_app": "dvwa", "method": "GET",
         "path": "/", "status": 200},
        {"ts": now - 50, "src_label": "playwright_bot",
         "target_app": "juice_shop", "method": "GET",
         "path": "/api/products", "status": 200},
        # stale
        {"ts": now - 999, "src_label": "playwright_bot",
         "target_app": "dvwa", "method": "GET",
         "path": "/old", "status": 200},
    ]
    (data / "requests.jsonl").write_text(
        "\n".join(json.dumps(r) for r in req_rows) + "\n"
    )

    # leaderboard.jsonl — 5 entries, two dedupe collisions
    lb_rows = [
        {"submitted_at": "2026-06-21T10:00:00Z",
         "submission": "benchmark/baselines/ua_rule",
         "submission_hash": "sha256:aaaa",
         "splits_version": "v1", "split": "public_test", "seed": 0,
         "primary": {"pr_auc": 0.42, "fp_per_hour": 1.2, "threshold": 0.3},
         "resource": {"wall_time_s": 1.1, "peak_mem_mb": None, "exit_status": 0},
         "runner": "python"},
        {"submitted_at": "2026-06-21T11:00:00Z",
         "submission": "benchmark/baselines/ua_rule",
         "submission_hash": "sha256:aaaa",
         "splits_version": "v1", "split": "public_test", "seed": 0,
         "primary": {"pr_auc": 0.45, "fp_per_hour": 1.0, "threshold": 0.31},
         "resource": {"wall_time_s": 1.4, "peak_mem_mb": None, "exit_status": 0},
         "runner": "python"},
        {"submitted_at": "2026-06-21T12:00:00Z",
         "submission": "benchmark/baselines/hybrid",
         "submission_hash": "sha256:bbbb",
         "splits_version": "v1", "split": "public_test", "seed": 0,
         "primary": {"pr_auc": 0.88, "fp_per_hour": 0.4, "threshold": 0.55},
         "resource": {"wall_time_s": 12.3, "peak_mem_mb": 320.0, "exit_status": 0},
         "runner": "container"},
        {"submitted_at": "2026-06-21T12:30:00Z",
         "submission": "benchmark/baselines/aggregate_only",
         "submission_hash": "sha256:cccc",
         "splits_version": "v1", "split": "heldout", "seed": 0,
         "primary": {"pr_auc": 0.62, "fp_per_hour": 0.9, "threshold": 0.41},
         "resource": {"wall_time_s": 2.0, "peak_mem_mb": None, "exit_status": 0},
         "runner": "python"},
        # Different submission_hash → different row even at same split/seed
        {"submitted_at": "2026-06-21T13:00:00Z",
         "submission": "benchmark/baselines/gru_only",
         "submission_hash": "sha256:dddd",
         "splits_version": "v1", "split": "public_test", "seed": 0,
         "primary": {"pr_auc": 0.71, "fp_per_hour": 0.7, "threshold": 0.48},
         "resource": {"wall_time_s": 4.2, "peak_mem_mb": 410.0, "exit_status": 0},
         "runner": "container"},
    ]
    lb_path = data / "reports" / "leaderboard.jsonl"
    lb_path.write_text("\n".join(json.dumps(r) for r in lb_rows) + "\n")

    # alert_fatigue.json — minimal phase-3 + phase-4 shape
    af_path = data / "host" / "alert_fatigue.json"
    af_path.write_text(json.dumps({
        "fp_per_hour_budget": 1.0,
        "threshold": 0.512,
        "window_seconds_estimate": 174.3,
        "per_class_fp_rate": {"normal": {"n_windows": 100, "fp_windows": 4,
                                          "fp_rate": 0.04}},
        "per_hard_negative_subtype_fp_rate": {},
        "mttd_by_attack_family": {
            "caldera": {"n_campaigns": 1, "n_detected": 1,
                        "detect_rate": 1.0, "mttd_s": 174.3, "mttd_s_p95": 174.3},
            "atomic":  {"n_campaigns": 1, "n_detected": 0,
                        "detect_rate": 0.0, "mttd_s": None, "mttd_s_p95": None},
        },
        "deployment_estimates": [
            {"deployment": "small_office", "hosts": 10,
             "events_per_sec_per_host": 1.0,
             "normal_fp_per_hour": 0.5, "hard_negative_fp_per_hour": 0.0,
             "total_fp_per_hour": 0.5},
            {"deployment": "med_business", "hosts": 50,
             "events_per_sec_per_host": 1.5,
             "normal_fp_per_hour": 3.75, "hard_negative_fp_per_hour": 0.0,
             "total_fp_per_hour": 3.75},
        ],
    }))

    # sweep_*.json — pick two so find_latest_sweep has work to do
    (data / "reports" / "sweep_20260620_120000.json").write_text(
        json.dumps({"summary": {"n_cells_planned": 5,
                                 "n_cells_with_data": 3}}))
    (data / "reports" / "sweep_20260621_090000.json").write_text(
        json.dumps({"summary": {"n_cells_planned": 8,
                                 "n_cells_with_data": 6}}))

    return {"data": data, "leaderboard": lb_path, "alert_fatigue": af_path}


# ── PART A: pure data functions ─────────────────────────────────────


def part_a_pure(paths: dict) -> None:
    print("\n[smoke-p15] PART A — pure data functions")
    data = paths["data"]

    # tail_sessions
    rows = dashmod.tail_sessions(data / "sessions.jsonl", n=5)
    _assert(len(rows) == 5,
            f"[A] tail_sessions n=5 expected 5 rows, got {len(rows)}")
    _assert(rows[0]["family"] == "human_real",
            f"[A] tail not newest-first: {rows[0]}")
    _assert("extra_keys" in rows[1] and "extra" not in rows[1],
            f"[A] tail not redacting extra: {rows[1]}")

    # sessions_by_family within 300s window
    fams = dashmod.sessions_by_family(
        data / "sessions.jsonl", window_s=300,
    )
    _assert("googlebot" in fams,
            f"[A] sessions_by_family missing googlebot: {sorted(fams)}")
    _assert("playwright_bot" in fams,
            f"[A] sessions_by_family missing playwright_bot")
    _assert(fams["googlebot"]["n"] == 2,
            f"[A] googlebot count wrong: {fams['googlebot']}")
    pw = fams["playwright_bot"]
    _assert(pw["n"] == 1,
            f"[A] playwright_bot count includes stale rows: {pw}")
    _assert(pw["by_class"].get("agent") == 1,
            f"[A] by_class wrong: {pw['by_class']}")
    llm = fams.get("llm_openai_gpt_4o_mini") or {}
    _assert(llm.get("n") == 2,
            f"[A] LLM family count wrong: {llm}")
    _assert(llm["by_stealth"]["stealth"] == 1,
            f"[A] LLM stealth count wrong: {llm['by_stealth']}")

    # requests_rate
    rates = dashmod.requests_rate(
        data / "requests.jsonl", window_s=60,
    )
    pw_dvwa = rates.get("playwright_bot@dvwa") or {}
    _assert(pw_dvwa.get("n_requests") == 3,
            f"[A] playwright@dvwa req count wrong: {pw_dvwa}")
    _assert(pw_dvwa.get("status_2xx") == 1,
            f"[A] playwright@dvwa 2xx count: {pw_dvwa}")
    _assert(pw_dvwa.get("status_4xx") == 1,
            f"[A] playwright@dvwa 4xx count: {pw_dvwa}")
    _assert(pw_dvwa.get("status_5xx") == 1,
            f"[A] playwright@dvwa 5xx count: {pw_dvwa}")
    _assert(abs(pw_dvwa["req_per_s"] - (3 / 60)) < 1e-9,
            f"[A] req_per_s wrong: {pw_dvwa['req_per_s']}")

    # dedupe + leaderboard view
    raw_rows = dashmod.read_jsonl(paths["leaderboard"])
    deduped = dashmod.dedupe_leaderboard(raw_rows)
    _assert(len(deduped) == 4,
            f"[A] dedupe expected 4, got {len(deduped)}")
    # Confirm latest-by-submitted_at survived for ua_rule collision
    ua_entries = [e for e in deduped if e["submission_hash"] == "sha256:aaaa"]
    _assert(len(ua_entries) == 1
            and ua_entries[0]["submitted_at"] == "2026-06-21T11:00:00Z",
            f"[A] dedupe kept the older ua_rule entry: {ua_entries}")

    view = dashmod.leaderboard_view(paths["leaderboard"])
    _assert(view["n_raw"] == 5 and view["n_deduped"] == 4,
            f"[A] view counts wrong: {view['n_raw']}, {view['n_deduped']}")
    _assert(len(view["groups"]) == 2,
            f"[A] expected 2 groups (public_test + heldout), got "
            f"{len(view['groups'])}")
    pt = next(g for g in view["groups"] if g["split"] == "public_test")
    _assert(pt["entries"][0]["primary"]["pr_auc"] == 0.88,
            f"[A] public_test top entry should be hybrid (0.88), got "
            f"{pt['entries'][0]['primary']}")

    # alert_fatigue
    af = dashmod.read_alert_fatigue(paths["alert_fatigue"])
    _assert(af is not None and af["threshold"] == 0.512,
            f"[A] alert_fatigue load wrong: {af}")
    missing = dashmod.read_alert_fatigue(data / "host" / "missing.json")
    _assert(missing is None,
            f"[A] missing file should return None: {missing}")
    bad = data / "host" / "bad.json"
    bad.write_text("not json")
    _assert(dashmod.read_alert_fatigue(bad) is None,
            "[A] malformed JSON should return None")

    # find_latest_sweep
    latest = dashmod.find_latest_sweep(data / "reports")
    _assert(latest is not None and latest.name == "sweep_20260621_090000.json",
            f"[A] find_latest_sweep picked wrong: {latest}")

    print("[smoke-p15] PART A passed")


# ── PART B: aiohttp end-to-end ──────────────────────────────────────


async def _serve(app):
    """Start `app` on a random loopback port; return (runner, port)."""
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, port


async def part_b_endpoints(paths: dict) -> None:
    print("\n[smoke-p15] PART B — HTTP endpoints")
    app = dashmod.make_app(paths["data"], alert_fatigue_path=paths["alert_fatigue"])
    runner, port = await _serve(app)
    base = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession() as client:
            # /api/health
            async with client.get(f"{base}/api/health") as r:
                _assert(r.status == 200, f"[B] /api/health status {r.status}")
                data = await r.json()
                _assert(data.get("ok") is True,
                        f"[B] /api/health body: {data}")

            # /api/meta
            async with client.get(f"{base}/api/meta") as r:
                _assert(r.status == 200, f"[B] /api/meta status {r.status}")
                meta = await r.json()
                _assert("sessions_path" in meta
                        and "leaderboard_path" in meta,
                        f"[B] /api/meta: {meta}")

            # /api/sessions/recent
            async with client.get(f"{base}/api/sessions/recent?n=4") as r:
                _assert(r.status == 200,
                        f"[B] sessions/recent status {r.status}")
                body = await r.json()
                _assert(len(body["rows"]) == 4,
                        f"[B] expected 4 recent rows, got {len(body['rows'])}")

            # /api/sessions/by_family
            async with client.get(
                    f"{base}/api/sessions/by_family?window_s=300") as r:
                _assert(r.status == 200,
                        f"[B] by_family status {r.status}")
                body = await r.json()
                _assert("googlebot" in body["by_family"],
                        f"[B] by_family missing googlebot")

            # /api/requests/rate
            async with client.get(f"{base}/api/requests/rate?window_s=60") as r:
                _assert(r.status == 200,
                        f"[B] requests/rate status {r.status}")
                body = await r.json()
                _assert("playwright_bot@dvwa" in body["by_key"],
                        f"[B] requests/rate missing key")

            # /api/leaderboard
            async with client.get(f"{base}/api/leaderboard") as r:
                _assert(r.status == 200,
                        f"[B] leaderboard status {r.status}")
                view = await r.json()
                _assert(view["n_raw"] == 5
                        and view["n_deduped"] == 4
                        and len(view["groups"]) == 2,
                        f"[B] leaderboard view wrong: {view}")

            # /api/alert_fatigue
            async with client.get(f"{base}/api/alert_fatigue") as r:
                _assert(r.status == 200,
                        f"[B] alert_fatigue status {r.status}")
                body = await r.json()
                _assert(body["report"]["threshold"] == 0.512,
                        f"[B] alert_fatigue body: {body}")

            # /api/sweep
            async with client.get(f"{base}/api/sweep") as r:
                _assert(r.status == 200,
                        f"[B] sweep status {r.status}")
                body = await r.json()
                _assert("sweep_20260621_090000.json" in (body.get("path") or ""),
                        f"[B] sweep picked wrong file: {body}")

            # GET / → inline HTML
            async with client.get(f"{base}/") as r:
                _assert(r.status == 200,
                        f"[B] / status {r.status}")
                _assert(r.content_type == "text/html",
                        f"[B] / content_type {r.content_type}")
                html = await r.text()
                for panel in ("Live sweep", "Leaderboard",
                              "Alert-fatigue", "Recent sessions"):
                    _assert(panel in html,
                            f"[B] HTML missing panel {panel!r}")
    finally:
        await runner.cleanup()
    print("[smoke-p15] PART B passed")


# ── PART C: accuracy scrubber ──────────────────────────────────────


async def part_c_scrubber(td: pathlib.Path) -> None:
    print("\n[smoke-p15] PART C — accuracy scrubber")
    # Stage a fresh tree; poison the leaderboard.
    paths = _stage_data(td)
    bad_rows = [{
        "submitted_at": "2026-06-22T08:00:00Z",
        "submission": "evil/baseline",
        "submission_hash": "sha256:eeee",
        "splits_version": "v1", "split": "public_test", "seed": 0,
        "primary": {"pr_auc": 0.9, "fp_per_hour": 0.1, "accuracy": 0.99},
        "resource": {"wall_time_s": 1.0, "exit_status": 0},
        "runner": "python",
    }]
    with paths["leaderboard"].open("a") as f:
        for r in bad_rows:
            f.write(json.dumps(r) + "\n")

    app = dashmod.make_app(paths["data"], alert_fatigue_path=paths["alert_fatigue"])
    runner, port = await _serve(app)
    base = f"http://127.0.0.1:{port}"
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(f"{base}/api/leaderboard") as r:
                _assert(r.status == 500,
                        f"[C] poisoned leaderboard should 500, got {r.status}")

            # Other endpoints still healthy
            async with client.get(f"{base}/api/sessions/recent?n=3") as r:
                _assert(r.status == 200,
                        f"[C] sessions still 200: {r.status}")
            async with client.get(f"{base}/api/alert_fatigue") as r:
                _assert(r.status == 200,
                        f"[C] alert_fatigue still 200: {r.status}")
            async with client.get(f"{base}/api/health") as r:
                _assert(r.status == 200, "[C] health still 200")
    finally:
        await runner.cleanup()
    print("[smoke-p15] PART C passed")


# ── main ────────────────────────────────────────────────────────────


async def amain() -> None:
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cernis_p15_a_") as td:
        paths = _stage_data(pathlib.Path(td))
        part_a_pure(paths)
        await part_b_endpoints(paths)
    with tempfile.TemporaryDirectory(prefix="cernis_p15_c_") as td:
        await part_c_scrubber(pathlib.Path(td))
    print()
    print(f"PHASE-15 SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
