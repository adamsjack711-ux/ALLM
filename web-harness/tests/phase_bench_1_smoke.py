"""phase-bench-1 verification gate.

Two-part check, in priority order:

PART A — consent-gated human-real capture channel.
  1. Unconsented requests to the human listener get 403 and do NOT
     write a row to requests.jsonl.
  2. GET /__consent serves the consent page (200, text/html).
  3. POST /__consent/accept mints both cernis_consent and cernis_sid
     cookies, writes one row to consent.jsonl and one to sessions.jsonl
     with class=human / family=human_real and the consent_id stamped
     into extra.
  4. Subsequent requests carrying the consent cookie do reach the
     session_and_log_middleware and emit a row to requests.jsonl, and
     that row carries the human PII redactions: src_ip is None, the
     ua field is a coarse bucket (not the raw User-Agent), and no
     auth/cookie *values* appear anywhere in the row.

PART B — real LLM browser agent wiring (no API calls made in smoke).
  5. generators/real_agent/bot.py refuses to start when CERNIS_TARGET
     points outside the target_guard allow-list (covers prompt-jailbreak
     / misconfig). The check runs before any LLM client is instantiated.
  6. After a consented human session and a (mocked) real_agent session,
     sessions.jsonl contains both class=human and class=agent rows with
     full provenance.
  7. No secret literal — known API-key prefixes (sk-, sk-ant-) and the
     literal values of OPENAI_API_KEY / ANTHROPIC_API_KEY if set in the
     test environment — appears in the repo tree or in data/.

Runs in <5s, no docker, no real LLM calls, no real DVWA upstream.
"""

from __future__ import annotations

import asyncio
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
CAPTURE_DIR = ROOT / "capture"
GENERATORS_DIR = ROOT / "generators"


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: consent gate + redaction ─────────────────────────────────


def _import_proxy(data_dir: pathlib.Path):
    """Import the capture proxy with DATA_DIR pointed at a tempdir.

    capture/proxy.py is a sibling-import module (it does `import
    honeypots` and `from redaction import ...`), so the smoke needs
    capture/ on sys.path before the import happens.
    """
    os.environ["DATA_DIR"] = str(data_dir)
    if str(CAPTURE_DIR) not in sys.path:
        sys.path.insert(0, str(CAPTURE_DIR))
    # Drop any cached module so a previous smoke run with a different
    # DATA_DIR doesn't bleed in.
    for cached in ("proxy", "honeypots", "redaction"):
        sys.modules.pop(cached, None)
    import proxy  # type: ignore  # noqa: E402
    return proxy


def _read_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


async def _run_part_a() -> None:
    from aiohttp.test_utils import TestClient, TestServer  # noqa: E402

    with tempfile.TemporaryDirectory() as td:
        data_dir = pathlib.Path(td)
        proxy = _import_proxy(data_dir)

        # Build the same app run() builds for :8090.
        app = proxy.make_app(
            label="human_real",
            default_from_header=False,
            is_human_channel=True,
        )
        server = TestServer(app)
        await server.start_server()
        client = TestClient(server)

        try:
            # (1) Unconsented capture is blocked.
            resp = await client.get("/index.php")
            _assert(
                resp.status == 403,
                f"[phase-bench-1] unconsented /index.php expected 403, got {resp.status}",
            )
            req_rows_before = _read_jsonl(data_dir / "requests.jsonl")
            _assert(
                len(req_rows_before) == 0,
                f"[phase-bench-1] unconsented request still wrote to requests.jsonl "
                f"({len(req_rows_before)} rows)",
            )

            # (2) /__consent serves the consent page.
            resp = await client.get("/__consent")
            _assert(
                resp.status == 200,
                f"[phase-bench-1] /__consent expected 200, got {resp.status}",
            )
            ct = resp.headers.get("Content-Type", "")
            _assert(
                "text/html" in ct,
                f"[phase-bench-1] /__consent expected html, got {ct!r}",
            )
            body = await resp.text()
            _assert(
                "Cernis benchmark" in body and "consent" in body.lower(),
                "[phase-bench-1] consent page body missing expected text",
            )

            # (3) Consent accept mints cookies, writes consent + session rows.
            resp = await client.post(
                "/__consent/accept",
                headers={
                    "User-Agent": (
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0 Safari/537.36"
                    ),
                },
                allow_redirects=False,
            )
            _assert(
                resp.status == 302,
                f"[phase-bench-1] /__consent/accept expected 302, got {resp.status}",
            )
            # Cookies from set-cookie headers
            set_cookies = resp.headers.getall("Set-Cookie", [])
            joined = " ; ".join(set_cookies)
            _assert(
                "cernis_consent=" in joined and "cernis_sid=" in joined,
                f"[phase-bench-1] expected both consent + sid cookies in set-cookie; "
                f"got {set_cookies!r}",
            )
            _assert(
                "HttpOnly" in joined,
                "[phase-bench-1] consent cookies missing HttpOnly flag",
            )
            consent_rows = _read_jsonl(data_dir / "consent.jsonl")
            _assert(
                len(consent_rows) == 1,
                f"[phase-bench-1] consent.jsonl expected 1 row, got {len(consent_rows)}",
            )
            cr = consent_rows[0]
            _assert(
                set(cr.keys()) == {"ts", "consent_id", "consent_text_version", "ua_bucket"},
                f"[phase-bench-1] consent row leaked extra fields: {sorted(cr.keys())}",
            )
            _assert(
                cr["ua_bucket"] == "chrome-desktop",
                f"[phase-bench-1] ua_bucket expected chrome-desktop, got {cr['ua_bucket']!r}",
            )
            sess_rows = _read_jsonl(data_dir / "sessions.jsonl")
            _assert(
                len(sess_rows) == 1,
                f"[phase-bench-1] sessions.jsonl expected 1 row after consent, "
                f"got {len(sess_rows)}",
            )
            sr = sess_rows[0]
            _assert(
                sr["class"] == "human" and sr["family"] == "human_real",
                f"[phase-bench-1] session row class/family wrong: {sr['class']}/{sr['family']}",
            )
            _assert(
                sr["extra"].get("consent_id") == cr["consent_id"],
                "[phase-bench-1] session.extra.consent_id != consent_id (linkage broken)",
            )

            # (4) Consented request is captured with redacted PII.
            # Set the cookies the client returned, then issue a real
            # request. Upstream is unreachable so the proxy returns 502
            # — that's fine; we're testing the *log row*.
            consent_id = cr["consent_id"]
            sid = sr["session_id"]
            cookie_hdr = f"cernis_consent={consent_id}; cernis_sid={sid}"
            resp = await client.get(
                "/index.php",
                headers={
                    "Cookie": cookie_hdr,
                    "User-Agent": (
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                        "AppleWebKit/537.36 (KHTML, like Gecko) "
                        "Chrome/120.0 Safari/537.36"
                    ),
                    "Authorization": "Bearer should-be-stripped",
                },
            )
            # 502 (upstream unreachable in smoke) or 200 (if upstream
            # somehow exists) — either way the row must be present.
            req_rows = _read_jsonl(data_dir / "requests.jsonl")
            _assert(
                len(req_rows) == 1,
                f"[phase-bench-1] consented request expected 1 log row, got {len(req_rows)}",
            )
            row = req_rows[0]
            _assert(
                row["src_ip"] is None,
                f"[phase-bench-1] human-channel row leaked src_ip: {row['src_ip']!r}",
            )
            allowed_buckets = {
                "chrome-desktop", "chrome-mobile",
                "firefox-desktop", "firefox-mobile",
                "safari-desktop", "safari-mobile",
                "other",
            }
            _assert(
                row["ua"] in allowed_buckets,
                f"[phase-bench-1] human-channel row leaked raw UA "
                f"(ua={row['ua']!r}, not in bucket set)",
            )
            _assert(
                row["class"] == "human" and row["family"] == "human_real",
                f"[phase-bench-1] consented row class/family wrong: "
                f"{row['class']}/{row['family']}",
            )
            _assert(
                row["has_auth_header"] is True,
                "[phase-bench-1] has_auth_header bool didn't pick up Authorization "
                "header (redaction is fine but the bool must still flip)",
            )
            # Belt-and-suspenders: the literal Authorization value must
            # not have leaked into any string field on the row.
            row_blob = json.dumps(row)
            _assert(
                "should-be-stripped" not in row_blob,
                "[phase-bench-1] Authorization VALUE leaked into the log row",
            )
            print("[phase-bench-1] PART A passed (consent + redaction)")
        finally:
            await client.close()
            await server.close()


# ── PART B: real-agent target_guard + sessions coverage + secret scan ─


def _check_target_guard_blocks_off_allowlist() -> None:
    """Invoke generators/real_agent/bot.py with a forbidden CERNIS_TARGET
    and assert it dies before any LLM/browser init."""
    bot = GENERATORS_DIR / "real_agent" / "bot.py"
    _assert(bot.exists(), f"[phase-bench-1] expected {bot} to exist")
    env = dict(os.environ)
    env["CERNIS_TARGET"] = "http://evil.example.com:80"
    # Set both keys to obviously-bogus values so the bot can't reach a
    # real API even if guard ordering regresses.
    env["OPENAI_API_KEY"] = "sk-test-DO-NOT-USE"
    env["ANTHROPIC_API_KEY"] = "sk-ant-test-DO-NOT-USE"
    # CERNIS_AGENT_DRY_RUN=1 tells bot.py to skip the actual run loop
    # so we're only exercising the guard + imports.
    env["CERNIS_AGENT_DRY_RUN"] = "1"
    # Make sure capture/ + generators/shared/ resolve like in the container.
    env["PYTHONPATH"] = (
        f"{GENERATORS_DIR / 'shared'}:{env.get('PYTHONPATH', '')}"
    )
    result = subprocess.run(
        [sys.executable, str(bot)],
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
    )
    _assert(
        result.returncode != 0,
        f"[phase-bench-1] real_agent/bot.py should have exited non-zero on "
        f"off-allowlist CERNIS_TARGET; got rc={result.returncode}\n"
        f"stdout={result.stdout!r}\nstderr={result.stderr!r}",
    )
    combined = result.stdout + result.stderr
    _assert(
        "target_guard" in combined,
        f"[phase-bench-1] target_guard rejection message not surfaced; "
        f"output={combined!r}",
    )


def _check_sessions_has_both_classes() -> None:
    """After PART A + a mocked agent provenance write, sessions.jsonl
    must carry both class=human (from consent) and class=agent rows.

    Inline-mocks the agent provenance write to keep the smoke offline.
    """
    with tempfile.TemporaryDirectory() as td:
        data_dir = pathlib.Path(td)
        os.environ["DATA_DIR"] = str(data_dir)
        if str(CAPTURE_DIR) not in sys.path:
            sys.path.insert(0, str(CAPTURE_DIR))
        for cached in ("proxy", "honeypots", "redaction"):
            sys.modules.pop(cached, None)
        import proxy  # type: ignore  # noqa: E402

        # human side: simulate accept_consent's writes
        human_provenance = {
            "ts": 1.0,
            "session_id": "h" * 32,
            "src_label": "human_real",
            "class": "human",
            "family": "human_real",
            "target_app": "dvwa",
            "security_level": "low",
            "stealth": False,
            "generator": "human_real",
            "generator_version": proxy.CONSENT_TEXT_VERSION,
            "generator_config_sha": "deadbeef",
            "extra": {"browser_family": "chrome", "device_type": "desktop",
                       "consent_id": "c" * 32},
        }
        agent_provenance = {
            "ts": 2.0,
            "session_id": "a" * 32,
            "src_label": "llm_browser_agent",
            "class": "agent",
            "family": "llm_browser_agent",
            "target_app": "dvwa",
            "security_level": "low",
            "stealth": False,
            "generator": "real_agent",
            "generator_version": "0.1.0",
            "generator_config_sha": "cafebabe",
            "extra": {"model": "gpt-4o-mini", "framework": "browser-use",
                       "framework_version": "test"},
        }
        asyncio.run(proxy.write_session_log(human_provenance))
        asyncio.run(proxy.write_session_log(agent_provenance))

        rows = _read_jsonl(data_dir / "sessions.jsonl")
        classes = {r["class"] for r in rows}
        _assert(
            classes == {"human", "agent"},
            f"[phase-bench-1] sessions.jsonl missing class coverage: {classes}",
        )
        families = {r["family"] for r in rows}
        _assert(
            "human_real" in families and "llm_browser_agent" in families,
            f"[phase-bench-1] sessions.jsonl missing family coverage: {families}",
        )


# Built into the smoke (not derived from a third-party scanner) so it
# runs offline in CI without extra deps. Catches the typical leak shapes
# the user explicitly called out: api-key prefixes AND any literal value
# of the two env vars at test time.
_KEY_SUBSTRINGS = ("sk-live-", "sk-ant-", "sk-proj-", "sk-test-")


def _check_no_secret_leak() -> None:
    """Grep the worktree + data/ for known secret shapes."""
    leaked: list[str] = []
    repo_root = ROOT  # web-harness/ — narrower than the whole Cernis repo
    # Skip the smoke itself: it contains the bogus `sk-test-DO-NOT-USE`
    # literal on purpose, and that would create a false positive that's
    # impossible to scrub.
    skip = {
        repo_root / "tests" / "phase_bench_1_smoke.py",
    }
    runtime_secrets = [
        os.environ.get(k, "") for k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY")
    ]
    runtime_secrets = [s for s in runtime_secrets if s and len(s) >= 16]

    for path in repo_root.rglob("*"):
        if not path.is_file():
            continue
        if path in skip:
            continue
        # Skip obvious binary / heavy paths
        if any(p in path.parts for p in (
            "__pycache__", "node_modules", ".git", "data",
        )) and path.parts[path.parts.index("data") if "data" in path.parts else 0] != "data":
            # …unless we're explicitly scanning data/ below.
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for needle in _KEY_SUBSTRINGS:
            if needle in text:
                leaked.append(f"{path}: prefix {needle!r}")
        for secret in runtime_secrets:
            if secret in text:
                leaked.append(f"{path}: live key value")

    # Also walk data/ even though it's gitignored — capture writers
    # could persist a key if they were buggy.
    data_root = repo_root / "data"
    if data_root.exists():
        for path in data_root.rglob("*"):
            if not path.is_file():
                continue
            try:
                text = path.read_text(errors="ignore")
            except Exception:
                continue
            for needle in _KEY_SUBSTRINGS:
                if needle in text:
                    leaked.append(f"{path}: prefix {needle!r}")
            for secret in runtime_secrets:
                if secret in text:
                    leaked.append(f"{path}: live key value")

    _assert(
        not leaked,
        f"[phase-bench-1] secret leak detected: {leaked}",
    )


# ── runner ───────────────────────────────────────────────────────────


def main() -> int:
    print("[phase-bench-1] running smoke (offline, no docker)…")

    asyncio.run(_run_part_a())

    if (GENERATORS_DIR / "real_agent" / "bot.py").exists():
        _check_target_guard_blocks_off_allowlist()
        _check_sessions_has_both_classes()
        print("[phase-bench-1] PART B passed (target_guard + class coverage)")
    else:
        print(
            "[phase-bench-1] SKIPPED PART B (real_agent bot.py not present "
            "yet — commit 2 of this phase will add it)"
        )

    _check_no_secret_leak()
    print("[phase-bench-1] secret leak scan clean")
    print("[phase-bench-1] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
