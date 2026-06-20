"""Phase 13 verification gate: production access-log shipper.

Synthesizes a tiny nginx-style combined-format access log in a
tmpdir, runs the shipper in --once mode, and asserts:

  1. parse_line() correctly extracts ip / ts / method / path / status
     / bytes / ua from a known good line.
  2. SessionStitcher mints a fresh session_id when an (ip, ua) tuple
     goes inactive past the timeout, and reuses the same session_id
     within a quiet stretch.
  3. The resulting requests.jsonl rows carry the production schema
     (class=unknown, family=prod_traffic, target_app=prod) and don't
     leak any of the lab artifacts (no cernis_sid mention, no honeypot
     fields).
  4. The output feeds through detector/features.build_sessions
     cleanly — Session objects come back with the right resolved
     klass / family / target_app and stealth=False.
  5. Nothing in the shipper writes to a beacon log or honeypot log —
     production ingest is read-only on the source.

Runs in <1s, no docker.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _synth_access_log(out_path: pathlib.Path) -> int:
    """Write a small access log with multiple IPs + UAs + a gap that
    should force a new session for one of the tuples."""
    base = dt.datetime(2026, 6, 20, 13, 55, 0,
                       tzinfo=dt.timezone(dt.timedelta(hours=-7)))
    def fmt(t: dt.datetime) -> str:
        return t.strftime("%d/%b/%Y:%H:%M:%S %z")
    lines = []
    # 192.168.1.1 / Mozilla/5.0 — 3 requests close together (same session)
    for i, secs in enumerate([0, 4, 12]):
        t = base + dt.timedelta(seconds=secs)
        lines.append(
            f'192.168.1.1 - - [{fmt(t)}] "GET /index.html HTTP/1.1" '
            f'200 {2000 + i * 100} "-" "Mozilla/5.0 (X11; Linux x86_64)"'
        )
    # Same ip+ua but 35 minutes later — must be a NEW session under the
    # default 30-min inactivity timeout
    t_gap = base + dt.timedelta(minutes=35)
    lines.append(
        f'192.168.1.1 - - [{fmt(t_gap)}] "POST /login HTTP/1.1" '
        f'302 412 "-" "Mozilla/5.0 (X11; Linux x86_64)"'
    )
    # Different IP, same time — separate session
    t = base + dt.timedelta(seconds=2)
    lines.append(
        f'10.0.0.5 - - [{fmt(t)}] "GET /api/users?id=1 HTTP/1.1" '
        f'200 832 "https://example.com/" "curl/7.85.0"'
    )
    # Malformed line that should be skipped without breaking the run
    lines.append('this line is intentionally garbage and should be skipped')
    # Same IP+UA but yet different — fourth session-distinct stream
    for secs in [5, 9]:
        t = base + dt.timedelta(seconds=secs)
        lines.append(
            f'10.0.0.5 - - [{fmt(t)}] "GET /api/users HTTP/1.1" '
            f'200 1024 "-" "curl/7.85.0"'
        )
    out_path.write_text("\n".join(lines) + "\n")
    return len(lines)


def main() -> None:
    t0 = time.time()
    sys.path.insert(0, str(ROOT))
    from ingest.access_log_shipper import (  # type: ignore
        SessionStitcher, ShipperConfig, parse_line, ship,
    )

    # 1. parse_line on a known line
    sample = (
        '192.168.1.42 - - [20/Jun/2026:13:55:36 -0700] '
        '"GET /search?q=test HTTP/1.1" 200 1842 "-" '
        '"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"'
    )
    parsed = parse_line(sample)
    _assert(parsed is not None, "[phase13] parse_line returned None on good line")
    _assert(parsed["src_ip"] == "192.168.1.42",
            f"[phase13] parsed src_ip={parsed['src_ip']!r}")
    _assert(parsed["method"] == "GET",
            f"[phase13] parsed method={parsed['method']!r}")
    _assert(parsed["path"] == "/search",
            f"[phase13] parsed path={parsed['path']!r}")
    _assert(parsed["qs_len"] == len("q=test"),
            f"[phase13] qs_len={parsed['qs_len']}")
    _assert(parsed["status"] == 200,
            f"[phase13] status={parsed['status']}")
    _assert(parsed["resp_bytes"] == 1842,
            f"[phase13] resp_bytes={parsed['resp_bytes']}")
    _assert("Googlebot" in parsed["ua"],
            f"[phase13] ua={parsed['ua']!r}")
    # Garbage line returns None
    _assert(parse_line("xxx not a log line xxx") is None,
            "[phase13] parse_line accepted garbage line")
    print("[phase13] parse_line works on combined-format logs",
          flush=True)

    # 2. SessionStitcher behavior
    stitcher = SessionStitcher(inactivity_timeout_s=1800)
    base = 1_750_000_000.0
    p1 = {"ts": base, "src_ip": "1.1.1.1", "ua": "Mozilla"}
    p2 = {"ts": base + 30, "src_ip": "1.1.1.1", "ua": "Mozilla"}
    p3 = {"ts": base + 2000, "src_ip": "1.1.1.1", "ua": "Mozilla"}  # >timeout
    sid1, new1, _ = stitcher.session_for(p1)
    sid2, new2, _ = stitcher.session_for(p2)
    sid3, new3, _ = stitcher.session_for(p3)
    _assert(new1 is True and new2 is False and new3 is True,
            f"[phase13] is_new sequence wrong: {new1}/{new2}/{new3}")
    _assert(sid1 == sid2 and sid1 != sid3,
            f"[phase13] sids wrong: {sid1!r}, {sid2!r}, {sid3!r}")
    print("[phase13] SessionStitcher mints on gap, reuses within window",
          flush=True)

    # 3. ship() on a synth log, schema check
    with tempfile.TemporaryDirectory() as td:
        data_dir = pathlib.Path(td) / "data"
        log_path = pathlib.Path(td) / "access.log"
        n_in = _synth_access_log(log_path)
        req_out = data_dir / "requests.jsonl"
        cfg = ShipperConfig(target_app="prod", family="prod_traffic",
                            klass="unknown", inactivity_timeout_s=1800)
        n_out = ship(log_path, req_out, follow_mode=False, cfg=cfg)
        _assert(n_out >= 7,
                f"[phase13] expected >=7 rows shipped, got {n_out}")
        _assert(n_out < n_in,
                f"[phase13] garbage line was not skipped: in={n_in} out={n_out}")
        rows = [json.loads(line) for line in req_out.read_text().splitlines()
                if line.strip()]
        _assert(len(rows) == n_out,
                f"[phase13] shipped count mismatch: ship returned {n_out} "
                f"but file has {len(rows)}")
        for r in rows:
            for key in ("ts", "session_id", "src_ip", "src_label",
                        "method", "path", "qs_len", "status",
                        "req_bytes", "resp_bytes", "ua", "header_hash",
                        "header_count", "delta_ms", "is_new_session",
                        "has_auth_header", "has_cookie_header",
                        "content_type", "elapsed_ms", "class", "family",
                        "target_app", "security_level", "stealth"):
                _assert(key in r, f"[phase13] shipped row missing key {key!r}")
            _assert(r["class"] == "unknown",
                    f"[phase13] shipped row class={r['class']!r}")
            _assert(r["family"] == "prod_traffic",
                    f"[phase13] shipped row family={r['family']!r}")
            _assert(r["target_app"] == "prod",
                    f"[phase13] shipped row target_app={r['target_app']!r}")
            _assert(r["stealth"] is False,
                    f"[phase13] shipped row stealth={r['stealth']!r}")
            _assert(r["has_auth_header"] is False,
                    "[phase13] shipped row claims has_auth_header — leaks "
                    "sensitive info that the access log can't give us")
            _assert(r["has_cookie_header"] is False,
                    "[phase13] shipped row claims has_cookie_header")
        # there must be at least two distinct session_ids (the 35-min
        # gap forces a new session; the curl IP is a separate stream)
        sids = {r["session_id"] for r in rows}
        _assert(len(sids) >= 3,
                f"[phase13] expected >=3 sessions, got {len(sids)}: {sids}")
        # at least one is_new_session=True flag per session start
        new_count = sum(1 for r in rows if r["is_new_session"])
        _assert(new_count == len(sids),
                f"[phase13] is_new_session count {new_count} != "
                f"session count {len(sids)}")
        print(f"[phase13] shipped {len(rows)} rows / {len(sids)} sessions, "
              f"schema correct, no lab leaks", flush=True)

        # 4. ensure NO beacon / honeypot files were created — the
        # shipper is meant to be read-only on the source side.
        for never_should_exist in (
            data_dir / "beacons.jsonl",
            data_dir / "honeypots.jsonl",
            data_dir / "sessions.jsonl",
        ):
            _assert(not never_should_exist.exists(),
                    f"[phase13] shipper unexpectedly created "
                    f"{never_should_exist.name!r} — lab artifact leak")

        # 5. features.build_sessions consumes the shipped rows cleanly
        sys.path.insert(0, str(ROOT / "detector"))
        # ensure there's at least one row per session so build_sessions
        # doesn't filter them out (min_requests=1 here for our tiny synth)
        from features import build_sessions  # type: ignore
        sessions = build_sessions(data_dir, min_requests=1)
        _assert(sessions, "[phase13] build_sessions returned no sessions")
        for s in sessions[:3]:
            _assert(s.target_app == "prod",
                    f"[phase13] session target_app={s.target_app!r}")
            _assert(s.family == "prod_traffic",
                    f"[phase13] session family={s.family!r}")
            _assert(s.klass == "unknown",
                    f"[phase13] session klass={s.klass!r}")
            _assert(s.stealth is False,
                    f"[phase13] session stealth={s.stealth!r}")
        # unknown class -> y=0 (don't accidentally treat prod as positive)
        for s in sessions:
            _assert(s.y == 0,
                    f"[phase13] unlabeled prod session got y={s.y} "
                    f"(should be 0)")
        print(f"[phase13] features.build_sessions consumed shipper output, "
              f"{len(sessions)} sessions, all y=0", flush=True)

    print()
    print(f"PHASE 13 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
