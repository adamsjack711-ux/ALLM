"""Passive nginx / Apache access-log shipper.

Production ingest for the web detector. Reads a standard "combined"
access log (the default nginx format and Apache's `combined` LogFormat)
and emits the same `requests.jsonl` schema the lab capture proxy
writes — so a model trained on lab data can be pointed at production
traffic without further plumbing.

What this DOES NOT do (load-bearing for "safe for prod"):
  - NO reverse-proxy injection — we read existing logs, we don't sit
    in the request path.
  - NO honeypot injection — `/__canary` / invisible fields / hidden DOM
    notices belong in the lab, not on a live site.
  - NO JS beacon — we never modify response bodies.
  - NO cookie minting — the lab's `cernis_sid` cookie is a lab artifact;
    real users have their own session cookies, untouched.
  - NO authorization-header capture — the shipper reads the access log
    only, never the request body or any sensitive header values.

Session synthesis: an access log has no session_id. We key sessions on
(src_ip, sha1(user_agent)[:8]) with a 30-minute inactivity timeout —
when a (ip, ua) tuple goes quiet for >30 min, the next request starts
a fresh session_id. This is a heuristic; production deployments with
real session cookies should override `synthesize_session_id`.

Fields the access log can't give us (req_bytes, header_count,
content_type, has_cookie_header, etc.) get safe defaults that the
detector's features.py already tolerates — `_safe_log1p(None)` returns
0.0 and the ML-only head ignores honeypot inputs entirely. Detection
quality is reduced versus a fully instrumented session (no beacon
features, no honeypot signal) but the cadence / sequence / path /
status features still carry signal.

Two modes:
  --once    : parse the file end-to-end and exit. For backfill.
  --follow  : tail the file in real time, polling for new content
              every `--poll-interval-s` seconds. For ongoing ingest.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
import time
from typing import Iterator, Optional

# Combined log format:
#   $remote_addr - $remote_user [$time_local] "$request" $status
#   $body_bytes_sent "$http_referer" "$http_user_agent"
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)(?:\s+(?P<proto>\S+))?"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<bytes>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<ua>[^"]*)"'
)

_DEFAULT_INACTIVITY_S = 1800  # 30 minutes


@dataclasses.dataclass
class ShipperConfig:
    target_app: str = "prod"        # tags the rows so eval can slice prod vs lab
    family: str = "prod_traffic"    # src_label + family value
    klass: str = "unknown"          # never claim agent/benign for unlabeled prod
    inactivity_timeout_s: int = _DEFAULT_INACTIVITY_S
    truncate_ua_to: int = 300       # safety bound for UA size in logs


def _parse_timestamp(s: str) -> Optional[float]:
    """Parse the combined-format timestamp `10/Oct/2000:13:55:36 -0700` to
    unix seconds."""
    try:
        # %z handles the trailing tz offset
        return dt.datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except ValueError:
        return None


def _parse_int(s: str, default: int = 0) -> int:
    if s == "-" or not s:
        return default
    try:
        return int(s)
    except ValueError:
        return default


def parse_line(line: str) -> Optional[dict]:
    """Parse a single combined-format access-log line into a dict, or
    None if the line doesn't match. Lines that fail to parse are
    skipped — production logs sometimes have weird embedded
    newlines, log-rotation status lines, etc."""
    line = line.rstrip("\r\n")
    if not line:
        return None
    m = _COMBINED_RE.match(line)
    if not m:
        return None
    ts = _parse_timestamp(m.group("ts"))
    if ts is None:
        return None
    path = m.group("path") or "/"
    if "?" in path:
        bare_path, qs = path.split("?", 1)
        qs_len = len(qs)
    else:
        bare_path, qs_len = path, 0
    return {
        "ts": ts,
        "src_ip": m.group("ip"),
        "method": m.group("method"),
        "path": bare_path,
        "qs_len": qs_len,
        "status": _parse_int(m.group("status")),
        "resp_bytes": _parse_int(m.group("bytes")),
        "ua": m.group("ua") or "",
        "referer": m.group("referer") or "",
    }


def _ua_bucket_hash(ua: str) -> str:
    return hashlib.sha1(ua.encode("utf-8")).hexdigest()[:8]


def _header_hash_for_parsed(parsed: dict) -> str:
    """Derive a stable header hash from what the access log gives us.

    We don't have the actual header set, so we hash the small set of
    fields we *can* observe: UA bucket + a normalized referer host.
    Same shape (8 hex chars) as the lab proxy's `safe_header_set`.
    """
    bits = (
        _ua_bucket_hash(parsed["ua"]),
        parsed["referer"][:80],
    )
    return hashlib.sha1("|".join(bits).encode()).hexdigest()[:8]


class SessionStitcher:
    """Synthesize session_ids from a stream of parsed log rows.

    Key = (src_ip, sha1(ua)[:8]). If a key goes inactive for more than
    `inactivity_timeout_s` seconds, a new session_id is minted on the
    next sighting. Otherwise the prior session_id is reused.
    """

    def __init__(self, inactivity_timeout_s: int = _DEFAULT_INACTIVITY_S):
        self.inactivity_timeout_s = inactivity_timeout_s
        # key -> (session_id, last_ts, is_new_flag_pending)
        self._state: dict[tuple[str, str], tuple[str, float, bool]] = {}

    def session_for(self, parsed: dict) -> tuple[str, bool, Optional[int]]:
        """Return (session_id, is_new_session, delta_ms_or_none)."""
        ts = parsed["ts"]
        key = (parsed["src_ip"], _ua_bucket_hash(parsed["ua"]))
        prior = self._state.get(key)
        if prior is None or (ts - prior[1]) > self.inactivity_timeout_s:
            sid = hashlib.sha1(
                f"{key[0]}|{key[1]}|{ts:.0f}".encode()
            ).hexdigest()[:24]
            self._state[key] = (sid, ts, False)
            return sid, True, None
        sid, last_ts, _ = prior
        delta_ms = int(max(0.0, ts - last_ts) * 1000)
        self._state[key] = (sid, ts, False)
        return sid, False, delta_ms


def to_request_row(
    parsed: dict, sid: str, is_new: bool, delta_ms: Optional[int],
    cfg: ShipperConfig,
) -> dict:
    """Convert a parsed access-log row into the requests.jsonl schema."""
    return {
        "ts": parsed["ts"],
        "session_id": sid,
        "src_ip": parsed["src_ip"],
        "src_label": cfg.family,
        "method": parsed["method"],
        "path": parsed["path"],
        "qs_len": parsed["qs_len"],
        "status": parsed["status"],
        # access log doesn't carry request body size — leave 0
        "req_bytes": 0,
        "resp_bytes": parsed["resp_bytes"],
        "ua": (parsed["ua"] or "")[: cfg.truncate_ua_to],
        "header_hash": _header_hash_for_parsed(parsed),
        # Heuristic. Real headers we don't know.
        "header_count": 0,
        "delta_ms": delta_ms,
        "is_new_session": is_new,
        "has_auth_header": False,
        "has_cookie_header": False,
        "content_type": "",
        # access log doesn't carry per-request server time unless the
        # admin added $request_time. Leave 0.
        "elapsed_ms": 0,
        "class": cfg.klass,
        "family": cfg.family,
        "target_app": cfg.target_app,
        "security_level": "na",
        "stealth": False,
    }


def iter_log_once(path: pathlib.Path) -> Iterator[str]:
    """Iterate the file line by line, then close."""
    with path.open("r", errors="replace") as f:
        for line in f:
            yield line


def follow(path: pathlib.Path, poll_interval_s: float = 1.0) -> Iterator[str]:
    """Tail the file, yielding new lines as they appear.

    Uses polling rather than inotify so it works on macOS / Linux /
    containers identically. The 1s default poll cadence is more than
    enough for the detector's session-level scoring.
    """
    with path.open("r", errors="replace") as f:
        f.seek(0, 2)  # end of file
        while True:
            line = f.readline()
            if line:
                yield line
                continue
            time.sleep(poll_interval_s)


def ship(
    log_path: pathlib.Path,
    out_requests: pathlib.Path,
    *,
    follow_mode: bool,
    cfg: Optional[ShipperConfig] = None,
    poll_interval_s: float = 1.0,
    flush_every_n: int = 100,
) -> int:
    cfg = cfg or ShipperConfig()
    stitcher = SessionStitcher(inactivity_timeout_s=cfg.inactivity_timeout_s)
    out_requests.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    pending = 0
    out = out_requests.open("a")
    lines = follow(log_path, poll_interval_s) if follow_mode else iter_log_once(log_path)
    try:
        for line in lines:
            parsed = parse_line(line)
            if parsed is None:
                continue
            sid, is_new, delta_ms = stitcher.session_for(parsed)
            row = to_request_row(parsed, sid, is_new, delta_ms, cfg)
            out.write(json.dumps(row, separators=(",", ":")) + "\n")
            n += 1
            pending += 1
            if pending >= flush_every_n:
                out.flush()
                pending = 0
    finally:
        out.close()
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", type=pathlib.Path, required=True,
                    help="path to nginx / Apache combined access log")
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/requests.jsonl"),
                    help="where to append the requests.jsonl rows")
    ap.add_argument("--once", action="store_true",
                    help="process the file end-to-end and exit (default mode)")
    ap.add_argument("--follow", action="store_true",
                    help="tail the file in real time")
    ap.add_argument("--target-app", default="prod",
                    help="tags requests rows with this target_app value")
    ap.add_argument("--family", default="prod_traffic",
                    help="src_label + family value on every row")
    ap.add_argument("--klass", default="unknown",
                    choices=("unknown", "agent", "human", "benign_bot"),
                    help="class for the rows. Defaults to unknown — set to "
                         "human if you're shipping a known-benign segment.")
    ap.add_argument("--inactivity-timeout-s", type=int, default=_DEFAULT_INACTIVITY_S)
    ap.add_argument("--poll-interval-s", type=float, default=1.0)
    args = ap.parse_args(argv)

    if args.follow and args.once:
        ap.error("--once and --follow are mutually exclusive")
    follow_mode = args.follow
    if not args.follow and not args.once:
        # backfill is the safer default
        follow_mode = False

    cfg = ShipperConfig(
        target_app=args.target_app,
        family=args.family,
        klass=args.klass,
        inactivity_timeout_s=args.inactivity_timeout_s,
    )
    print(f"[shipper] log={args.log} out={args.out} "
          f"mode={'follow' if follow_mode else 'once'} "
          f"target_app={cfg.target_app}", flush=True)
    n = ship(args.log, args.out,
             follow_mode=follow_mode, cfg=cfg,
             poll_interval_s=args.poll_interval_s)
    print(f"[shipper] processed {n:,} rows -> {args.out}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
