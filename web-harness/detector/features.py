"""Feature extraction for the ALLM web detector.

Loads three JSONL files from `--data`:
  requests.jsonl   one row per HTTP request through the capture proxy
  beacons.jsonl    one row per JS beacon callback (proves JS ran + cadence)
  honeypots.jsonl  one row per honeypot trip

Groups by session_id and emits, per session:
  seq[T, F_req]   per-request features in chronological order
  agg[F_sess]     session aggregates
  hp[F_hp]        binary honeypot flags
  y               1 if src_label in AGENT_LABELS else 0
  session_id, src_label, duration_s   (carried for eval / GroupShuffleSplit)

Normalization fits on a train subset (`fit_aggregate_scaler`) and applies
the same mean/std to val and test — never the other way round.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import pathlib
from typing import Iterable

import numpy as np

# Agent and benign-bot family labels.
#
# `AGENT_LABELS` is the legacy hardcoded set used to derive `y` for rows
# from phases 1-5 (pre-phase-6 data has no `class` column). Phase 7
# generators (sqlmap / selenium_bot / puppeteer_bot) are listed here too
# so eval still computes y correctly even if the proxy somehow dropped
# the X-Allm-Class header.
AGENT_LABELS = frozenset({
    "playwright_bot", "pentesterpro",
    "sqlmap", "selenium_bot", "puppeteer_bot",
})
BENIGN_BOT_LABELS = frozenset({
    "googlebot", "uptime_monitor", "rss_reader",
    "link_unfurler", "ci_health_check",
})
HUMAN_LABELS = frozenset({"human_sim", "human_real"})

HONEYPOT_NAMES = ("canary", "invisible_field", "admin_secrets", "robots_read")


def derive_class_from_label(src_label: str) -> str:
    """Legacy mapping for rows that pre-date the X-Allm-Class header."""
    if src_label in AGENT_LABELS:
        return "agent"
    if src_label in BENIGN_BOT_LABELS:
        return "benign_bot"
    if src_label in HUMAN_LABELS:
        return "human"
    return "unknown"

F_REQ = 9
F_SESS = 12
F_HP = len(HONEYPOT_NAMES)


@dataclasses.dataclass
class Session:
    session_id: str
    src_label: str
    seq: np.ndarray  # [T, F_REQ]
    agg: np.ndarray  # [F_SESS]
    hp: np.ndarray  # [F_HP]
    y: int
    duration_s: float
    ts_start: float
    n_req: int
    # phase 6+ label-schema fields. Resolved at build time from row
    # columns; for pre-phase-6 rows these are derived from src_label via
    # derive_class_from_label() so eval code doesn't need per-row guards.
    klass: str = "unknown"
    family: str = ""
    target_app: str = "dvwa"


def _safe_log1p(x: float) -> float:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return 0.0
    return math.log1p(max(0.0, float(x)))


def _path_bucket(path: str, n: int = 16) -> float:
    h = hashlib.blake2b(path.encode("utf-8"), digest_size=4).digest()
    return (int.from_bytes(h, "big") % n) / n


def _header_hash_norm(hh: str | None) -> float:
    if not hh:
        return 0.0
    try:
        return int(hh, 16) / (16 ** 8)
    except ValueError:
        return 0.0


def _ua_bucket(ua: str) -> float:
    if not ua:
        return 0.0
    if "Chrome" in ua or "Chromium" in ua:
        return 1.0
    if "Mozilla" in ua:
        return 0.6
    if "curl" in ua or "python" in ua.lower() or "wget" in ua:
        return 0.3
    return 0.1


def _req_features(row: dict) -> list[float]:
    return [
        _safe_log1p(row.get("delta_ms")),
        (row.get("status") or 0) / 100.0,
        1.0 if row.get("method") == "POST" else 0.0,
        _path_bucket(row.get("path", "")),
        _safe_log1p(row.get("req_bytes")),
        _safe_log1p(row.get("resp_bytes")),
        _ua_bucket(row.get("ua", "")),
        _safe_log1p(row.get("header_count")),
        _header_hash_norm(row.get("header_hash")),
    ]


def _agg_features(
    reqs: list[dict], beacons: list[dict]
) -> tuple[np.ndarray, float, float]:
    deltas = [r["delta_ms"] for r in reqs if r.get("delta_ms") is not None]
    statuses = [r.get("status") or 0 for r in reqs]
    paths = {r.get("path", "") for r in reqs}
    ts = [r["ts"] for r in reqs]
    duration = max(ts) - min(ts) if ts else 0.0

    # max_rps over a 1 second sliding window
    if len(ts) >= 2:
        ts_sorted = sorted(ts)
        max_rps = 0
        for i in range(len(ts_sorted)):
            j = i
            while j < len(ts_sorted) and ts_sorted[j] - ts_sorted[i] <= 1.0:
                j += 1
            max_rps = max(max_rps, j - i)
        max_rps_v = float(max_rps)
    else:
        max_rps_v = float(len(ts))

    delta_mean = float(np.mean(deltas)) if deltas else 0.0
    delta_std = float(np.std(deltas)) if deltas else 0.0
    delta_p95 = float(np.percentile(deltas, 95)) if deltas else 0.0
    frac_4xx = sum(1 for s in statuses if 400 <= s < 500) / max(1, len(statuses))
    frac_5xx = sum(1 for s in statuses if 500 <= s < 600) / max(1, len(statuses))

    js_ran = 1.0 if beacons else 0.0
    ttfi = 0.0
    dom_read = 0.0
    if beacons:
        ready = [b for b in beacons if b.get("event", {}).get("type") == "ready"]
        loaded = [b for b in beacons if b.get("event", {}).get("type") == "loaded"]
        if loaded:
            ttfi = float(loaded[0].get("event", {}).get("ttfi_candidate", 0.0) or 0.0)
        if ready and loaded:
            dom_read = max(
                0.0,
                float(loaded[0].get("event", {}).get("t", 0.0) or 0.0)
                - float(ready[0].get("event", {}).get("t", 0.0) or 0.0),
            )

    agg = np.array(
        [
            _safe_log1p(len(reqs)),
            _safe_log1p(delta_mean),
            _safe_log1p(delta_std),
            _safe_log1p(delta_p95),
            _safe_log1p(len(paths)),
            frac_4xx,
            frac_5xx,
            max_rps_v,
            js_ran,
            _safe_log1p(ttfi),
            _safe_log1p(dom_read),
            _safe_log1p(duration * 1000.0),
        ],
        dtype=np.float32,
    )
    return agg, duration, (ts[0] if ts else 0.0)


def _hp_features(trips: list[dict]) -> np.ndarray:
    flags = {name: 0.0 for name in HONEYPOT_NAMES}
    for t in trips:
        name = t.get("honeypot")
        if name in flags:
            flags[name] = 1.0
    return np.array([flags[n] for n in HONEYPOT_NAMES], dtype=np.float32)


def load_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _majority_str(values) -> str:
    """Most-common non-empty value, "" if there isn't one."""
    counts: dict[str, int] = {}
    for v in values:
        if v:
            counts[v] = counts.get(v, 0) + 1
    if not counts:
        return ""
    return max(counts.items(), key=lambda kv: kv[1])[0]


def build_sessions(data_dir: pathlib.Path, min_requests: int = 3) -> list[Session]:
    reqs = load_jsonl(data_dir / "requests.jsonl")
    beacons = load_jsonl(data_dir / "beacons.jsonl")
    trips = load_jsonl(data_dir / "honeypots.jsonl")
    sess_meta = load_jsonl(data_dir / "sessions.jsonl")

    by_sid_reqs: dict[str, list[dict]] = {}
    by_sid_bcn: dict[str, list[dict]] = {}
    by_sid_trip: dict[str, list[dict]] = {}
    sid_label: dict[str, str] = {}

    for r in reqs:
        sid = r.get("session_id")
        if not sid:
            continue
        by_sid_reqs.setdefault(sid, []).append(r)
        if r.get("src_label"):
            sid_label[sid] = r["src_label"]
    for b in beacons:
        sid = b.get("session_id")
        if sid:
            by_sid_bcn.setdefault(sid, []).append(b)
    for t in trips:
        sid = t.get("session_id")
        if sid:
            by_sid_trip.setdefault(sid, []).append(t)
            sid_label.setdefault(sid, t.get("src_label", "unknown"))

    # sessions.jsonl is the authoritative source for the new label
    # schema when present. Latest row per session_id wins (the proxy
    # currently writes once per session, but be defensive).
    sid_meta: dict[str, dict] = {}
    for row in sess_meta:
        sid = row.get("session_id")
        if sid:
            sid_meta[sid] = row

    sessions: list[Session] = []
    for sid, rs in by_sid_reqs.items():
        if len(rs) < min_requests:
            continue
        rs.sort(key=lambda r: r.get("ts", 0.0))
        seq = np.array([_req_features(r) for r in rs], dtype=np.float32)
        agg, dur, ts0 = _agg_features(rs, by_sid_bcn.get(sid, []))
        hp = _hp_features(by_sid_trip.get(sid, []))
        label = sid_label.get(sid, "unknown")

        # Resolve the new label schema. Priority:
        #   1. sessions.jsonl row (phase 6+ provenance manifest).
        #   2. Majority value across the session's request rows
        #      (phase 6+ requests.jsonl rows carry class/family/etc).
        #   3. Legacy derivation from src_label.
        meta = sid_meta.get(sid)
        klass = ""
        family = ""
        target_app = ""
        if meta:
            klass = meta.get("class", "") or ""
            family = meta.get("family", "") or ""
            target_app = meta.get("target_app", "") or ""
        if not klass:
            klass = _majority_str(r.get("class") for r in rs)
        if not family:
            family = _majority_str(r.get("family") for r in rs)
        if not target_app:
            target_app = _majority_str(r.get("target_app") for r in rs)
        if not klass:
            klass = derive_class_from_label(label)
        if not family:
            family = label
        if not target_app:
            target_app = "dvwa"

        y = 1 if klass == "agent" else 0
        sessions.append(
            Session(
                session_id=sid,
                src_label=label,
                seq=seq,
                agg=agg,
                hp=hp,
                y=y,
                duration_s=dur,
                ts_start=ts0,
                n_req=len(rs),
                klass=klass,
                family=family,
                target_app=target_app,
            )
        )
    sessions.sort(key=lambda s: s.ts_start)
    return sessions


def fit_aggregate_scaler(sessions: Iterable[Session]) -> tuple[np.ndarray, np.ndarray]:
    aggs = np.stack([s.agg for s in sessions], axis=0)
    mean = aggs.mean(axis=0)
    std = aggs.std(axis=0)
    std = np.where(std < 1e-6, 1.0, std)
    return mean.astype(np.float32), std.astype(np.float32)


def apply_aggregate_scaler(
    sessions: list[Session], mean: np.ndarray, std: np.ndarray
) -> list[Session]:
    scaled = []
    for s in sessions:
        new = dataclasses.replace(s, agg=((s.agg - mean) / std).astype(np.float32))
        scaled.append(new)
    return scaled


def label_counts(sessions: list[Session]) -> dict:
    out: dict[str, int] = {}
    for s in sessions:
        out[s.src_label] = out.get(s.src_label, 0) + 1
    return out
