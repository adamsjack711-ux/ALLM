"""phase-bench-1 sanity printout — no detector, no pass/fail.

After a consented human session and a real_agent session land in
data/requests.jsonl + data/sessions.jsonl, this script prints two
things you can eyeball:

  1. Session counts per (class, family) — sanity that both channels
     produced rows with the expected labels.
  2. A crude human-vs-agent comparison on cadence (median delta_ms
     between requests within a session) and beacon presence (was a
     /__beacon ping recorded for this session_id at all?).

Run:
    python3 web-harness/scripts/phase_bench_1_summary.py [DATA_DIR]

DATA_DIR defaults to web-harness/data/.
"""

from __future__ import annotations

import collections
import json
import pathlib
import statistics
import sys


def _read_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _class_family_counts(sessions: list[dict]) -> dict[tuple[str, str], int]:
    cnt: collections.Counter[tuple[str, str]] = collections.Counter()
    for s in sessions:
        cnt[(s.get("class", "?"), s.get("family", "?"))] += 1
    return dict(cnt)


def _per_session_features(
    requests: list[dict], beacons: list[dict]
) -> dict[str, dict[str, float | int | bool]]:
    """Aggregate per-session: median delta_ms + did this session emit
    any /__beacon ping at all."""
    deltas: dict[str, list[int]] = collections.defaultdict(list)
    counts: dict[str, int] = collections.Counter()
    has_beacon: set[str] = set()
    sess_class: dict[str, str] = {}
    sess_family: dict[str, str] = {}
    for r in requests:
        sid = r.get("session_id")
        if not sid:
            continue
        d = r.get("delta_ms")
        if isinstance(d, int):
            deltas[sid].append(d)
        counts[sid] += 1
        sess_class.setdefault(sid, r.get("class", "?"))
        sess_family.setdefault(sid, r.get("family", "?"))
    for b in beacons:
        sid = b.get("session_id")
        if sid:
            has_beacon.add(sid)
    out: dict[str, dict[str, float | int | bool]] = {}
    for sid, n in counts.items():
        ds = deltas[sid]
        out[sid] = {
            "n_requests": n,
            "median_delta_ms": int(statistics.median(ds)) if ds else 0,
            "has_beacon": sid in has_beacon,
            "class": sess_class.get(sid, "?"),
            "family": sess_family.get(sid, "?"),
        }
    return out


def _aggregate_by_class(
    features: dict[str, dict[str, float | int | bool]]
) -> dict[str, dict[str, float | int]]:
    by: dict[str, list[dict[str, float | int | bool]]] = collections.defaultdict(list)
    for f in features.values():
        by[str(f["class"])].append(f)
    out: dict[str, dict[str, float | int]] = {}
    for klass, rows in by.items():
        medians = [int(r["median_delta_ms"]) for r in rows if int(r["median_delta_ms"]) > 0]
        out[klass] = {
            "sessions": len(rows),
            "median_delta_ms": int(statistics.median(medians)) if medians else 0,
            "beacon_present_ratio": (
                round(sum(1 for r in rows if r["has_beacon"]) / len(rows), 3)
                if rows else 0.0
            ),
        }
    return out


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        data_dir = pathlib.Path(argv[1])
    else:
        data_dir = pathlib.Path(__file__).resolve().parent.parent / "data"
    print(f"[phase-bench-1] reading {data_dir}")

    sessions = _read_jsonl(data_dir / "sessions.jsonl")
    requests = _read_jsonl(data_dir / "requests.jsonl")
    beacons = _read_jsonl(data_dir / "beacons.jsonl")
    consent = _read_jsonl(data_dir / "consent.jsonl")

    print(f"  sessions.jsonl: {len(sessions)} rows")
    print(f"  requests.jsonl: {len(requests)} rows")
    print(f"  beacons.jsonl:  {len(beacons)} rows")
    print(f"  consent.jsonl:  {len(consent)} rows")

    print()
    print("session counts by (class, family):")
    counts = _class_family_counts(sessions)
    if not counts:
        print("  (none yet)")
    for (klass, family), n in sorted(counts.items()):
        print(f"  {klass:8s}  {family:24s}  {n}")

    print()
    print("eyeball human-vs-agent (no model):")
    features = _per_session_features(requests, beacons)
    agg = _aggregate_by_class(features)
    if not agg:
        print("  (no requests yet — run a consented human session and a "
              "real_agent session first)")
    else:
        print(f"  {'class':8s}  {'sessions':>8s}  "
              f"{'median_delta_ms':>16s}  {'beacon_ratio':>13s}")
        for klass, row in sorted(agg.items()):
            print(
                f"  {klass:8s}  {row['sessions']:>8d}  "
                f"{row['median_delta_ms']:>16d}  {row['beacon_present_ratio']:>13.3f}"
            )
        print()
        print("Expected shape: human sessions have higher median_delta_ms")
        print("(seconds between clicks) and beacon_ratio=1.0 (every HTML")
        print("page injects the beacon). Agent sessions cluster at much")
        print("lower delta_ms and may have beacon_ratio<1 depending on")
        print("framework (browser-use renders HTML so the beacon DOES fire).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
