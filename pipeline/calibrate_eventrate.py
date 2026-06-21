"""Real-data calibration for the host alert-fatigue arithmetic.

`pipeline/alert_fatigue.py` ships with hand-tuned DEFAULT_DEPLOYMENTS
(1.0–2.0 events/sec/host across small/med/large fleets). Those numbers
came from a handful of synthetic-derived measurements and the operator's
priors. As soon as you have real Sysmon telemetry from a deployment, you
can do better:

  - Load any Sysmon dump (JSONL / CSV / Parquet) via `ingest_sysmon`.
  - Measure the *combined* event rate per host (EID 1 + 3 + 5 + 7 + …
    whatever your config is collecting).
  - Measure burst behavior with sliding 60-second windows: median and
    p95 per-minute rates capture the "steady state" vs "noisy minute"
    spread that drives FP/hour worst case.
  - Emit `deployments.json` — a file `alert_fatigue --deployments-file`
    will consume — pinned to *your* observed rate instead of the
    built-in defaults.

This is read-only: no labels, no detector inference, no ML. Just rate
math + a JSON write.

Usage:

  # Calibrate against a real Sysmon dump
  python3 -m pipeline.calibrate_eventrate \\
      --sysmon /path/to/sysmon.jsonl \\
      --hosts-per-deployment "10,50,200" \\
      --out data/host/deployments.json

  # Feed the calibrated shapes into alert_fatigue
  python3 -m pipeline.alert_fatigue \\
      --deployments-file data/host/deployments.json \\
      --fp-budget 1.0 \\
      --multi-day
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Optional

import numpy as np
import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline import ingest_sysmon

# Mirror the adapter's field detection so a dump that loads in
# adapter_winlogs also loads here without surprises.
from adapter_winlogs import EVENTID_FIELDS, TS_FIELDS


def _pick_col(df: pd.DataFrame, candidates: list[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _to_unix_seconds(col: pd.Series) -> pd.Series:
    """Coerce any TS_FIELDS shape to unix seconds (float).

    Handles: numeric (already unix s or ms), ISO strings, pandas Timestamps.
    Heuristic for numeric: values > 1e12 are treated as milliseconds.
    """
    if pd.api.types.is_numeric_dtype(col):
        arr = col.astype(float)
        if arr.max() > 1e12:
            arr = arr / 1000.0
        return arr
    parsed = pd.to_datetime(col, utc=True, errors="coerce")
    return parsed.astype("int64").astype(float) / 1e9


def _per_minute_rate_distribution(
    ts: np.ndarray, n_hosts: int,
) -> tuple[float, float, float, float, int]:
    """Sliding 60-second buckets across the full ts span, normalized to
    per-host rate (assumes events are roughly uniformly distributed
    across hosts — fine for the burst summary; per-host segmentation
    would be over-engineering for a calibration tool).

    Returns: (mean_rate, p50_rate, p95_rate, max_rate, n_buckets).
    """
    if len(ts) < 2 or n_hosts < 1:
        return 0.0, 0.0, 0.0, 0.0, 0
    t0, t1 = float(ts.min()), float(ts.max())
    span = t1 - t0
    if span < 60.0:
        # one bucket — degenerate but defined
        rate = len(ts) / max(span, 1.0) / n_hosts
        return rate, rate, rate, rate, 1
    n_buckets = int(span // 60.0)
    edges = np.linspace(t0, t0 + n_buckets * 60.0, n_buckets + 1)
    counts, _ = np.histogram(ts, bins=edges)
    rates = counts.astype(float) / 60.0 / float(n_hosts)
    return (
        float(rates.mean()),
        float(np.median(rates)),
        float(np.percentile(rates, 95)),
        float(rates.max()),
        int(n_buckets),
    )


def calibrate(sysmon_path: pathlib.Path) -> dict:
    df = ingest_sysmon.load_sysmon(sysmon_path)
    if df.empty:
        raise SystemExit(f"[calibrate] {sysmon_path} parsed to 0 events")

    ts_col = _pick_col(df, TS_FIELDS)
    eid_col = _pick_col(df, EVENTID_FIELDS)
    if ts_col is None or eid_col is None:
        raise SystemExit(
            f"[calibrate] could not find timestamp/EventID in {sysmon_path}. "
            f"Tried TS={TS_FIELDS} EID={EVENTID_FIELDS}. "
            f"Available columns: {list(df.columns)[:20]}")

    ts = _to_unix_seconds(df[ts_col]).to_numpy()
    ts = ts[np.isfinite(ts) & (ts > 0)]
    if ts.size < 2:
        raise SystemExit(
            f"[calibrate] {sysmon_path} has <2 usable timestamps after coercion")
    ts.sort()
    eid = pd.to_numeric(df[eid_col], errors="coerce").to_numpy()

    host_col = _pick_col(df, ["Hostname", "host", "Computer", "hostname"])
    n_hosts = int(df[host_col].nunique()) if host_col else 1
    n_hosts = max(n_hosts, 1)

    span_s = float(ts.max() - ts.min())
    overall_rate = float(ts.size) / max(span_s, 1.0) / float(n_hosts)
    mean_min, p50_min, p95_min, max_min, n_buckets = _per_minute_rate_distribution(
        ts, n_hosts,
    )

    per_eid: dict[str, dict] = {}
    if eid.size and span_s > 0:
        unique, counts = np.unique(eid[~np.isnan(eid)], return_counts=True)
        for u, c in zip(unique, counts):
            per_eid[str(int(u))] = {
                "count": int(c),
                "events_per_sec_per_host": float(c) / span_s / float(n_hosts),
                "share": float(c) / float(ts.size),
            }

    return {
        "input_path": str(sysmon_path),
        "n_events": int(ts.size),
        "n_hosts_observed": n_hosts,
        "observation_seconds": span_s,
        "observation_hours": span_s / 3600.0,
        "events_per_sec_per_host": {
            "overall": overall_rate,
            "minute_bucket_mean": mean_min,
            "minute_bucket_p50": p50_min,
            "minute_bucket_p95": p95_min,
            "minute_bucket_max": max_min,
            "n_minute_buckets": n_buckets,
        },
        "per_eid": per_eid,
    }


def suggest_deployments(
    calibration: dict, hosts_per_deployment: list[int],
) -> list[dict]:
    """Build a deployments list `alert_fatigue --deployments-file` can load.

    Steady-state shapes use the overall mean rate; we also emit a single
    `burst_p95` shape pinned to the busy-minute p95 so the operator sees
    what FP/hour looks like in a noisy minute, not just on average.
    """
    eps = calibration["events_per_sec_per_host"]
    overall = eps["overall"]
    p95 = eps["minute_bucket_p95"]

    deployments: list[dict] = []
    for hosts in hosts_per_deployment:
        size_label = (
            "small_office" if hosts <= 25
            else "med_business" if hosts <= 100
            else "large_business"
        )
        deployments.append({
            "name": f"calibrated_{size_label}_{hosts}h",
            "hosts": int(hosts),
            "events_per_sec_per_host": round(overall, 4),
            "_source": "calibrated_overall_mean",
        })

    if p95 > 0 and hosts_per_deployment:
        ref = max(hosts_per_deployment)
        deployments.append({
            "name": f"calibrated_burst_p95_{ref}h",
            "hosts": int(ref),
            "events_per_sec_per_host": round(p95, 4),
            "_source": "calibrated_minute_bucket_p95",
        })

    return deployments


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sysmon", type=pathlib.Path, required=True,
                    help="path to a Sysmon dump (.jsonl / .csv / .parquet / .json)")
    ap.add_argument("--hosts-per-deployment", type=str, default="10,50,200",
                    help="comma-separated host counts for the suggested "
                         "deployment shapes (default 10,50,200)")
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host/deployments.json"))
    args = ap.parse_args(argv)

    hosts_list = [int(s) for s in args.hosts_per_deployment.split(",") if s.strip()]
    if not hosts_list:
        raise SystemExit("[calibrate] --hosts-per-deployment must have ≥1 entry")

    calibration = calibrate(args.sysmon)
    deployments = suggest_deployments(calibration, hosts_list)

    payload = {**calibration, "deployments": deployments}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2))

    eps = calibration["events_per_sec_per_host"]
    print(f"\n[calibrate] wrote {args.out}")
    print(f"  events                      = {calibration['n_events']}")
    print(f"  hosts observed              = {calibration['n_hosts_observed']}")
    print(f"  observation                 = {calibration['observation_hours']:.2f}h")
    print(f"  events/sec/host overall     = {eps['overall']:.3f}")
    print(f"  events/sec/host p50 (1-min) = {eps['minute_bucket_p50']:.3f}")
    print(f"  events/sec/host p95 (1-min) = {eps['minute_bucket_p95']:.3f}")
    print(f"  events/sec/host max (1-min) = {eps['minute_bucket_max']:.3f}")
    print()
    print("  per-EID share (top 8):")
    by_share = sorted(calibration["per_eid"].items(),
                      key=lambda kv: -kv[1]["share"])[:8]
    for eid, cell in by_share:
        print(f"    EID {eid:>4}  share={cell['share']*100:5.1f}%  "
              f"rate={cell['events_per_sec_per_host']:.3f}/s/host  "
              f"count={cell['count']}")
    print()
    print("  suggested deployments (feed into alert_fatigue --deployments-file):")
    for dep in deployments:
        print(f"    {dep['name']:>34}  hosts={dep['hosts']:<3}  "
              f"R={dep['events_per_sec_per_host']:.3f}/s  "
              f"[{dep['_source']}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
