"""Turn a CALDERA operation report into per-event attack labels.

CALDERA emits an operation report (the /api/v2/operations/{id}/report
endpoint, or `caldera --report`) that lists each ability execution: the
agent host it ran on, the start / end timestamps, and the MITRE ATT&CK
technique id. We use those to label the matching Sysmon events two
ways and take the union:

  1. ProcessGuid set — if Sysmon EID 1 fires on the same host within
     a small window of an ability start, the resulting ProcessGuid is
     marked malicious. Any downstream Sysmon event whose
     ParentProcessGuid (or chain) traces back to one of these is also
     malicious. This is the high-precision path.

  2. (host, [t_start, t_end]) fallback — for events that don't have a
     parent in the malicious GUID set (network connect, file create
     from an already-running benign process, registry edits), we label
     by time window on the same host. Lower precision, but it catches
     the cases where CALDERA's ability runs inside a long-lived
     process whose GUID we didn't seed.

The output is a `Labels` bundle that adapt_winlog_dataframe consumes:
malicious_guids (set) plus a list of (host, t_start, t_end) windows.

This module is intentionally small: real CALDERA reports vary across
versions (v4 vs v5) and across REST vs file dumps. The minimal stable
contract is: "give me a list of {host, technique_id, t_start_ms,
t_end_ms} steps" — adapters for specific report schemas live in
load_caldera_op().
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
from typing import Any


@dataclasses.dataclass
class Step:
    host: str
    technique_id: str
    t_start: float  # unix seconds
    t_end: float
    ability_name: str = ""
    command_hash: str = ""


@dataclasses.dataclass
class Labels:
    steps: list[Step]
    malicious_guids: set[str]
    host_time_windows: list[tuple[str, float, float]]
    techniques: set[str]
    tactic_coverage: set[str]

    def to_dict(self) -> dict:
        return {
            "n_steps": len(self.steps),
            "n_malicious_guids": len(self.malicious_guids),
            "n_host_windows": len(self.host_time_windows),
            "techniques": sorted(self.techniques),
            "tactic_coverage": sorted(self.tactic_coverage),
        }


def _to_unix_s(v: Any) -> float | None:
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v) / (1e3 if v > 1e12 else 1.0)
    try:
        import datetime as dt
        return dt.datetime.fromisoformat(str(v).replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def load_caldera_op(path: pathlib.Path) -> list[Step]:
    """Read a CALDERA op JSON report into a list of Steps.

    Handles two common shapes:
      - {"steps": [{host, technique_id, t_start, t_end, ...}, ...]} (the
        normalized shape this repo's synthesizer writes)
      - {"operation": {"steps": [{... finish, host{...}}], ...}} (the
        CALDERA REST report shape, abridged)
    """
    raw = json.loads(path.read_text())
    steps: list[Step] = []

    container = raw.get("operation") or raw
    raw_steps = container.get("steps") or container.get("links") or []

    for s in raw_steps:
        host = (
            s.get("host")
            or (s.get("host") or {}).get("hostname")
            or (s.get("paw") or "")
            or "unknown"
        )
        if isinstance(host, dict):
            host = host.get("hostname") or "unknown"
        tech = (
            s.get("technique_id")
            or s.get("technique") and s["technique"].get("technique_id")
            or s.get("attack_id")
            or ""
        )
        if not tech:
            continue
        t0 = _to_unix_s(s.get("t_start") or s.get("decide") or s.get("start"))
        t1 = _to_unix_s(s.get("t_end") or s.get("finish") or s.get("status_changed"))
        if t0 is None and t1 is None:
            continue
        if t0 is None:
            t0 = t1
        if t1 is None or t1 < t0:
            t1 = t0 + 5.0
        steps.append(Step(
            host=str(host),
            technique_id=str(tech),
            t_start=float(t0),
            t_end=float(t1),
            ability_name=str(s.get("ability_name", "") or s.get("ability_id", "")),
            command_hash=str(s.get("command_hash", "")),
        ))
    return steps


def resolve_labels(
    steps: list[Step], sysmon_df, *, guid_window_s: float = 5.0
) -> Labels:
    """Resolve labels by joining steps against Sysmon EID 1 events.

    Walks the events DataFrame for process_create events (EID 1) on
    each step's host within [t_start - guid_window_s, t_end +
    guid_window_s] and marks their ProcessGuid malicious. Builds the
    transitive closure across ProcessGuid -> ParentProcessGuid so child
    processes of a malicious parent inherit the label.

    Falls back to (host, time-window) labels for steps whose start
    window catches no EID 1 (long-lived process steps).
    """
    from adapter_winlogs import (  # local import: top-level may not be on path
        ATTACK_ID_TO_TACTIC, EVENTID_FIELDS, HOST_FIELDS, PGUID_FIELDS,
        PPGUID_FIELDS, TS_FIELDS, _coalesce, _to_unix,
    )

    techniques = {s.technique_id for s in steps}
    tactic_coverage = {
        ATTACK_ID_TO_TACTIC.get(t.split(".")[0], "")
        for t in techniques
    } - {""}

    df = sysmon_df
    ts = _coalesce(df, TS_FIELDS)
    host = _coalesce(df, HOST_FIELDS)
    eid = _coalesce(df, EVENTID_FIELDS)
    pguid = _coalesce(df, PGUID_FIELDS)
    ppguid = _coalesce(df, PPGUID_FIELDS)
    if ts is None or eid is None or host is None or pguid is None:
        return Labels([], set(), [(s.host, s.t_start, s.t_end) for s in steps],
                      techniques, tactic_coverage)

    ts_unix = _to_unix(ts)
    by_host: dict[str, list[tuple[float, str, str]]] = {}
    for h, t, e, g, pg in zip(host, ts_unix, eid, pguid, ppguid):
        try:
            e_int = int(e)
        except (TypeError, ValueError):
            continue
        if e_int != 1:
            continue
        h_str = str(h)
        by_host.setdefault(h_str, []).append((float(t), str(g) if g else "",
                                              str(pg) if pg else ""))

    malicious: set[str] = set()
    host_windows: list[tuple[str, float, float]] = []
    for step in steps:
        events = by_host.get(step.host, [])
        lo, hi = step.t_start - guid_window_s, step.t_end + guid_window_s
        matched = [(t, g, pg) for (t, g, pg) in events if lo <= t <= hi and g]
        if matched:
            for _, g, _ in matched:
                malicious.add(g)
        else:
            host_windows.append((step.host, step.t_start, step.t_end))

    # transitive closure: any process whose parent chain leads to a
    # malicious GUID is also malicious. Bounded by the process count.
    if malicious:
        parent_of: dict[str, str] = {}
        for events in by_host.values():
            for _, g, pg in events:
                if g and pg:
                    parent_of[g] = pg
        changed = True
        depth = 0
        while changed and depth < 32:
            changed = False
            for g, pg in parent_of.items():
                if pg in malicious and g not in malicious:
                    malicious.add(g)
                    changed = True
            depth += 1

    return Labels(
        steps=steps,
        malicious_guids=malicious,
        host_time_windows=host_windows,
        techniques=techniques,
        tactic_coverage=tactic_coverage,
    )


REQUIRED_TACTICS = (
    "recon", "discovery", "credential_access",
    "command_execution", "lateral_movement", "exfiltration",
)


def tactic_coverage_check(labels: Labels) -> tuple[bool, list[str]]:
    """Return (covered_all_six, missing_tactic_names)."""
    missing = [t for t in REQUIRED_TACTICS if t not in labels.tactic_coverage]
    return not missing, missing
