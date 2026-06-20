"""Turn Atomic Red Team invocations into per-event attack labels.

Atomic Red Team isn't an orchestrator like CALDERA — it's a library of
per-technique "atomics" you invoke via `Invoke-AtomicTest -TechniqueId
T1059` from a PowerShell session on the target host. The "operation
report" equivalent is just a list of which atomics you ran, on which
host, with what start/end timestamps. We accept that as
`atomic_invocations.json`:

  {
    "framework": "atomic-red-team",
    "version": "1.5.0",
    "invocations": [
      {
        "host": "WS-A0",
        "technique_id": "T1059",
        "atomic_name": "Command Execution: Powershell",
        "executor": "powershell",
        "command_hash": "abc1234",
        "t_start": 1700187280.5,
        "t_end": 1700187282.1
      },
      ...
    ]
  }

Once parsed, this module reuses caldera_op_to_labels.resolve_labels to
walk the Sysmon stream, seed the malicious-ProcessGuid set, take the
transitive closure across ProcessGuid -> ParentProcessGuid, and
return a host/time-window fallback for atomics where no Sysmon EID 1
landed inside the window (long-lived process atomics like WMI calls).

This intentionally piggybacks on the CALDERA module's resolver rather
than duplicating it: the contract a labeler exposes is "give me a list
of {host, technique_id, t_start, t_end}", everything downstream is
shared.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from pipeline.caldera_op_to_labels import (
    Labels, Step, REQUIRED_TACTICS, _to_unix_s, resolve_labels,
    tactic_coverage_check,
)


def load_atomic_invocations(path: pathlib.Path) -> list[Step]:
    """Read an Atomic Red Team invocations JSON into a list of Steps."""
    raw = json.loads(path.read_text())
    invocations = raw.get("invocations") or raw.get("steps") or []

    steps: list[Step] = []
    for inv in invocations:
        host = (
            inv.get("host")
            or inv.get("Hostname")
            or inv.get("ComputerName")
            or "unknown"
        )
        if isinstance(host, dict):
            host = host.get("hostname") or "unknown"
        tech = (
            inv.get("technique_id")
            or inv.get("technique")
            or inv.get("attack_technique")
            or ""
        )
        if not tech:
            continue
        t0 = _to_unix_s(inv.get("t_start") or inv.get("start"))
        t1 = _to_unix_s(inv.get("t_end") or inv.get("finish") or inv.get("end"))
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
            ability_name=str(inv.get("atomic_name", "") or inv.get("name", "")),
            command_hash=str(inv.get("command_hash", "")),
        ))
    return steps


__all__ = [
    "Labels", "Step", "REQUIRED_TACTICS",
    "load_atomic_invocations", "resolve_labels", "tactic_coverage_check",
]
