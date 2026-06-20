"""Synthesize an Atomic Red Team campaign for in-sandbox validation.

The host-side equivalent of phase 7's "second attacker family" — we
need both CALDERA and Atomic to flow through the same ingest path so
phase 2's held-out emulation eval has two families to swap between.

Atomic Red Team's signal differs from CALDERA in a few ways the
detector should pick up on:

  - Shallower process tree (atomics typically spawn from one
    PowerShell host process per invocation; CALDERA chains a longer
    cmd → powershell → tool tree).
  - Quick-fire cadence (each atomic finishes in seconds, then the
    operator picks the next).
  - Different technique-ID set per tactic so held-out is meaningful:
    Atomic uses T1592/T1057/T1555/T1106/T1570/T1567; the CALDERA synth
    uses T1595/T1046/T1003/T1059/T1021/T1041.

The output mirrors `synth_caldera.write_synth_campaign`: a sysmon.jsonl
plus an atomic_invocations.json that score_campaign can read via
atomic_to_labels.load_atomic_invocations.
"""

from __future__ import annotations

import json
import pathlib
import random
from typing import Optional

import numpy as np
import pandas as pd


# Atomic technique IDs deliberately chosen to differ from CALDERA's set
# while still covering all six modeled tactics. Each maps via the
# existing ATTACK_ID_TO_TACTIC crosswalk in adapter_winlogs.
ATOMIC_TECHNIQUES = {
    "recon":              "T1592",
    "discovery":          "T1057",
    "credential_access":  "T1555",
    "command_execution":  "T1106",
    "lateral_movement":   "T1570",
    "exfiltration":       "T1567",
}


def _make_atomic_events(
    n_atomic_hosts: int = 1,
    seed: int = 0,
) -> pd.DataFrame:
    """Sysmon-shaped events for a small Atomic campaign.

    Different process-tree shape than synth_caldera's attack rows:
    every atomic spawns from a single long-lived `powershell.exe` host
    process per invocation, no deep child chain, but more atomics per
    host (one per tactic minimum, often more).
    """
    rng = np.random.default_rng(seed)
    rows = []
    gid = [0]

    def new_guid() -> str:
        gid[0] += 1
        return f"{{guid-atomic-{gid[0]}}}"

    def proc(host: str, ds: str, t: float, parent: str, image: str,
             eid: int, tech: str, mal: int, chan: str = "Sysmon",
             extra: Optional[dict] = None) -> str:
        g = new_guid()
        row = {
            "@timestamp": t, "Hostname": host, "dataset": ds,
            "Channel": f"Microsoft-Windows-{chan}/Operational",
            "EventID": eid, "Image": image,
            "ProcessGuid": g, "ParentProcessGuid": parent,
            "technique": tech, "is_malicious": mal,
        }
        if extra:
            row.update(extra)
        rows.append(row)
        return g

    base = 1.7e9
    for i in range(n_atomic_hosts):
        host, ds = f"WS-Atomic-{i}", f"atomic_{i}"
        t = base + rng.uniform(0, 1e6)
        # Operator's PowerShell host — long-lived, all atomics fire under it.
        ps_host = proc(host, ds, t, "",
                       "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                       1, "", 0)
        t += rng.uniform(0.5, 2.0)

        # Multiple passes over the six tactics so the campaign produces
        # enough events to fill a 32-event window after windowize's
        # half-fill threshold. Each pass shuffles the order so the
        # detector can't trivially memorize a fixed sequence.
        for _ in range(int(rng.integers(4, 7))):
            atomics = list(ATOMIC_TECHNIQUES.items())
            rng.shuffle(atomics)
            for tactic, tech in atomics:
                burst_dt = rng.exponential(0.8)
                t += burst_dt
                if tactic == "recon":
                    proc(host, ds, t, ps_host, "C:\\Windows\\System32\\whoami.exe",
                         1, tech, 1)
                elif tactic == "discovery":
                    proc(host, ds, t, ps_host, "C:\\Windows\\System32\\tasklist.exe",
                         1, tech, 1)
                    t += rng.exponential(0.5)
                    proc(host, ds, t, ps_host, "C:\\Windows\\System32\\net.exe",
                         1, tech, 1)
                elif tactic == "credential_access":
                    proc(host, ds, t, ps_host,
                         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         11, tech, 1,
                         extra={"TargetFilename":
                                "C:\\Users\\admin\\AppData\\Local\\Microsoft\\Vault\\Policy.vpol"})
                elif tactic == "command_execution":
                    proc(host, ds, t, ps_host, "C:\\Windows\\System32\\rundll32.exe",
                         1, tech, 1)
                elif tactic == "lateral_movement":
                    proc(host, ds, t, ps_host, "C:\\Windows\\System32\\xcopy.exe",
                         1, tech, 1)
                    t += rng.exponential(0.3)
                    proc(host, ds, t, ps_host,
                         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         11, tech, 1,
                         extra={"TargetFilename":
                                "\\\\WS-Atomic-1\\admin$\\temp\\tool.exe"})
                elif tactic == "exfiltration":
                    proc(host, ds, t, ps_host,
                         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         3, tech, 1,
                         extra={"DestinationHostname": "transfer.sh"})

        # A few "noise" atomics — not in the six-tactic set, mapped to ""
        for _ in range(int(rng.integers(8, 16))):
            t += rng.exponential(1.5)
            proc(host, ds, t, ps_host,
                 rng.choice(["C:\\Windows\\System32\\ipconfig.exe",
                             "C:\\Windows\\System32\\nslookup.exe",
                             "C:\\Windows\\System32\\reg.exe"]),
                 1, "T1082", 1)

    return pd.DataFrame(rows)


def write_synth_campaign(
    out_dir: pathlib.Path,
    *,
    campaign_id: str,
    n_atomic_hosts: int = 1,
    seed: int = 0,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    df = _make_atomic_events(n_atomic_hosts=n_atomic_hosts, seed=seed)

    invocations: list[dict] = []
    hosts = sorted(df["Hostname"].dropna().unique())
    for host in hosts:
        host_evs = df[df["Hostname"] == host]
        if host_evs.empty:
            continue
        # one invocation per known tactic+technique that fired on this host
        for tactic, tech in ATOMIC_TECHNIQUES.items():
            ev_for_tech = host_evs[host_evs["technique"] == tech]
            if ev_for_tech.empty:
                continue
            t0 = float(ev_for_tech["@timestamp"].min())
            t1 = float(ev_for_tech["@timestamp"].max()) + 1.0
            invocations.append({
                "host": host,
                "technique_id": tech,
                "atomic_name": f"atomic_{tactic}_{tech.lower()}",
                "executor": "powershell",
                "command_hash": f"{abs(hash((host, tech, seed))) & 0xffffffff:08x}",
                "t_start": t0,
                "t_end": t1,
            })

    ts_start = float(df["@timestamp"].min())
    ts_end = float(df["@timestamp"].max())
    report = {
        "framework": "atomic-red-team",
        "version": "1.5.0-synth",
        "campaign_id": campaign_id,
        "host_list": hosts,
        "ts_start": ts_start,
        "ts_end": ts_end,
        "invocations": invocations,
    }

    sysmon_path = out_dir / "sysmon.jsonl"
    with sysmon_path.open("w") as f:
        for row in df.to_dict(orient="records"):
            clean = {k: v for k, v in row.items() if v == v}  # NaN-safe
            f.write(json.dumps(clean, separators=(",", ":")) + "\n")
    (out_dir / "atomic_invocations.json").write_text(json.dumps(report, indent=2))

    mal_guids = set(df.loc[df["is_malicious"] == 1, "ProcessGuid"].dropna().tolist())
    return {
        "campaign_id": campaign_id,
        "framework": "atomic",
        "host_list": hosts,
        "invocations": [inv["atomic_name"] for inv in invocations],
        "tactic_coverage": list(ATOMIC_TECHNIQUES.keys()),
        "ts_start": ts_start,
        "ts_end": ts_end,
        "malicious_guid_count": len(mal_guids),
        "n_events": len(df),
    }


def cli(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", default="atomic-001")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--n-atomic-hosts", type=int, default=1)
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    args = ap.parse_args(argv)

    out_dir = args.out / args.campaign
    meta = write_synth_campaign(
        out_dir,
        campaign_id=args.campaign,
        n_atomic_hosts=args.n_atomic_hosts,
        seed=args.seed,
    )
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(cli())
