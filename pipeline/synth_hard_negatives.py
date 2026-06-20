"""Synthesize hard-negative campaigns — sanctioned activity that looks like attack.

The bulk-benign workload (synth_workload) anchors the FP/hour budget on
ordinary stuff. Hard negatives are the OTHER thing the detector has to
not flag: legitimate-but-scary admin work that overlaps the attack
behavioral envelope. Each hard-negative campaign self-labels its
`benign_subtype`:

  ps_remoting     — Enter-PSSession / Invoke-Command across two hosts.
                    wsmprovhost.exe + powershell.exe, looks remarkably
                    like CALDERA's lateral_movement step.
  wmi             — WMI calls (WmiPrvSE.exe under a wbem provider tree),
                    looks like discovery + command_execution.
  sched_task      — schtasks.exe + Security 4698 (scheduled task
                    create), looks like persistence.
  sanctioned_scan — internal vulnerability scan: nmap.exe from an admin
                    host hitting known internal ranges. Looks exactly
                    like CALDERA's discovery → recon chain.
  backup          — backup agent + robocopy doing scheduled writes.
                    Looks like exfiltration if you only see network
                    bytes + file activity at scale.

Each campaign writes sysmon.jsonl + workload.json. score_campaign reads
workload.json to pick up class + benign_subtype + framework and
appends a provenance row. label=0 everywhere — these aren't attacks,
they're stress on the FP side.
"""

from __future__ import annotations

import json
import pathlib
from typing import Callable, Optional

import numpy as np
import pandas as pd


VALID_SUBTYPES = (
    "ps_remoting", "wmi", "sched_task", "sanctioned_scan", "backup",
)


def _proc_factory(rows: list[dict], gid: list[int]) -> Callable:
    def proc(host: str, ds: str, t: float, parent: str, image: str,
             eid: int, extra: Optional[dict] = None,
             chan: str = "Sysmon") -> str:
        gid[0] += 1
        g = f"{{guid-hardneg-{gid[0]}}}"
        row = {
            "@timestamp": t, "Hostname": host, "dataset": ds,
            "Channel": f"Microsoft-Windows-{chan}/Operational",
            "EventID": eid, "Image": image,
            "ProcessGuid": g, "ParentProcessGuid": parent,
            "technique": "", "is_malicious": 0,
        }
        if extra:
            row.update(extra)
        rows.append(row)
        return g
    return proc


def _ps_remoting(rng: np.random.Generator, host: str, ds: str,
                 t0: float, rows: list[dict], gid: list[int]) -> None:
    proc = _proc_factory(rows, gid)
    # On target host: wsmprovhost spawns powershell which runs a command
    wsm = proc(host, ds, t0, "", "C:\\Windows\\System32\\wsmprovhost.exe", 1)
    t = t0 + 0.3
    ps = proc(host, ds, t, wsm,
              "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 1)
    # Several remoting sessions back to back — admin running an ad-hoc
    # script over a few minutes generates dozens of process / file / reg
    # events, more than enough for a 32-event window.
    for _ in range(int(rng.integers(35, 60))):
        t += rng.exponential(0.6)
        eid = int(rng.choice([1, 11, 13]))
        if eid == 1:
            proc(host, ds, t, ps, "C:\\Windows\\System32\\reg.exe", 1)
        elif eid == 11:
            proc(host, ds, t, ps,
                 "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 11,
                 extra={"TargetFilename":
                        f"C:\\Windows\\Temp\\admin-script-{rng.integers(0, 99)}.ps1"})
        else:
            proc(host, ds, t, ps,
                 "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 13)


def _wmi(rng: np.random.Generator, host: str, ds: str,
         t0: float, rows: list[dict], gid: list[int]) -> None:
    proc = _proc_factory(rows, gid)
    # WmiPrvSE under svchost — typical wbem provider tree
    svc = proc(host, ds, t0, "", "C:\\Windows\\System32\\svchost.exe", 1)
    t = t0 + 0.5
    wmi_p = proc(host, ds, t, svc, "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", 1)
    for _ in range(int(rng.integers(40, 70))):
        t += rng.exponential(0.4)
        if rng.random() < 0.4:
            proc(host, ds, t, wmi_p,
                 "C:\\Windows\\System32\\wbem\\WMIC.exe", 1)
        else:
            proc(host, ds, t, wmi_p,
                 "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", 11,
                 extra={"TargetFilename":
                        f"C:\\Windows\\Temp\\wmi-stage-{rng.integers(0, 99)}"})


def _sched_task(rng: np.random.Generator, host: str, ds: str,
                t0: float, rows: list[dict], gid: list[int]) -> None:
    proc = _proc_factory(rows, gid)
    explorer = proc(host, ds, t0, "", "C:\\Windows\\explorer.exe", 1)
    t = t0 + 1.0
    for _ in range(int(rng.integers(20, 40))):
        t += rng.exponential(2.5)
        proc(host, ds, t, explorer,
             "C:\\Windows\\System32\\schtasks.exe", 1)
        # Security 4698 — scheduled task created
        rows.append({
            "@timestamp": t + 0.1, "Hostname": host, "dataset": ds,
            "Channel": "Security", "EventID": 4698,
            "Image": "", "ProcessGuid": "", "ParentProcessGuid": "",
            "technique": "", "is_malicious": 0,
            "TaskName": f"\\Microsoft\\BackupTask-{rng.integers(0, 99)}",
        })


def _sanctioned_scan(rng: np.random.Generator, host: str, ds: str,
                     t0: float, rows: list[dict], gid: list[int]) -> None:
    proc = _proc_factory(rows, gid)
    # Internal sanctioned scan from an admin host. nmap spawns many EID 3
    # events as it probes the internal range.
    nmap = proc(host, ds, t0, "",
                "C:\\Program Files (x86)\\Nmap\\nmap.exe", 1)
    t = t0 + 0.5
    for _ in range(int(rng.integers(40, 90))):
        t += rng.exponential(0.05)
        proc(host, ds, t, nmap,
             "C:\\Program Files (x86)\\Nmap\\nmap.exe", 3,
             extra={"DestinationIp":
                    f"10.0.{rng.integers(0, 256)}.{rng.integers(0, 256)}",
                    "DestinationPort": int(rng.choice([22, 80, 443, 445, 3389]))})


def _backup(rng: np.random.Generator, host: str, ds: str,
            t0: float, rows: list[dict], gid: list[int]) -> None:
    proc = _proc_factory(rows, gid)
    veeam = proc(host, ds, t0, "",
                 "C:\\Program Files\\Veeam\\Backup Agent\\veeam-agent.exe", 1)
    t = t0 + 1.0
    for _ in range(int(rng.integers(15, 35))):
        t += rng.exponential(0.3)
        eid = int(rng.choice([11, 3]))
        if eid == 11:
            proc(host, ds, t, veeam,
                 "C:\\Windows\\System32\\robocopy.exe", 11,
                 extra={"TargetFilename":
                        f"\\\\BACKUP-SRV\\share$\\dailybackup\\file-{rng.integers(0, 999)}.bak"})
        else:
            proc(host, ds, t, veeam,
                 "C:\\Program Files\\Veeam\\Backup Agent\\veeam-agent.exe", 3,
                 extra={"DestinationHostname": "backup-srv.internal"})


SUBTYPE_GENERATORS = {
    "ps_remoting":     _ps_remoting,
    "wmi":             _wmi,
    "sched_task":      _sched_task,
    "sanctioned_scan": _sanctioned_scan,
    "backup":          _backup,
}


def write_synth_campaign(
    out_dir: pathlib.Path,
    *,
    campaign_id: str,
    benign_subtype: str,
    seed: int = 0,
    n_hosts: int = 1,
) -> dict:
    if benign_subtype not in SUBTYPE_GENERATORS:
        raise SystemExit(
            f"[synth_hard_negatives] unknown benign_subtype={benign_subtype!r}; "
            f"valid = {sorted(SUBTYPE_GENERATORS)}"
        )
    out_dir.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)
    rows: list[dict] = []
    gid = [0]
    fn = SUBTYPE_GENERATORS[benign_subtype]
    base = 1.7e9
    for i in range(n_hosts):
        host, ds = f"WS-Admin-{i}", f"hardneg_{benign_subtype}_{i}"
        fn(rng, host, ds, base + rng.uniform(0, 1e6), rows, gid)

    df = pd.DataFrame(rows)
    hosts = sorted(df["Hostname"].dropna().unique())
    ts_start = float(df["@timestamp"].min())
    ts_end = float(df["@timestamp"].max())
    meta = {
        "campaign_id": campaign_id,
        "class": "hard_negative",
        "framework": "scripted",
        "benign_subtype": benign_subtype,
        "host_list": hosts,
        "n_events": len(df),
        "ts_start": ts_start,
        "ts_end": ts_end,
        "notes": f"sanctioned admin activity: {benign_subtype}",
    }

    sysmon_path = out_dir / "sysmon.jsonl"
    with sysmon_path.open("w") as f:
        for row in df.to_dict(orient="records"):
            clean = {k: v for k, v in row.items() if v == v}
            f.write(json.dumps(clean, separators=(",", ":")) + "\n")
    (out_dir / "workload.json").write_text(json.dumps(meta, indent=2))
    return meta


def cli(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", required=True)
    ap.add_argument("--benign-subtype", required=True,
                    choices=sorted(SUBTYPE_GENERATORS))
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument("--n-hosts", type=int, default=1)
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    args = ap.parse_args(argv)
    meta = write_synth_campaign(
        args.out / args.campaign,
        campaign_id=args.campaign,
        benign_subtype=args.benign_subtype,
        seed=args.seed,
        n_hosts=args.n_hosts,
    )
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(cli())
