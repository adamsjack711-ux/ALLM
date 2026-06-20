"""Synthesize a normal-workload campaign for the host pipeline.

class=normal. Models a typical workday's worth of user + admin activity
on one or more workstations: browser sessions, IDE / build activity,
Outlook, occasional admin tasks (Windows updates, package installs),
file activity in the user profile, ordinary logons.

NONE of these should fire the detector. This is the bulk negative
class that anchors the FP/hour budget.

The shape distinction from the attack synths:
  - Wider process diversity (chrome, outlook, code, msbuild, …)
  - Mostly long inter-event gaps (5-30s) with occasional burst pockets
    around builds
  - Shallow trees with the exception of a parent build process
    (msbuild → cl.exe → link.exe, intentionally deep but benign — this
    is the realistic ceiling the detector has to learn to tolerate)
  - Mix of EID 1 (process create), 3 (network), 11 (file create),
    13 (registry set) — same vocabulary the attack synths use, so the
    detector has to discriminate on patterns not vocabulary
"""

from __future__ import annotations

import json
import pathlib
from typing import Optional

import numpy as np
import pandas as pd


BENIGN_IMAGES = [
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
    "C:\\Program Files\\Microsoft VS Code\\Code.exe",
    "C:\\Windows\\System32\\svchost.exe",
    "C:\\Windows\\System32\\TiWorker.exe",   # Windows Update worker
    "C:\\Windows\\System32\\TrustedInstaller.exe",
    "C:\\Windows\\System32\\backgroundTaskHost.exe",
    "C:\\Program Files\\WindowsApps\\Microsoft.Teams\\Teams.exe",
]


def _make_workload(n_hosts: int = 5, seed: int = 0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    gid = [0]

    def new_guid() -> str:
        gid[0] += 1
        return f"{{guid-workload-{gid[0]}}}"

    def proc(host: str, ds: str, t: float, parent: str, image: str,
             eid: int, extra: Optional[dict] = None,
             chan: str = "Sysmon") -> str:
        g = new_guid()
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

    base = 1.7e9
    for i in range(n_hosts):
        host, ds = f"WS-User-{i}", f"normal_{i}"
        t = base + rng.uniform(0, 1e6)

        # Login event
        rows.append({
            "@timestamp": t, "Hostname": host, "dataset": ds,
            "Channel": "Security", "EventID": 4624,
            "Image": "", "ProcessGuid": "", "ParentProcessGuid": "",
            "technique": "", "is_malicious": 0,
            "TargetUserName": "alice",
        })

        explorer = proc(host, ds, t + 0.5, "", "C:\\Windows\\explorer.exe", 1)
        bursty_build = rng.random() < 0.4

        # Workday-shaped event stream: long benign gaps + occasional bursts
        n_events = int(rng.integers(30, 90))
        cur_parent = explorer
        for _ in range(n_events):
            if bursty_build and rng.random() < 0.1:
                # build burst: msbuild → cl.exe → link.exe — deep benign tree
                t += rng.exponential(2.0)
                msbuild = proc(host, ds, t, explorer,
                               "C:\\Program Files\\MSBuild\\msbuild.exe", 1)
                for _ in range(int(rng.integers(3, 8))):
                    t += rng.exponential(0.4)
                    cl = proc(host, ds, t, msbuild,
                              "C:\\Program Files\\VS\\VC\\bin\\cl.exe", 1)
                    t += rng.exponential(0.3)
                    proc(host, ds, t, cl,
                         "C:\\Program Files\\VS\\VC\\bin\\link.exe", 1)
                cur_parent = explorer
            else:
                t += rng.exponential(rng.uniform(6, 22))
                eid = int(rng.choice([1, 3, 11, 13], p=[0.35, 0.3, 0.25, 0.10]))
                image = str(rng.choice(BENIGN_IMAGES))
                extra = None
                if eid == 3:
                    extra = {"DestinationHostname":
                             str(rng.choice(["outlook.office365.com",
                                              "windowsupdate.com",
                                              "ghcr.io",
                                              "github.com"]))}
                elif eid == 11:
                    extra = {"TargetFilename":
                             f"C:\\Users\\alice\\Documents\\notes-{rng.integers(0, 99)}.docx"}
                cur_parent = proc(host, ds, t, cur_parent, image, eid,
                                  extra=extra)

    return pd.DataFrame(rows)


def write_synth_campaign(
    out_dir: pathlib.Path,
    *,
    campaign_id: str,
    n_hosts: int = 5,
    seed: int = 0,
) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    df = _make_workload(n_hosts=n_hosts, seed=seed)

    hosts = sorted(df["Hostname"].dropna().unique())
    ts_start = float(df["@timestamp"].min())
    ts_end = float(df["@timestamp"].max())
    meta = {
        "campaign_id": campaign_id,
        "class": "normal",
        "framework": "scripted",
        "host_list": hosts,
        "n_events": len(df),
        "ts_start": ts_start,
        "ts_end": ts_end,
        "notes": "scripted normal workload — browsing, IDE/build, Outlook, updates",
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
    ap.add_argument("--campaign", default="workload-001")
    ap.add_argument("--seed", type=int, default=2)
    ap.add_argument("--n-hosts", type=int, default=5)
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    args = ap.parse_args(argv)

    meta = write_synth_campaign(
        args.out / args.campaign,
        campaign_id=args.campaign,
        n_hosts=args.n_hosts,
        seed=args.seed,
    )
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(cli())
