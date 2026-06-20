"""
AI-Attack Detector — Windows event-log adapter (OTRF / Cyber Defense Benchmark)
==============================================================================
Maps Windows event logs (Sysmon + Security channel, the format the Simbian
Cyber Defense Benchmark wraps from the OTRF Security-Datasets corpus) onto the
detector's normalized schema, and carries an ATT&CK `technique` field through
for the multi-label task.

Why a dedicated adapter (vs the generic inspect_dataset mapping): Windows logs
need real DERIVATION, not just renames --
  - `action`  is derived from (Channel, EventID), not a single column
  - `target`  is coalesced differently per event type (process / net / file / registry)
  - `depth`   is derived by walking the ProcessGuid -> ParentProcessGuid tree
  - `label`   usually comes from external ground-truth (malicious ProcessGuids
              or (host, timestamp) pairs), not a column in the raw logs

The exact column names in any given release vary; this coalesces over the common
OTRF/Sysmon field names. If a field isn't found, run inspect_dataset.py on the
real file and extend the *_FIELDS lists below.

    python adapter_winlogs.py --demo     # generate sample logs, adapt, run detector

Dependencies: numpy, pandas  (+ detector_v0 in the same dir for the --demo check)
"""

from __future__ import annotations
import argparse
import numpy as np
import pandas as pd

# --- candidate source field names (first match wins) ------------------------
TS_FIELDS      = ["@timestamp", "TimeCreated", "UtcTime", "EventTime", "timestamp"]
HOST_FIELDS    = ["Hostname", "Computer", "host", "ComputerName"]
EVENTID_FIELDS = ["EventID", "event_id", "EventId"]
CHANNEL_FIELDS = ["Channel", "Provider", "SourceName", "channel"]
PGUID_FIELDS   = ["ProcessGuid", "process_guid"]
PPGUID_FIELDS  = ["ParentProcessGuid", "parent_process_guid"]
CAMPAIGN_FIELDS = ["dataset", "procedure", "campaign", "episode", "scenario"]
LABEL_FIELDS   = ["label", "is_malicious", "malicious", "ground_truth"]
TECH_FIELDS    = ["technique", "attack_technique", "mitre_technique", "technique_id"]

# per-event-type "thing acted upon"
TARGET_FIELDS  = ["TargetFilename", "DestinationHostname", "DestinationIp",
                  "TargetObject", "Image", "TargetUserName", "DestinationPort"]

# --- ATT&CK technique-id -> detector_v1 tactic name (APPROXIMATE crosswalk) ---
# Real logs tag events with ATT&CK ids (T1059, T1071, ...); the multi-label
# detector (detector_v1) reasons in named tactics. This maps the common ids onto
# that tactic vocabulary so winlog output is consumable by the multi-label heads.
# It is intentionally coarse and only covers ids seen in practice -- extend it as
# you wire in more data. Ids with no tactic in our set (e.g. persistence) map to "".
ATTACK_ID_TO_TACTIC = {
    # reconnaissance / discovery
    "T1595": "recon", "T1592": "recon", "T1590": "recon",
    "T1046": "discovery", "T1018": "discovery", "T1083": "discovery",
    "T1057": "discovery", "T1082": "discovery", "T1087": "discovery",
    # credential access (and valid-account use, which rides on creds)
    "T1003": "credential_access", "T1078": "credential_access",
    "T1110": "credential_access", "T1555": "credential_access",
    # execution
    "T1059": "command_execution", "T1106": "command_execution",
    "T1053": "command_execution", "T1105": "command_execution",
    # lateral movement
    "T1021": "lateral_movement", "T1570": "lateral_movement",
    "T1080": "lateral_movement",
    # exfiltration / C2 egress
    "T1041": "exfiltration", "T1048": "exfiltration", "T1567": "exfiltration",
    "T1071": "exfiltration", "T1020": "exfiltration",
}


def attack_id_to_tactic(tech_id) -> str:
    """Map an ATT&CK id (or sub-technique like 'T1059.001') to a detector_v1
    tactic name, or '' if it's outside the modeled tactic set."""
    if not tech_id or str(tech_id) == "":
        return ""
    base = str(tech_id).strip().split(".")[0]       # drop sub-technique suffix
    return ATTACK_ID_TO_TACTIC.get(base, "")


# --- (Channel, EventID) -> action -------------------------------------------
SYSMON_ACTIONS = {
    1: "process_create", 3: "network_connect", 7: "image_load",
    8: "create_remote_thread", 10: "process_access", 11: "file_create",
    12: "registry_event", 13: "registry_set", 14: "registry_rename",
    15: "file_create_stream", 22: "dns_query", 23: "file_delete",
}
SECURITY_ACTIONS = {
    4624: "logon", 4625: "logon_failed", 4688: "process_create",
    4672: "special_privileges", 4698: "scheduled_task_create",
    5140: "share_access", 4720: "user_create", 1102: "log_cleared",
}


def _coalesce(df: pd.DataFrame, names) -> pd.Series | None:
    for n in names:
        if n in df.columns:
            return df[n]
    return None


def _to_unix(s: pd.Series) -> pd.Series:
    if pd.api.types.is_numeric_dtype(s):
        return s.astype(float)
    return pd.to_datetime(s, errors="coerce", utc=True).astype("int64") / 1e9


def _action(channel, eventid) -> str:
    try:
        eid = int(eventid)
    except (TypeError, ValueError):
        return "unknown"
    ch = str(channel).lower()
    if "sysmon" in ch:
        return SYSMON_ACTIONS.get(eid, f"sysmon_{eid}")
    if "security" in ch:
        return SECURITY_ACTIONS.get(eid, f"security_{eid}")
    return SYSMON_ACTIONS.get(eid) or SECURITY_ACTIONS.get(eid) or f"event_{eid}"


def _target_for_row(row: pd.Series) -> str:
    for f in TARGET_FIELDS:
        v = row.get(f)
        if pd.notna(v) and str(v) != "":
            return str(v)
    return str(row.get("_host", "unknown"))


def _derive_depth(pguid: pd.Series, ppguid: pd.Series) -> pd.Series:
    """Process-tree depth via ProcessGuid -> ParentProcessGuid, memoized."""
    parent = dict(zip(pguid.fillna(""), ppguid.fillna("")))
    cache: dict[str, int] = {}

    def depth(g: str, seen=()) -> int:
        if not g or g not in parent:
            return 0
        if g in cache:
            return cache[g]
        p = parent[g]
        d = 0 if (not p or p == g or p in seen) else 1 + depth(p, seen + (g,))
        cache[g] = d
        return d

    return pguid.fillna("").map(depth).astype(int)


# ---------------------------------------------------------------------------
# the adapter
# ---------------------------------------------------------------------------
def adapt_winlog_dataframe(df: pd.DataFrame,
                           malicious_guids: set | None = None) -> pd.DataFrame:
    """Windows event-log DataFrame -> normalized detector schema (+ technique)."""
    ts   = _coalesce(df, TS_FIELDS)
    host = _coalesce(df, HOST_FIELDS)
    eid  = _coalesce(df, EVENTID_FIELDS)
    chan = _coalesce(df, CHANNEL_FIELDS)
    if ts is None or eid is None:
        raise ValueError(
            "Could not find timestamp/EventID fields. Run inspect_dataset.py on "
            "the file and extend TS_FIELDS / EVENTID_FIELDS at the top of this module."
        )
    if chan is None:
        chan = pd.Series(["sysmon"] * len(df))   # assume Sysmon if unlabeled
    if host is None:
        host = pd.Series(["host"] * len(df))

    work = df.copy()
    work["_host"] = host.values
    pguid  = _coalesce(work, PGUID_FIELDS)
    ppguid = _coalesce(work, PPGUID_FIELDS)
    if pguid is None:
        pguid = pd.Series([""] * len(work))
    if ppguid is None:
        ppguid = pd.Series([""] * len(work))

    out = pd.DataFrame(index=work.index)
    # campaign: explicit id if present, else host
    camp = _coalesce(work, CAMPAIGN_FIELDS)
    out["campaign_id"] = (camp if camp is not None else host).astype(str).values
    out["ts"]     = _to_unix(ts).values
    out["action"] = [_action(c, e) for c, e in zip(chan.values, eid.values)]
    out["target"] = work.apply(_target_for_row, axis=1).values
    out["depth"]  = _derive_depth(pd.Series(pguid.values),
                                  pd.Series(ppguid.values)).values
    out["artifact_ai"] = 0.0     # not present in winlogs; left for a later scorer

    # label: explicit column, else from a set of malicious ProcessGuids, else 0
    lab = _coalesce(work, LABEL_FIELDS)
    if lab is not None:
        out["label"] = lab.astype(int).values
    elif malicious_guids is not None:
        out["label"] = pd.Series(pguid.values).isin(malicious_guids).astype(int).values
    else:
        out["label"] = 0

    tech = _coalesce(work, TECH_FIELDS)         # passthrough for multi-label task
    out["technique"] = (tech.astype(str).values if tech is not None else "")
    # detector_v1 reasons in named tactics, not raw ATT&CK ids -> add a mapped
    # column so winlog output drops straight into the multi-label heads.
    out["tactic"] = out["technique"].map(attack_id_to_tactic)

    out = out.dropna(subset=["ts"]).sort_values("ts").reset_index(drop=True)
    return out


# ---------------------------------------------------------------------------
# demo: fabricate Sysmon-like logs (benign + labeled attack chains) end-to-end
# ---------------------------------------------------------------------------
def make_demo_winlogs(n_benign=120, n_attack=40, seed=0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    gid = [0]

    def new_guid():
        gid[0] += 1
        return f"{{guid-{gid[0]}}}"

    def proc(host, ds, t, parent, image, eid, tech, mal, chan="Sysmon"):
        g = new_guid()
        rows.append(dict(
            **{"@timestamp": t, "Hostname": host, "dataset": ds,
               "Channel": f"Microsoft-Windows-{chan}/Operational",
               "EventID": eid, "Image": image,
               "ProcessGuid": g, "ParentProcessGuid": parent,
               "technique": tech, "is_malicious": mal}))
        return g

    base = 1.7e9
    # benign hosts: varied cadence (some automated/bursty) + occasional deep
    # build-tool trees, so timing and depth aren't clean tells.
    for i in range(n_benign):
        host, ds = f"WS-{i}", f"benign_{i}"
        t = base + rng.uniform(0, 1e6)
        bursty = rng.random() < 0.30
        cadence = rng.uniform(1.5, 4) if bursty else rng.uniform(6, 15)
        root = proc(host, ds, t, "", "C:\\Windows\\explorer.exe", 1, "", 0)
        cur = root
        for _ in range(int(rng.integers(30, 90))):
            t += rng.exponential(cadence)
            eid = int(rng.choice([1, 3, 11, 13], p=[.4, .25, .2, .15]))
            # build tools occasionally spawn child processes -> deeper benign tree
            parent = cur if (eid == 1 and rng.random() < 0.3) else root
            g = proc(host, ds, t, parent, rng.choice(
                ["chrome.exe", "outlook.exe", "svchost.exe", "code.exe", "msbuild.exe"]),
                eid, "", 0)
            if eid == 1 and rng.random() < 0.3:
                cur = g

    # attack campaigns: kill-chain, but 25% go low-and-slow / shallow so they
    # overlap benign and cap achievable recall (realistic ceiling).
    for i in range(n_attack):
        host, ds = f"WS-A{i}", f"attack_{i}"
        t = base + rng.uniform(0, 1e6)
        slow = rng.random() < 0.25
        cadence = rng.uniform(5, 10) if slow else rng.uniform(0.5, 2.5)
        rows.append(dict(**{"@timestamp": t, "Hostname": host, "dataset": ds,
                            "Channel": "Security", "EventID": 4624,
                            "Image": "", "ProcessGuid": "", "ParentProcessGuid": "",
                            "technique": "T1078", "is_malicious": 1}))   # valid acct
        p = proc(host, ds, t + 1, "", "C:\\Windows\\System32\\cmd.exe", 1, "T1059", 1)
        ps = proc(host, ds, t + 2, p, "powershell.exe", 1, "T1059.001", 1)
        for _ in range(int(rng.integers(30, 80))):
            t += rng.exponential(cadence)
            kind = rng.choice(["net", "file", "reg", "child", "noise"],
                              p=[.3, .2, .15, .15, .2])
            if kind == "net":
                proc(host, ds, t, ps, "powershell.exe", 3, "T1071", 1)
            elif kind == "file":
                proc(host, ds, t, ps, "powershell.exe", 11, "T1105", 1)
            elif kind == "reg":
                proc(host, ds, t, ps, "powershell.exe", 13, "T1547", 1)
            elif kind == "child" and not slow:
                ps = proc(host, ds, t, ps, "rundll32.exe", 1, "T1059", 1)
            else:  # ordinary-looking activity, like a real attacker blending in
                proc(host, ds, t, ps, "chrome.exe", 1, "T1059", 1)
    return pd.DataFrame(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--demo", action="store_true")
    ap.add_argument("--data", type=str, help="path to a real winlog file (.json/.csv/.parquet)")
    args = ap.parse_args()

    if args.data:
        from inspect_dataset import load_any
        norm = adapt_winlog_dataframe(load_any(args.data))
    else:
        raw = make_demo_winlogs()
        print(f"[demo] generated {len(raw):,} Sysmon/Security-style events")
        norm = adapt_winlog_dataframe(raw)

    print("\n--- normalized output (head) ---")
    print(norm.head(8).to_string(index=False))
    print(f"\nrows: {len(norm):,}   campaigns: {norm.campaign_id.nunique()}")
    print(f"event label rate: {norm.label.mean():.3f}")
    print("action mix:", dict(norm.action.value_counts().head(6)))
    print("max process depth:", int(norm.depth.max()))
    nz = norm[norm.technique != ""]
    print("ATT&CK techniques present:", sorted(nz.technique.unique())[:12])
    mapped = norm[norm.tactic != ""]
    print("mapped to detector_v1 tactics:", sorted(mapped.tactic.unique()))
    unmapped = sorted(set(nz.technique) - set(norm.loc[norm.tactic != "", "technique"]))
    if unmapped:
        print("  (unmapped ids -> extend ATTACK_ID_TO_TACTIC):", unmapped)

    # end-to-end check: feed normalized events through the existing detector
    try:
        from detector_v0 import windowize, run
        # promote campaign-level label (a campaign is attack if any event is)
        camp_label = norm.groupby("campaign_id")["label"].max()
        norm["label"] = norm["campaign_id"].map(camp_label)
        res = run(windowize(norm), seed=0)
        print(f"\n--- end-to-end through detector_v0 ---")
        print(f"PR-AUC {res.pr_auc:.3f} | precision {res.precision:.3f} | "
              f"recall {res.recall:.3f} | FP/hr {res.fp_per_hour:.2f}")
        print("(confirms the adapter output is consumable by the full pipeline)\n")
    except ImportError:
        print("\n(detector_v0 not importable here; adapter output shown above)\n")


if __name__ == "__main__":
    main()
