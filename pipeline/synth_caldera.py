"""Synthesize a CALDERA-flavored campaign for in-sandbox validation.

Real-data path:
  1. Run a CALDERA op on your isolated lab range.
  2. Copy the op's REST report JSON to data/host/<campaign_id>/caldera_op.json.
  3. Copy the matching Sysmon dump (JSONL) to
     data/host/<campaign_id>/sysmon.jsonl.
  4. python -m pipeline.score_campaign --campaign <campaign_id>

This module is the *synthetic* dry-run that exercises the same code
path without needing the range: it reuses adapter_winlogs.make_demo_winlogs
to produce realistic Sysmon-like events, then writes a faux CALDERA
op report whose `steps` line up with the malicious ProcessGuids the
demo generator created. The exit criterion is "the pipeline runs
end-to-end and the provenance + scoring files come out shaped right" —
not "PR-AUC is high." One synthetic campaign is too small to set a
quality bar.
"""

from __future__ import annotations

import json
import pathlib
import random
import time
from typing import Optional


SIX_TACTIC_TECHNIQUES = {
    "recon": "T1595",
    "discovery": "T1046",
    "credential_access": "T1003",
    "command_execution": "T1059",
    "lateral_movement": "T1021",
    "exfiltration": "T1041",
}


def write_synth_campaign(
    out_dir: pathlib.Path,
    *,
    campaign_id: str,
    n_attack_hosts: int = 1,
    n_benign_hosts: int = 6,
    seed: int = 0,
) -> dict:
    """Write sysmon.jsonl + caldera_op.json into out_dir.

    Returns metadata: {campaign_id, host_list, abilities, tactic_coverage,
    ts_start, ts_end, malicious_guid_count}.
    """
    from adapter_winlogs import make_demo_winlogs

    out_dir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(seed)

    df = make_demo_winlogs(
        n_benign=n_benign_hosts, n_attack=n_attack_hosts, seed=seed,
    )

    # Discover the attack-tagged events from the demo generator: their
    # `dataset` column starts with "attack_". For each attack host, mint
    # a CALDERA-flavored step per the six required tactics, time-aligned
    # to the actual events that fired.
    attack_rows = df[df["dataset"].str.startswith("attack_", na=False)]
    hosts = sorted(attack_rows["Hostname"].dropna().unique())

    steps: list[dict] = []
    abilities: list[str] = []
    for host in hosts:
        host_events = attack_rows[attack_rows["Hostname"] == host]
        if host_events.empty:
            continue
        ts_lo = float(host_events["@timestamp"].min())
        ts_hi = float(host_events["@timestamp"].max())
        # spread the six abilities across the host's attack timeline
        span = max(1.0, (ts_hi - ts_lo) / 6.0)
        for i, (tactic, tech) in enumerate(SIX_TACTIC_TECHNIQUES.items()):
            t0 = ts_lo + i * span + rng.uniform(0.0, 0.5)
            t1 = t0 + rng.uniform(0.5, 2.0)
            ability = f"caldera_{tactic}_{tech.lower()}"
            abilities.append(ability)
            steps.append({
                "host": host,
                "technique_id": tech,
                "t_start": t0,
                "t_end": t1,
                "ability_name": ability,
                "ability_id": f"abil-{tech.lower()}",
                "command_hash": f"{rng.randrange(16**8):08x}",
            })

    ts_start = float(df["@timestamp"].min())
    ts_end = float(df["@timestamp"].max())

    op_report = {
        "operation": {
            "id": campaign_id,
            "name": f"synth-{campaign_id}",
            "adversary": "synth_six_tactic",
            "start": ts_start,
            "finish": ts_end,
            "host_list": hosts,
            "steps": steps,
        }
    }

    # sysmon.jsonl: write each row as a single-line JSON object; the
    # raw winlog field names are exactly what adapter_winlogs already
    # coalesces over, so no transformation here.
    sysmon_path = out_dir / "sysmon.jsonl"
    with sysmon_path.open("w") as f:
        for row in df.to_dict(orient="records"):
            # JSON-safe: drop NaN (json.dumps would emit `NaN`, which is
            # not strictly valid). adapter handles missing fields fine.
            clean = {k: v for k, v in row.items() if v == v}  # NaN != NaN
            f.write(json.dumps(clean, separators=(",", ":")) + "\n")
    (out_dir / "caldera_op.json").write_text(json.dumps(op_report, indent=2))

    # mirror the malicious guids the demo generator created so the
    # caller can sanity-check labeling without re-running the join
    mal = set(df.loc[df["is_malicious"] == 1, "ProcessGuid"].dropna().tolist())

    return {
        "campaign_id": campaign_id,
        "host_list": hosts,
        "abilities": abilities,
        "tactic_coverage": list(SIX_TACTIC_TECHNIQUES.keys()),
        "ts_start": ts_start,
        "ts_end": ts_end,
        "malicious_guid_count": len(mal),
        "n_events": len(df),
    }


def cli(argv: Optional[list[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--campaign", default="synth-001",
                    help="campaign_id (also the data/host/ subdir name)")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--n-benign-hosts", type=int, default=6)
    ap.add_argument("--n-attack-hosts", type=int, default=1)
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    args = ap.parse_args(argv)

    out_dir = args.out / args.campaign
    meta = write_synth_campaign(
        out_dir,
        campaign_id=args.campaign,
        n_attack_hosts=args.n_attack_hosts,
        n_benign_hosts=args.n_benign_hosts,
        seed=args.seed,
    )
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(cli())
