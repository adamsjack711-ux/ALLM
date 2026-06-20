# `pipeline/` — host telemetry → ALLM detector

A real-data ingest path for the ALLM host detector. Takes Sysmon dumps
from an authorized lab range, joins them against a CALDERA operation
report to recover attack labels, normalizes via `adapter_winlogs`,
windowizes (32 events, the same shape `detector_v0..v3` expect), runs
the detector, and writes:

- `data/host/<campaign_id>/scored.jsonl` — per-window risk + tactic.
- `data/host/manifest.jsonl` — append-only per-campaign provenance.

Phase 1 ships the structural ingest path + provenance writer + a
synthetic dry-run that exercises the full pipeline in-sandbox. The
real-CALDERA validation is a one-command rerun on lab-range data; the
range itself is out of scope for this sandbox (which blocks
`huggingface.co` with `HTTP 403` and has no path to your Windows VMs).

## Layout

```
pipeline/
├── caldera_op_to_labels.py   # CALDERA op JSON -> Steps + malicious_guids
├── ingest_sysmon.py          # Sysmon dump -> normalized DataFrame
├── provenance_host.py        # data/host/manifest.jsonl writer
├── synth_caldera.py          # in-sandbox synthetic campaign generator
├── score_campaign.py         # the orchestrator (ingest -> score -> emit)
└── README.md                 # this file
data/host/
├── manifest.jsonl            # append-only provenance, one row per campaign
└── <campaign_id>/
    ├── sysmon.jsonl          # range collector dump (you drop this)
    ├── caldera_op.json       # CALDERA op report (you drop this)
    └── scored.jsonl          # output
```

## In-sandbox dry-run (synthetic CALDERA campaign)

```sh
python3 -m pipeline.synth_caldera --campaign synth-001
python3 -m pipeline.score_campaign --campaign synth-001 \
    --synth-mix 8 --adversary synth_six_tactic --generator-version "synth-0.1"
```

The synth generator extends `adapter_winlogs.make_demo_winlogs` to also
write a faux `caldera_op.json` whose `steps` cover all six tactics
(`recon, discovery, credential_access, command_execution,
lateral_movement, exfiltration`). The scorer mixes in a small set of
synthetic background campaigns (`--synth-mix N`) so the
`GroupShuffleSplit` baseline detector has multiple positive and
negative groups to split.

Expected output (PR-AUC on synth is high because the demo generator's
attack and benign distributions diverge cleanly — this is not a real
quality claim, it's a structural pass check):

```
[score] campaign=synth-001
[score]   events=389  steps=6  techniques=['T1003', 'T1021', …, 'T1595']
[score]   tactic_coverage=['command_execution', 'credential_access', …]
[score]   malicious_guids=24  host_window_fallbacks=1
[score]   normalized events: 953  campaigns: 11
[score]   windows: 44  (target campaign: 23)

PR-AUC          : <reported, never asserted on synth>
FP/hour         : <reported>
per-tactic recall (target campaign):
     command_execution  recall=1.00  n=9
[score] provenance row appended -> data/host/manifest.jsonl
[score] scored -> data/host/synth-001/scored.jsonl
```

The synth Sysmon events only carry the technique IDs the demo
generator emits (`T1059`, `T1071`, `T1105`, …), which don't fully
overlap with the CALDERA op's `T1595/T1046/T1003/T1059/T1021/T1041`
spread — that's why `per-tactic recall` on synth surfaces fewer
tactics than the op claims. On a real CALDERA run, each Sysmon event
is timestamped near a step and inherits the step's technique via the
ProcessGuid join in `caldera_op_to_labels.resolve_labels`, so all six
tactics surface in `scored.jsonl`.

## Real-data run (runs *outside* this sandbox)

This sandbox can't talk to a CALDERA server or the Windows VMs, so the
range-side steps run on your authorized lab. Once you have a CALDERA op
report + matching Sysmon dump, the pipeline is the same one command.

### 1. Lab range (one-time setup)

Authorized, isolated VM range you control. Indicative:

- 2–3 Windows 10/11 / Server 2022 VMs, all on a flat private network
  with no internet egress.
- Sysmon installed on each VM with [SwiftOnSecurity's config][soc-sysmon]
  (or [Olaf Hartong's modular config][olaf-sysmon]), high-fidelity
  process/network/file logging.
- Windows event logging dialed up: Security 4624/4625/4688/4672/4698,
  Sysmon 1/3/7/8/10/11/12/13/22.
- Events shipped to a collector (winlogbeat → Elasticsearch / OpenSearch,
  or NXLog → flat JSONL on disk). Capture the Sysmon config XML SHA so
  re-runs reproduce the same field coverage.
- CALDERA server running on its own VM, agents enrolled on each Windows
  host. Pick an adversary profile that covers all six tactics this
  project models — adversary builder, or one of the bundled profiles
  (`thief`, `red_alice`, `red_tlousand`) extended with the tactics this
  detector cares about.

[soc-sysmon]: https://github.com/SwiftOnSecurity/sysmon-config
[olaf-sysmon]: https://github.com/olafhartong/sysmon-modular

### 2. Run a CALDERA operation

Pick an adversary that covers all six tactics. Start the op, let it
run to completion, then export the operation report:

```sh
# from the CALDERA host
curl -s -H "KEY: <api_key>" \
    http://<caldera>:8888/api/v2/operations/<op_id>/report \
    > caldera_op.json
```

Equivalently, the CALDERA UI's "Download report" button on the
operation page writes the same JSON.

### 3. Dump the matching Sysmon range

Filter by `(host ∈ <attack hosts>, ts ∈ [op.start - 1m, op.finish + 1m])`
to a `sysmon.jsonl` file — one event per line, raw Sysmon field names.
Most collectors can export this directly; if you're going through
Elasticsearch:

```sh
elasticdump --input=http://es:9200/winlogbeat-* --output=sysmon.jsonl \
    --searchBody='{"query":{"bool":{"must":[
        {"range":{"@timestamp":{"gte":"<op.start>","lte":"<op.finish>"}}},
        {"terms":{"host.name":["WS-1","WS-2"]}}]}}}'
```

Drop both files into `data/host/<campaign_id>/` on the box where this
repo lives:

```
data/host/op-2026-06-20/
├── caldera_op.json
└── sysmon.jsonl
```

### 4. Score it

```sh
python3 -m pipeline.score_campaign --campaign op-2026-06-20 \
    --synth-mix 0 \
    --adversary <adversary_profile_name> \
    --op-id <caldera_op_id> \
    --generator-version "caldera-<version_or_sha>"
```

If this is your *first* real campaign and you don't have a benign
baseline staged yet, leave `--synth-mix` at the default `6` — the
splitter needs at least one negative campaign to split. As you
accumulate normal-workload and hard-negative campaigns under
`data/host/`, drop `--synth-mix` to `0` and use those as the
denominator (phase 2 ships the normal-workload and hard-negative
generators).

## Provenance schema (`data/host/manifest.jsonl`)

Group key: `campaign_id`. Append-only. One row per scored campaign:

| field | example |
|---|---|
| `campaign_id` | `op-2026-06-20` |
| `ts_start`, `ts_end` | unix-seconds bounds of events in this campaign |
| `class` | `attack` / `normal` / `hard_negative` |
| `generator` | `caldera` / `atomic` / `scripted` / `manual` |
| `generator_version` | `caldera-5.0.1` |
| `caldera_adversary` | `red_alice` |
| `caldera_op_id` | the op id from CALDERA |
| `abilities` | `["caldera_recon_t1595", "caldera_discovery_t1046", …]` |
| `tactic_coverage` | subset of the six the op exercised |
| `host_list` | hosts that emitted events for this campaign |
| `config_sha` | 8-hex hash of the campaign config dict |
| `sysmon_config_sha` | 8-hex hash of the Sysmon XML config (if known) |
| `source_path` | relative dir under `data/host/` |
| `notes` | free-form |

## Phase 2 — Atomic Red Team + normal workload + hard negatives + held-out emulation

Phase 1 had a single source type (CALDERA) and a single class
(`attack`). Phase 2 widens both axes:

### Campaign sources (auto-detected per directory)

| metadata file | class | framework | use |
|---|---|---|---|
| `caldera_op.json` | `attack` | `caldera` | CALDERA operation report (phase 1) |
| `atomic_invocations.json` | `attack` | `atomic` | Atomic Red Team invocations log — the **held-out emulation family** |
| `workload.json` (class=`normal`) | `normal` | `scripted` | bulk benign baseline (browsing / IDE / Outlook / updates) |
| `workload.json` (class=`hard_negative`, with `benign_subtype`) | `hard_negative` | `scripted` | sanctioned admin activity that looks scary |

`score_campaign.py` auto-detects which file is present and routes to
the right labeler. For `class=normal` and `class=hard_negative` no
attack labels are resolved (`label=0` everywhere) but the campaign
still gets a provenance row + a `scored.jsonl` so the FP/hour
denominator sees it during eval.

### Held-out emulation family eval (`score_heldout_emulation.py`)

The host-side mirror of phase 8 on the web harness. For each direction
(`train_caldera_eval_atomic` and `train_atomic_eval_caldera`):

1. Train `HistGradientBoostingClassifier` on the train framework's
   attack campaigns plus ALL benign campaigns (normal + hard_negative).
   Hard-negatives appear in train so the model sees the "looks scary,
   isn't" pattern at least once.
2. Pick τ to meet the FP/hour budget on the eval slice (last 25% of
   benign campaigns by sort order + the eval framework's attack
   campaigns).
3. Report **PR-AUC**, **FP/hour**, **per-tactic macro recall** (over
   the six modeled tactics), and **hard-negative FP rate by
   `benign_subtype`** on the eval slice.
4. Swap directions; repeat.

NEVER reports accuracy. Output lands in `data/host/heldout_emulation.json`.

### Synth dry-run (in-sandbox)

```sh
# one of each campaign type
python3 -m pipeline.synth_caldera        --campaign synth-caldera-001
python3 -m pipeline.synth_atomic         --campaign synth-atomic-001
python3 -m pipeline.synth_workload       --campaign workload-001
python3 -m pipeline.synth_hard_negatives --campaign hardneg-ps-remoting-001 --benign-subtype ps_remoting
python3 -m pipeline.synth_hard_negatives --campaign hardneg-sched-task-001  --benign-subtype sched_task

# score them — each appends a provenance row + writes scored.jsonl
python3 -m pipeline.score_campaign --campaign synth-caldera-001 --synth-mix 6 --adversary synth_six_tactic
python3 -m pipeline.score_campaign --campaign synth-atomic-001  --synth-mix 6
python3 -m pipeline.score_campaign --campaign workload-001      --synth-mix 6
python3 -m pipeline.score_campaign --campaign hardneg-ps-remoting-001 --synth-mix 6
python3 -m pipeline.score_campaign --campaign hardneg-sched-task-001  --synth-mix 6

# held-out emulation eval
python3 -m pipeline.score_heldout_emulation
```

Or run the full sequence + assertions in one shot:

```sh
python3 -m pipeline.smoke_phase2     # ~13s, no docker, no real Sysmon
```

Smoke verifies: all five manifest rows have the expected (class,
framework, benign_subtype) combination, both attack campaigns cover
all six tactics, scored.jsonl is emitted per campaign, and the
held-out report has both directions populated with `pr_auc /
fp_per_hour / per_tactic / hard_negative_fp_by_subtype`.

### Real-data setup (runs *outside* this sandbox)

On your authorized lab range, alongside the phase-1 CALDERA setup:

**Atomic Red Team** — install on each Windows host, invoke per
technique from the operator's PowerShell session, capture each
invocation's `t_start` / `t_end`:

```ps1
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Import-Module invoke-atomicredteam
$invocations = @()
foreach ($tid in @("T1059","T1057","T1003","T1021","T1041","T1083")) {
    Invoke-AtomicTest $tid -GetPrereqs
    $ts = (Get-Date).ToUnixTimeSeconds()
    Invoke-AtomicTest $tid
    $te = (Get-Date).ToUnixTimeSeconds()
    $invocations += @{
        host = $env:COMPUTERNAME; technique_id = $tid
        atomic_name = $tid; t_start = $ts; t_end = $te
        executor = "powershell"; command_hash = ""
    }
}
@{ framework = "atomic-red-team"
   version = (Get-Module invoke-atomicredteam).Version.ToString()
   invocations = $invocations
} | ConvertTo-Json -Depth 5 > atomic_invocations.json
```

Drop `atomic_invocations.json` + matching Sysmon range into
`data/host/<campaign_id>/`, then `python3 -m pipeline.score_campaign`.

**Normal workload + hard negatives** — capture the matching Sysmon
range during ordinary user activity, and during sanctioned admin
work (PS remoting / WMI / scheduled tasks / internal vuln scan /
backup jobs). Drop into `data/host/<campaign_id>/` along with a
hand-written `workload.json` containing `class`, `framework`,
`host_list`, `ts_start`, `ts_end`, and (for hard negatives)
`benign_subtype`.

### What phase 2 explicitly does *not* do

- **Re-documented alert-fatigue arithmetic on real data.** The
  formula sits in the web harness README; the meaningful denominator
  on the host side comes from multi-day real-range telemetry, not
  five synth campaigns.
- **WEC / winlogbeat collector tuning docs.** Lab-side; the real-data
  section sketches the shape but doesn't go deep.
- **Multi-day campaign aggregation.** One campaign = one CALDERA op
  or one shift of activity for now. Spanning days requires either
  longer windows or a different group key.

## What phase 1 explicitly does *not* do (historical)

Phase 1 originally deferred Atomic, normal-workload, hard-negative,
held-out family sweep, and per-subtype FP reporting to phase 2. All
five are now shipped — see the section above.
