# `pipeline/` — host telemetry → CERNIS detector

A real-data ingest path for the CERNIS host detector. Takes Sysmon dumps
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
├── atomic_to_labels.py       # Atomic Red Team invocations -> labels (phase 2)
├── ingest_sysmon.py          # Sysmon dump -> normalized DataFrame
├── provenance_host.py        # data/host/manifest.jsonl writer
├── score_campaign.py         # the orchestrator (ingest -> score -> emit)
├── score_heldout_emulation.py # held-out emulation-family eval (phase 2)
├── alert_fatigue.py          # window-rate FP/hour arithmetic (phase 3)
│                             #   + --multi-day + --deployments-file (phase 4)
│                             #   + --per-eid-attribution (phase 5)
├── calibrate_eventrate.py    # real-Sysmon → deployments.json (phase 4)
├── per_eid_attribution.py    # benign dropout + composition + attack
│                             #   dropout (--target-class) (phase 5 + 6)
├── COLLECTOR_TUNING.md       # operator cookbook (phase 4 + 5)
├── synth_caldera.py          # synthetic CALDERA campaign
├── synth_atomic.py           # synthetic Atomic campaign        (phase 2)
├── synth_workload.py         # synthetic normal-workload campaign (phase 2)
├── synth_hard_negatives.py   # synthetic hard-negative bursts   (phase 2)
├── smoke.py                  # phase 1 smoke
├── smoke_phase2.py           # phase 2 smoke
├── smoke_phase3.py           # phase 3 smoke
├── smoke_phase4.py           # phase 4 smoke
├── smoke_phase_host_5.py     # phase 5 smoke
├── smoke_phase_host_6.py     # phase 6 smoke
└── README.md                 # this file
data/host/
├── manifest.jsonl            # append-only provenance, one row per campaign
├── alert_fatigue.json        # window-rate arithmetic output (phase 3+4+5)
├── deployments.json          # calibrated deployment shapes  (phase 4)
├── per_eid_attribution.json  # benign per-EID dropout + composition  (phase 5)
├── per_eid_attack_attribution.json  # attack per-EID dropout         (phase 6)
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

- ~~Re-documented alert-fatigue arithmetic on real data.~~
  **Phase 3 ships this** — see the section below.
- **WEC / winlogbeat collector tuning docs.** Lab-side; the real-data
  section sketches the shape but doesn't go deep.
- **Multi-day campaign aggregation.** One campaign = one CALDERA op
  or one shift of activity for now. Spanning days requires either
  longer windows or a different group key.

## Phase 3 — alert-fatigue arithmetic (host-side, window-rate-based)

The web harness side computes FP/hour at the **session** level:

```
E[FP/hour] = p_session × (60 / μ_minutes)
```

The host pipeline doesn't have sessions. It has **32-event windows**
produced continuously as Sysmon events stream in. So the host-side
arithmetic is window-rate-based, derived from real per-window FP
rates measured at the threshold τ.

### The formula

```
Per-window FP rate at τ (measured from eval set, per benign class):
  p_w(class, subtype) = P(score >= τ | label = 0, class, subtype)

Continuous-workload window-production rate for a deployment of N
hosts each emitting R events/sec across Sysmon EID 1, 3, 11, 13, …:
  W_total = N × R × 3600 / WINDOW_STRIDE   windows/hour

Expected FPs/hour from normal background workload:
  E[FP/hour | normal] = p_w(normal) × W_total

Sanctioned hard-negative bursts (PS remoting, scheduled tasks,
WMI, sanctioned scans, backup jobs) generate brief windows of
elevated event rate. For each subtype b with duration D_b
seconds, burst event rate R_b, fired F_b bursts/host/day:
  windows_per_burst = D_b × R_b / WINDOW_STRIDE
  bursts_per_hour   = F_b × N / 24
  E[FP/hour | b]    = p_w(b) × windows_per_burst × bursts_per_hour

Total expected FPs/hour at τ:
  E[FP/hour] = E[FP/hour | normal] + Σ_b E[FP/hour | b]
```

### MTTD

Mean time-to-detect per attack family (CALDERA, Atomic): for each
attack campaign, the wall-clock from the campaign's first window to
the first window whose score >= τ. Reported separately per family so
the held-out family's MTTD can be compared to in-distribution. A
flat-line MTTD on the held-out family is the same signal
`heldout_emulation`'s low recall surfaces — alert-fatigue tooling
makes it operationally legible.

### Tooling

`pipeline/alert_fatigue.py` runs the whole computation end-to-end
against whatever campaigns are in `data/host/manifest.jsonl`:

```sh
# all campaigns in data/host/, default 3-deployment matrix
python3 -m pipeline.alert_fatigue --fp-budget 1.0

# override deployment shape
python3 -m pipeline.alert_fatigue --hosts 200 --event-rate 2.0

# tighter alert budget
python3 -m pipeline.alert_fatigue --fp-budget 0.25
```

The script:
1. Loads every campaign's metadata + Sysmon JSONL.
2. Normalizes + windowizes.
3. Stratified-splits campaigns by (class, framework, benign_subtype)
   so eval has at least one of each bucket.
4. Trains `HistGradientBoostingClassifier` on the train split.
5. Picks τ at the FP-budget against the eval window-rate.
6. Computes `p_w(normal)` + `p_w(b)` for each hard-negative subtype
   present in eval.
7. Computes MTTD per attack framework.
8. Applies the deployment-shape arithmetic for `small_office (10h,
   1.0 evt/s)`, `med_business (50h, 1.5/s)`, `large_business (200h,
   2.0/s)` by default — overridable via `--hosts` / `--event-rate`.
9. Writes `data/host/alert_fatigue.json` + prints a readable summary.

### Default hard-negative burst shapes (override in code if needed)

| benign_subtype | bursts/host/day | duration (s) | burst event rate (/s) |
|---|---|---|---|
| `ps_remoting` | 4 | 300 | 6.0 |
| `wmi` | 12 | 60 | 5.0 |
| `sched_task` | 6 | 30 | 3.0 |
| `sanctioned_scan` | 1 | 600 | 8.0 |
| `backup` | 2 | 900 | 4.0 |

These are starting points calibrated against the phase-host-2 synth
generators. **Replace them with measurements from your range** before
trusting the deployment estimates.

### Worked example (synth data, structural)

After running the phase-host-2 synth pipeline through
`score_campaign.py` on 6 campaigns (1 CALDERA + 1 Atomic + 1 normal +
3 hard-negative subtypes):

```
[alert_fatigue] threshold τ                = 0.974  (budget 1.00 FP/hour)
[alert_fatigue] benign window duration est = 174.3s
[alert_fatigue] per-window FP on normal    = 0.0000  (0/17 windows)
[alert_fatigue] MTTD per attack family:
        atomic  detected 0/1  MTTD=n/a
       caldera  detected 1/1  MTTD=174.3s
[alert_fatigue] deployment FP/hour estimates:
   small_office  hosts=10   R=1.0/s  total=0.00/h
   med_business  hosts=50   R=1.5/s  total=0.00/h
   large_business hosts=200 R=2.0/s  total=0.00/h
```

Numbers are zero because the synth dataset's per-window FP rate is
zero — the model trivially separates the small synth distributions.
**The synth output validates that the tooling runs; it tells you
nothing about real production behavior.**

Note the interesting structural signal: CALDERA campaign detected,
Atomic campaign missed. That's the held-out-emulation gap from phase
2 showing up through the alert-fatigue lens. On real range data the
same number tells you "your detector is blind to one attack family"
in operational terms.

### Swap in real-range data

Real numbers require real campaigns under `data/host/`. The minimum
viable real-data run:

1. **One CALDERA campaign** through your authorized lab (phase-host-1
   real-data section). Stage it.
2. **One Atomic Red Team campaign** (phase-host-2 real-data section)
   covering the same 6 tactics. Stage it.
3. **At least one 24-hour normal-workload capture** — point Sysmon
   at an ordinary workstation for a day, dump that as `sysmon.jsonl`,
   write a hand-built `workload.json` with `class=normal,
   framework=scripted, ts_start, ts_end, host_list`. Score it.
4. **One or more hard-negative captures** — schedule a sanctioned
   PowerShell remoting session, a WMI sweep, a backup job, etc.
   Dump each as a separate campaign with `class=hard_negative,
   benign_subtype=<one_of_the_5>`. Score them.
5. Calibrate the per-subtype `bursts_per_host_per_day` shapes against
   your environment (read your incident-response runbooks or count
   from `4698` / `5140` / `wsmprovhost.exe` events over a sample
   period).
6. Run `python3 -m pipeline.alert_fatigue --fp-budget <your_budget>
   --hosts <fleet_size> --event-rate <observed_evt_per_sec>`.

The output gives you, **at the budget you can actually staff**:

- The threshold τ to deploy.
- The MTTD you can expect per attack family.
- A breakdown of where alerts come from — continuous workload noise
  vs each sanctioned-admin burst class.
- A flag (via the `detected_rate < 1.0` row) when an emulation family
  is silently missing from your detector's blind spot.

### What phase 3 explicitly does *not* do

- ~~Multi-day campaign aggregation.~~ **Phase 4 ships this** —
  see the section below.
- ~~WEC / winlogbeat collector tuning docs.~~ **Phase 4 ships
  `COLLECTOR_TUNING.md`** — operator-facing Sysmon exclusion guidance
  + expected per-host rate ranges + per-EID FP attribution recipe.
- **Auto-discovery of `bursts_per_host_per_day`.** The defaults are
  hand-calibrated against synth; production deployments should
  measure their own via the runbook count described above.

## Phase 4 — real-data calibration, multi-day aggregation, collector tuning

Phase 3 produced defensible arithmetic with synthetic-derived per-host
event rates and hand-tuned deployment shapes. Phase 4 closes the gap to
real deployments along three axes.

### Calibrate against real Sysmon (`pipeline/calibrate_eventrate.py`)

Read-only: load any Sysmon dump (JSONL / CSV / Parquet), measure the
combined per-host event rate plus per-minute burst distribution, emit
a `deployments.json` that `alert_fatigue --deployments-file` consumes
in place of the built-in `DEFAULT_DEPLOYMENTS`.

```sh
python3 -m pipeline.calibrate_eventrate \
    --sysmon /path/to/sysmon.jsonl \
    --hosts-per-deployment "10,50,200" \
    --out data/host/deployments.json
```

The output includes:

- `events_per_sec_per_host.overall` — steady-state rate.
- `events_per_sec_per_host.minute_bucket_p50` / `p95` — burst
  spread. The gap between these is your burstiness budget.
- `per_eid` — share of total events per Sysmon EID, ranked. The
  top-3 EIDs usually account for >80% of volume; that's where
  collector tuning has the most leverage.
- `deployments` — suggested shapes ready for `alert_fatigue`.

### Multi-day partition (`alert_fatigue --multi-day`)

Single-day FP/hour estimates hide diurnal swings. With `--multi-day`,
`alert_fatigue` partitions eval campaigns by the UTC date of their
`ts_start` and emits, at the **same** fitted τ, per-day per-class FP
rate plus per-deployment FP/hour distribution (median / p95 / min /
max) across days.

```sh
python3 -m pipeline.alert_fatigue \
    --deployments-file data/host/deployments.json \
    --fp-budget 1.0 \
    --multi-day
```

τ stays fixed by design: jittering the threshold day-to-day would
hide the FP-rate drift the operator is trying to see. What varies
day-to-day is the *realized* per-window FP rate, and therefore the
FP/hour the operator would pay at a constant alarm budget.

The new `daily` block in `alert_fatigue.json`:

```jsonc
"daily": {
  "days": [
    {"date": "2026-06-19", "n_campaigns": 2,
     "per_class_fp_rate": {...},
     "per_hard_negative_subtype_fp_rate": {...},
     "deployment_estimates": [...]},
    ...
  ],
  "deployment_distribution": [
    {"deployment": "calibrated_med_business_50h",
     "n_days": 3,
     "median_total_fp_per_hour": 0.42,
     "p95_total_fp_per_hour": 1.18,
     "min_total_fp_per_hour": 0.21,
     "max_total_fp_per_hour": 1.20}
  ]
}
```

A 2× or wider spread between median and p95 is the signal that a
point-estimate is misleading and the threshold's safety margin is
smaller than it looks.

### Collector tuning cookbook (`pipeline/COLLECTOR_TUNING.md`)

Operator-facing doc covering:

- Expected per-host event-rate ranges by workstation class (kiosk /
  office / dev / build host / DC / file server).
- Noisy-EID list (10, 12/13/14, 22, 23, 5) with concrete Sysmon
  exclusion-stanza XML snippets.
- Per-EID FP attribution: how to combine `calibrate_eventrate`'s
  `per_eid.share` with `alert_fatigue`'s `per_class_fp_rate.normal`
  to rank which EIDs to filter first.
- Burst-shape encoding workflow for sanctioned activity that doesn't
  match the five built-in subtypes.
- Multi-day calibration discipline: ≥7 days before pinning
  production thresholds; re-calibrate when the daily median-vs-p95
  spread exceeds 2×.

### Smoke

```sh
python3 -m pipeline.smoke_phase4    # no docker, no real Sysmon
```

Stages the phase-host-2 synth set, re-stamps `ts_start` values to
span 3 distinct UTC dates, runs calibrate → `--deployments-file` →
`--multi-day`, and asserts each output's shape (per-EID share,
suggested deployments, daily distribution, populated min / median /
p95 / max stats).

### What phase 4 explicitly does *not* do

- **Automatic Sysmon config edits.** Exclusion-stanza XML is supplied;
  deploying it through GPO / config management is still manual.
- ~~Per-EID FP attribution at window granularity.~~ **Phase 5 ships
  this** — see the section below.
- **On-host agent threshold deployment.** The arithmetic is offline;
  pushing the picked τ to a running detector is out of scope here.

## Phase 5 — per-EID FP attribution at window granularity

Phase 3 + 4 give you total normal-workload FP/hour at a fitted
threshold τ and let you calibrate deployment shapes from real Sysmon.
`COLLECTOR_TUNING.md §4` told you which EIDs to filter using an
approximation: `fp_per_hour_X ≈ share_X × p_w × W_total`. Phase 5
replaces that with two real measurements.

### `pipeline/per_eid_attribution.py`

Two complementary views against a held-back normal-workload campaign:

1. **Dropout attribution** (marginal effect): for each EID X in the
   campaign, filter its events out, re-windowize + re-score with the
   same trained classifier at the same τ, measure the delta in
   per-window FP rate. `contribution_X = FP_rate(all) − FP_rate(all \ {X})`.
   Positive = EID adds FPs; negative = filtering it would actually
   make detection worse (the detector uses it for context).

2. **Per-window EID composition** (descriptive): for every scored
   window, record the dominant EID + share. Bucket windows by
   dominant EID; compute FP rate per bucket. Surfaces "windows
   where EID 10 is the majority fire at X% FP rate" as a concrete
   signal independent of dropout.

The two views are complementary: dropout ranks EIDs by marginal
effect; composition validates the rank by showing whether the
high-dropout EIDs also have high-FP buckets.

```sh
python3 -m pipeline.per_eid_attribution \
    --campaign workload-001 \
    --fp-budget 1.0 \
    --out data/host/per_eid_attribution.json
```

### `alert_fatigue --per-eid-attribution`

When `data/host/per_eid_attribution.json` exists,
`pipeline.alert_fatigue` auto-discovers it and attaches a
`per_eid_contributions` block to each `deployment_estimate`. Per-EID
FP/hour at deployment D is the real-measurement value:

    fp_per_hour_X = contribution_X × windows_per_hour_continuous(D)

The output ranks EIDs by `|fp_per_hour|` so the noisiest land first.
`alert_fatigue.json` carries `per_eid_attribution_source` so the
operator knows which attribution file fed the numbers.

### Smoke

```sh
python3 -m pipeline.smoke_phase_host_5    # no docker, no real Sysmon
```

Stages the phase-host-2 synth set, runs per_eid_attribution against
the workload campaign, verifies the dropout view has one row per
distinct EID + the composition view buckets by dominant EID, runs
alert_fatigue with the auto-discovered attribution and confirms the
new `per_eid_contributions` block lands on each deployment estimate.
NEVER reports accuracy.

### What phase 5 explicitly does *not* do

- ~~Per-EID attribution on attack campaigns.~~ **Phase 6 ships this** —
  see the section below.
- ~~Per-EID × per-deployment cost-benefit analysis.~~ **Phase 6 ships
  this** — see the section below.
- **Sysmon config XML auto-generation** from the dropout ranking.
  The cookbook tells you which EIDs to filter; deploying via GPO
  is still manual.

## Phase 6 — attack-side per-EID attribution + cost-benefit

Phase 5 measures filtering *cost saved* (FP/hour reduction on benign
workload). Phase 6 measures filtering *cost paid* (recall lost on
attack campaigns) and combines the two views into a rank-by-trade-off
operator output.

### `pipeline/per_eid_attribution.py --target-class attack`

Same dropout pattern as phase 5, but against an attack campaign and
measuring the WINDOW-LEVEL DETECTION RATE delta at the trained τ:

```
contribution_to_detect_rate_X = detect_rate(all) - detect_rate(all \ {X})
```

Positive = EID X is load-bearing for detection; filtering loses
recall. Negative = filtering helps. The attack-side run uses the same
HistGradientBoostingClassifier + τ as alert_fatigue, so the numbers
trade off cleanly with the phase-5 benign attribution.

```sh
python3 -m pipeline.per_eid_attribution \
    --campaign synth-caldera-001 \
    --target-class attack \
    --out data/host/per_eid_attack_attribution.json
```

### `alert_fatigue --per-eid-attack-attribution`

When BOTH `data/host/per_eid_attribution.json` (benign) AND
`data/host/per_eid_attack_attribution.json` (attack) exist,
`alert_fatigue` auto-discovers them and attaches a
`per_eid_cost_benefit` block to each deployment estimate:

```
EID    fp_per_hour_saved   recall_lost   ranking_score
  1     +18.92 / h         +0.080        +10.92
 13     +3.60  / h          0.000        +3.60
 10     +8.55  / h         +0.120        -3.45
```

Default ranking score: `fp_per_hour_saved − recall_weight × recall_lost`
with `recall_weight=100` (a 1pp recall drop = 1 FP/hour saved). Tune
with `--recall-weight N` for your operational reality. Highest score =
best filter candidate.

Report carries `per_eid_cost_benefit_meta` with both source paths +
the recall weight used so the operator can reproduce.

### Smoke

```sh
python3 -m pipeline.smoke_phase_host_6
```

Stages the phase-host-2 synth set, runs per_eid_attribution in BOTH
modes, runs alert_fatigue with and without the attack attribution
file, asserts the cost-benefit shape + recall_weight tuning behavior.

### What phase 6 explicitly does *not* do

- **Sysmon config XML auto-generation** from the cost-benefit ranking.
  The output tells you which EIDs to filter; deploying via GPO is
  still manual.
- **Per-EID-share-aware threshold tuning** (composite τ optimization
  across EIDs). Out of scope; see backlog.
- **Multi-attack-family attribution**. Today the attack-side dropout
  runs against ONE campaign at a time. Aggregating across CALDERA +
  Atomic + a custom emulation family at once is a phase-host-7 item.

## What phase 1 explicitly does *not* do (historical)

Phase 1 originally deferred Atomic, normal-workload, hard-negative,
held-out family sweep, and per-subtype FP reporting to phase 2. All
five shipped in phase 2.
