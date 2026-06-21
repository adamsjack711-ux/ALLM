# Collector tuning for the Cernis host detector

Operator notes for getting useful FP/hour numbers out of
`pipeline.alert_fatigue`. Three knobs matter, in order of impact:

1. **What you collect.** Sysmon EIDs vary by ~50× in volume.
2. **How many hosts you collect from.** Linear scaling, no surprises.
3. **What burst shapes you encode.** Hard-negative shapes drive the
   non-continuous half of the arithmetic.

This doc is the operator-facing side of phase-host-4. The mechanics it
references live in `alert_fatigue.py` (math) and `calibrate_eventrate.py`
(measure your own deployment).

## 1. Measure first

Don't tune blind. Run a 24-hour passive capture on a representative
host with your *production* Sysmon config, then:

```sh
python3 -m pipeline.calibrate_eventrate \
    --sysmon /path/to/sysmon.jsonl \
    --hosts-per-deployment "10,50,200" \
    --out data/host/deployments.json
```

This reports:

- `events_per_sec_per_host.overall` — your steady-state rate.
- `events_per_sec_per_host.minute_bucket_p95` — what a busy minute
  actually looks like. The gap between this and `overall` is your
  burstiness budget.
- `per_eid` — share of total events per Sysmon EID. The top-3
  EIDs usually account for >80% of volume.

Then feed the suggested shapes into the arithmetic:

```sh
python3 -m pipeline.alert_fatigue \
    --deployments-file data/host/deployments.json \
    --fp-budget 1.0 \
    --multi-day
```

The `--multi-day` flag partitions the eval campaigns by UTC date and
reports per-deployment FP/hour distribution (median / p95 / min / max)
at the same τ. A wide spread between median and p95 is the diurnal-swing
signal that says "your single-point estimate is misleading."

## 2. Expected per-host rate by host class

These are starting points — your actual numbers come from
`calibrate_eventrate`. Use these only as a sanity check ("does my
measurement land in the same order of magnitude").

| Host class | events/sec/host overall | Notes |
|---|---|---|
| Kiosk / single-purpose | 0.3 – 0.8 | Tight Sysmon config, idle most of the day |
| Office workstation | 0.8 – 1.6 | Typical user load: browser + chat + office |
| Developer workstation | 1.5 – 3.5 | Frequent compiler / interpreter / git activity |
| Build host / CI runner | 3.0 – 8.0 | Continuous process churn under load |
| Domain controller | 1.0 – 4.0 | LSASS-heavy, peaks at logon waves |
| File / print server | 0.5 – 2.0 | Stable, low process activity |

Outside this envelope by more than 3× usually means one of:

- A noisy EID (10 ProcessAccess, 12/13/14 RegistryEvent) is on with
  no exclusion filter — see §3.
- Sysmon is filtering out high-value EIDs (1 ProcessCreate, 3
  NetworkConnect, 11 FileCreate) and you're collecting only the
  long tail — the rate looks fine but the detector will be blind.

## 3. The noisy-EID list (drop or filter aggressively)

Top sources of "high volume / low detection value" rows we've seen in
real Sysmon dumps:

| EID | What it is | Why it's noisy | Reasonable filter |
|---|---|---|---|
| 10 | ProcessAccess | Every AV / EDR / debugger trips this on benign hosts | Exclude trusted security products by SHA256, include only LSASS-target access |
| 12/13/14 | RegistryEvent | Office / browser / installer churn | Exclude `\Software\Microsoft\Office\…`, `\Software\Google\Chrome\…`, focus on autorun + service hives |
| 22 | DnsQuery | Browser-tab spam | Exclude `Image` matching browser binaries, keep service-account queries |
| 23 | FileDelete | Build hosts blow this up | Exclude `\Users\<svc>\AppData\Local\Temp\…` |
| 5 | ProcessTerminate | Mirrors EID 1 — usually redundant | Drop entirely unless your detector needs explicit termination events |

A reasonable Sysmon config exclusion stanza for EID 10
(ProcessAccess) — drop in `<ProcessAccess onmatch="exclude">`:

```xml
<TargetImage condition="end with">\MsMpEng.exe</TargetImage>
<TargetImage condition="end with">\WmiPrvSE.exe</TargetImage>
<SourceImage condition="end with">\SearchProtocolHost.exe</SourceImage>
<GrantedAccess condition="is">0x1000</GrantedAccess>
<GrantedAccess condition="is">0x1400</GrantedAccess>
```

For EID 13 (RegistryEvent value set):

```xml
<TargetObject condition="contains">\Software\Microsoft\Office\</TargetObject>
<TargetObject condition="contains">\Software\Microsoft\Windows\CurrentVersion\Explorer\</TargetObject>
<TargetObject condition="end with">\MRUListEx</TargetObject>
<Image condition="end with">\OfficeClickToRun.exe</Image>
```

After applying exclusions, re-run `calibrate_eventrate` and compare:

- Per-EID share should redistribute toward EID 1 / 3 / 11 (the
  high-value triad).
- `minute_bucket_p95` should drop more than `minute_bucket_p50` —
  exclusions hit busy-minute spam hardest.

## 4. Per-EID FP attribution

`alert_fatigue.json` doesn't break FP down by EID directly, but the
combination of `calibrate_eventrate`'s `per_eid.share` and
`alert_fatigue`'s `per_class_fp_rate.normal.fp_rate` gives a rough
attribution. The arithmetic:

> If EID X accounts for `share_X` of all events, and the normal-workload
> per-window FP rate is `p_w`, then EID X's contribution to FP/hour at
> deployment D is approximately:
>
>     fp_per_hour_X ≈ share_X × p_w × (D.hosts × D.rate × 3600 / WINDOW_STRIDE)

This isn't exact — windows mix EIDs — but it's tight enough to rank
EIDs by impact and pick which filter to invest in first. The full per-
window-per-EID attribution would need windowized inference on a held-
back normal-workload campaign, which is a phase-host-5 item, not this
phase.

## 5. Burst shape encoding

`alert_fatigue.DEFAULT_BURST_SHAPES` ships five subtypes (`ps_remoting`,
`wmi`, `sched_task`, `sanctioned_scan`, `backup`). If your sanctioned
hard-negative activity doesn't match these — for example, weekly Tanium
sweeps that span 90 minutes — the right move is:

1. Capture a real burst (label it as `hard_negative` + your subtype name
   in the manifest via `pipeline.score_campaign`).
2. Add the subtype to `synth_hard_negatives.py` so you can re-run the
   smoke without needing the real burst every time.
3. Add a row to `DEFAULT_BURST_SHAPES` with the observed
   `duration_s` + `burst_event_rate` + `bursts_per_host_per_day`.

The arithmetic will then count the subtype both in the per-window FP
rate (from the real or synth burst) AND in the FP/hour estimate (from
the shape).

## 6. Multi-day calibration discipline

Single-day calibrations are misleading. Real deployments cycle:
weekday vs weekend, business hours vs overnight, end-of-month
batch jobs. Two practical rules:

- Calibrate over ≥ 7 days of continuous capture before pinning
  `deployments.json` for production thresholds.
- Re-run `--multi-day` whenever the spread between median and p95
  FP/hour exceeds 2×. That's the signal something is changing and
  your threshold's safety margin is shrinking.

## 7. What this phase does **not** do

- No collector tuning is automated. Sysmon config edits are still a
  manual deploy through whatever GPO / config-management path you
  already use.
- No per-EID FP attribution at window granularity (see §4).
- No on-host agent tuning loop. The arithmetic is offline; deploying
  threshold changes back to the detector is out of scope here.
