# AI-Attack Detector — v1 plan

A defender-side detector that flags AI-agent-driven activity in security
telemetry, classifies it against MITRE ATT&CK, and runs fast enough to matter.
It learns the *behavioral shape* of an AI-driven intrusion (machine-speed
pivoting, action-ordering structure, accelerating cadence), not static
signatures.

**Scope boundary:** this detects attacks against systems we operate. It does
NOT try to stop a model from generating an attack at the source — that needs
model-provider control and is out of scope. Detection layer only.

## Hard constraints (a regression if violated)

1. Evaluate with **PR-AUC** and **false-positives-per-hour**, never accuracy.
2. Always split by **campaign group** (`GroupShuffleSplit` on `campaign_id`).
3. Class imbalance is the real problem — keep a large benign baseline, use class
   weighting, don't oversample attacks until the split leaks.
4. PR-AUC ~1.0 is a **red flag to investigate**, not a win. Synthetic data must
   have genuinely overlapping classes (irreducible error).
5. Detect **behavior, not signatures**.
6. Every script runs end-to-end on synthetic/demo data, **no network**, via
   `--synthetic` / `--demo`.

## Normalized schema

Per event: `campaign_id`, `ts` (unix s), `action`, `target`, `depth`,
`artifact_ai` (0–1), `label` (1 attack / 0 benign). For the multi-label task an
optional `technique` (per-event ATT&CK tactic) rides alongside. Adapt every data
source in one place (`adapt_real_dataframe()` / dedicated adapters). Window = 32
events, stride 16, never crossing campaign boundaries.

## Components

| file | role | run |
|------|------|-----|
| `detector_v0.py` | aggregate baseline (HistGradientBoosting) | `python detector_v0.py --synthetic` |
| `detector_v05.py` | GRU over per-event sequences | `python detector_v05.py` |
| `detector_v1.py` | **ATT&CK multi-label** (risk + per-technique + spans) | `python detector_v1.py --synthetic` |
| `detector_v2.py` | **hybrid** (aggregate features + GRU hidden state) | `python detector_v2.py --synthetic` |
| `detector_v3.py` | **serving loop** (budget-tuned threshold, streaming, MTTD) | `python detector_v3.py --demo` |
| `sweep.py` | multi-seed robustness sweep over v1/v2/v3 | `python sweep.py` |
| `inspect_dataset.py` | profiles a real dataset, suggests a column mapping | `python inspect_dataset.py --demo` |
| `adapter_winlogs.py` | Windows/Sysmon event-log adapter (+ ATT&CK→tactic crosswalk) | `python adapter_winlogs.py --demo` |

## Tasks

### [x] Task 1 — ATT&CK multi-label output  (`detector_v1.py`)

Shipped. Extends the v0.5 GRU into a multi-head model:

- **Per-window risk score** — overall attack probability (its own attention head).
- **Per-technique multi-label** — 6 ATT&CK-style tactics (recon, discovery,
  credential_access, command_execution, lateral_movement, exfiltration), each
  with its own attention head so a window can light up several at once.
- **Triggering span** — the events each head attended to (top-k by attention),
  so an analyst sees *where* in the window a technique fired.

The synthetic generator builds phase-structured kill-chain campaigns and tags
every event with the technique that produced it, so per-technique recall is
measurable. Realism (constraint #4): all non-action features (timing, depth,
breadth, ai-artifact) are drawn from the **same** distribution for both classes
so they carry no label signal; the only separation is the (noisy) action
profile + phase structure, plus a 20% low-and-slow stealth fraction that caps
recall. Result: PR-AUC stays well under 1.0.

Measured on one shared campaign-level split (`--synthetic`, seed 0,
5,661 windows, 22.3% attack):

| model | risk PR-AUC |
|-------|-------------|
| v0 aggregate GBT (order-blind) | 0.695 |
| v0.5 binary GRU (prior best) | 0.780 |
| **v1 multi-label GRU (risk head)** | **0.766**  (lift vs v0 **+0.071**) |

v1 risk @ train-tuned threshold: precision 0.773, recall 0.609, **FP/hour 0.70**.

Per-technique recall (threshold tuned per technique on train):

| technique | support | PR-AUC | recall |
|-----------|--------:|-------:|-------:|
| recon | 86 | 0.547 | 0.477 |
| discovery | 129 | 0.523 | 0.488 |
| credential_access | 126 | 0.576 | 0.524 |
| command_execution | 127 | 0.733 | 0.669 |
| lateral_movement | 100 | 0.460 | 0.580 |
| exfiltration | 61 | 0.592 | 0.492 |
| **macro-avg recall** | | | **0.538** |

The measured improvement over the prior best (v0.5) is the **new structured
output**: the risk head matches the binary GRU's PR-AUC (0.766 vs 0.780, within
run-to-run noise) while additionally emitting per-technique labels, per-technique
recall, and attended spans — none of which v0/v0.5 can produce. Risk PR-AUC also
clears the v0 aggregate baseline by +0.071 because the kill-chain phase structure
is sequential (ordering the aggregates can't see).

### [x] Task 2 — Hybrid model  (`detector_v2.py`)

Shipped. `HybridDetector` runs the GRU over the event sequence, takes its final
hidden state, **concatenates the v0 aggregate feature vector**, and feeds the
fusion to one jointly-trained MLP head.

The synthetic data gives attacks two *orthogonal, partial* signals and assigns
most campaigns only one of them, so neither single model can be complete:

- **breadth** (aggregate-visible, GRU-blind): the attack fans out across many
  distinct targets — carried by `distinct_targets` / `target_churn`, which the
  GRU never sees (target identity isn't in the sequence features).
- **ordering** (GRU-visible, aggregate-blind): a doubly-stochastic action
  transition structure — marginal action frequencies match benign, so the
  aggregate histogram can't see it; only a sequence model can.

Timing/depth/ai are identical across classes (no signal). Attack modes:
aggregate-only / ordering-only / both / stealth(neither); the stealth fraction
is uncatchable and keeps PR-AUC under 1.

Measured on one shared campaign-level split (`--synthetic`, seed 0, 6,244
windows, 30.3% attack):

| model | PR-AUC |
|-------|-------:|
| v0 aggregate-only (breadth-visible, order-blind) | 0.759 |
| v0.5 GRU-only (order-visible, breadth-blind) | 0.720 |
| **v2 hybrid (both channels)** | **0.942**  (lift over best single **+0.183**) |

Hybrid @ train-tuned threshold: precision 0.954, recall 0.858, **FP/hour 0.31**.

Recall by attack mode makes the mechanism explicit:

| mode | aggregate | GRU | hybrid |
|------|----------:|----:|-------:|
| aggregate-only | 0.921 | 0.037 | 0.902 |
| ordering-only | 0.127 | 0.887 | 0.853 |
| both | 0.959 | 0.856 | 1.000 |
| stealth | 0.120 | 0.000 | 0.040 |

Each single model is blind to the other's channel (0.037, 0.127); the hybrid
recovers both groups, which is why its PR-AUC clears either model alone.

### [x] Task 3 — Real-data wiring + tiny serving loop  (`detector_v3.py`)

Shipped. Three pieces:

- **Real-data wiring** — `load_events()` runs the same pipeline on any source by
  adapting it into the normalized schema once: `adapt_real_dataframe` for generic
  sources, `adapter_winlogs.adapt_winlog_dataframe` for Windows/Sysmon logs
  (`--winlog`). The HF temporal-attack-pattern dataset is reached with
  `--data <hf_id>` behind a lazy `datasets` import (needs network); the demo
  path needs neither. `featurize_window` tolerates unknown action names (real
  data) by simply emitting no action one-hot for them.
- **Streaming serving loop** — `StreamingAlerter` ingests events one at a time,
  keeps a per-campaign sliding buffer, scores each completed 32-event window with
  the best model (the v2 hybrid), and emits an alert when risk crosses a
  threshold **tuned against an FP/hour budget, not F1** (`tune_threshold_for_budget`
  picks the lowest threshold whose estimated FP/hour ≤ budget → max recall within
  the alert budget).
- **Mean-time-to-detect** — `replay_mttd` replays held-out campaigns as streams
  and measures seconds from attack onset (first attack event) to first alert.

Measured (`--demo`, seed 0, 6,244 windows, 30.3% attack, FP/hour budget 1.0):

| metric | value |
|--------|------:|
| PR-AUC (held-out campaigns) | 0.942 |
| tuned threshold | 0.293 |
| achieved FP/hour (test) | 1.23 |
| precision / recall / F1 | 0.845 / 0.899 / 0.871 |
| attack traces detected | 56/57 (98%) |
| **mean-time-to-detect** | **94.2 s (~1.6 min)** |
| median-time-to-detect | 83.8 s |

Tightening to `--fp-budget 0.3` raises the threshold to 0.406, drops achieved
FP/hour to 0.46 and lifts precision to 0.933, with MTTD essentially unchanged
(~97 s) — the budget is a real, working knob.

**Honest caveat surfaced by the loop:** ~50–56% of *benign* campaigns fire at
least one alert even though window-level FP/hour is ≈1. That's alert-fatigue
arithmetic — long benign sessions accumulate many windows, so a low per-window FP
rate still yields a per-session alert often. It's a direct consequence of the
genuine class overlap (constraint #4) and a reason a deployment would add
per-entity alert suppression on top of the FP/hour budget.

The `adapter_winlogs.py` groundwork (Windows→schema, ATT&CK-id→tactic crosswalk)
feeds the `--winlog` path. Remaining for a true real run: point `--data` at the
HF dataset in a networked environment (the offline dev box used here blocks
huggingface.co with HTTP 403, so the real-data path is wired and code-exercised
on the demo loaders but not yet run against the live dataset).

## Robustness (`sweep.py`)

Single-seed numbers can flatter a model. `sweep.py` re-runs v1/v2/v3 across
seeds 0–2 (epochs 40) and reports mean ± std. The headline claims hold every
seed — they are not seed luck:

| detector | metric | mean ± std | min–max |
|----------|--------|-----------:|---------|
| v1 | v0 aggregate PR-AUC | 0.705 ± 0.015 | 0.694–0.726 |
| v1 | **v1 risk PR-AUC** | **0.782 ± 0.012** | 0.766–0.792 |
| v1 | per-technique macro recall | 0.550 ± 0.009 | 0.538–0.560 |
| v2 | aggregate-only PR-AUC | 0.771 ± 0.033 | 0.738–0.817 |
| v2 | GRU-only PR-AUC | 0.723 ± 0.014 | 0.707–0.741 |
| v2 | **hybrid PR-AUC** | **0.927 ± 0.012** | 0.913–0.942 |
| v2 | lift over best single | 0.155 ± 0.032 | 0.110–0.183 |
| v3 | serving PR-AUC | 0.927 ± 0.012 | 0.913–0.942 |
| v3 | achieved FP/hour (test) | 1.46 ± 0.22 | 1.23–1.76 |
| v3 | detection rate | 96% ± 1.6 | 94–98% |
| v3 | **mean-time-to-detect** | **101.8 s ± 5.5** | 94.2–107.0 s |

- task 1: v1 risk PR-AUC ≥ v0 aggregate in **3/3** seeds.
- task 2: hybrid beats the best single model in **3/3** seeds (mean lift +0.155).

(The per-task tables above quote the seed-0 run; every figure sits inside the
seed 0–2 range here.)
