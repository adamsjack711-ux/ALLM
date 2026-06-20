# Aardvark— AI-Attack Detector

A defender-side detector that flags AI-agent-driven activity in security
telemetry and classifies it against MITRE ATT&CK.

## What this is

A machine-learning system that ingests normalized event telemetry (campaign
events with action, target, depth, timing) and answers two questions in real
time:

1. **Is this campaign being driven by an AI agent?** — a per-window risk score.
2. **What is it doing?** — a per-window multi-label output over six ATT&CK
   tactics (recon, discovery, credential access, command execution, lateral
   movement, exfiltration) plus the events inside the window that triggered
   each label.

It ships as a small suite of Python modules — an aggregate baseline, a GRU
sequence model, an ATT&CK multi-label model, a hybrid fusion model, and a
streaming serving loop with a tunable false-positive budget. Every script
runs end-to-end on synthetic data with `--synthetic` / `--demo`, so the whole
project is reproducible offline with no network access.

## What it's trying to accomplish

AI-agent-driven intrusions have a *behavioral shape* that human-driven ones
don't: machine-speed pivoting, structured action ordering, accelerating
cadence, and atypical breadth of target enumeration. Static rules and
signature engines miss this because the individual actions look ordinary —
it's the *sequence*, *timing*, and *fan-out* that give the agent away.

The goal of this project is to build a detector that learns that behavioral
shape from telemetry alone, surfaces it to a SOC analyst with enough
structure to act on (which tactic, which events, how confident), and runs
inside a realistic false-positive budget rather than chasing F1.

**Explicit scope boundary:** this is a *detection* layer for systems we
operate. It does not attempt to prevent a model from generating an attack at
the source — that requires model-provider control and is out of scope here.

## Approach

- **Behavior, not signatures.** Features capture timing, depth, breadth,
  action-ordering structure, and AI-artifact priors — never specific strings
  or IoCs.
- **Honest evaluation.** Models are evaluated with **PR-AUC** and
  **false-positives-per-hour**, never accuracy, on a **campaign-level split**
  (`GroupShuffleSplit` on `campaign_id`) so leakage can't inflate numbers.
- **Genuine class overlap.** The synthetic generator is built so non-action
  features carry no label signal and a fraction of attacks are intentionally
  low-and-slow stealth — PR-AUC ≈ 1.0 would be a red flag, not a win.
- **Multi-seed robustness.** Every headline number is replicated across
  seeds 0–2 (`sweep.py`); single-seed luck doesn't ship.
- **Budget-tuned alerts.** The serving loop picks its threshold against a
  target FP/hour budget (the knob a SOC actually turns), not F1.

## Current results

Measured on synthetic data, campaign-level split, seed 0:

| component | metric | value |
|---|---|---|
| v1 multi-label GRU | risk PR-AUC | 0.766 (+0.071 vs aggregate baseline) |
| v1 multi-label GRU | per-technique macro recall | 0.538 |
| **v2 hybrid (aggregate + GRU)** | **PR-AUC** | **0.942** (+0.183 vs best single model) |
| v3 serving loop | PR-AUC / FP-hr / detection rate | 0.942 / 1.16 / 98% |
| v3 serving loop | **mean-time-to-detect** | **94.2 s** |

Multi-seed sweep (seeds 0–2): hybrid PR-AUC 0.927 ± 0.012, MTTD 101.8 s ± 5.5.
Full numbers and methodology in [`ai-attack-detector-v1-plan.md`](./ai-attack-detector-v1-plan.md).

## Quick start

```bash
pip install numpy pandas scikit-learn torch

python detector_v0.py --synthetic     # aggregate baseline
python detector_v05.py                # GRU over event sequences
python detector_v1.py --synthetic     # ATT&CK multi-label (risk + per-technique + spans)
python detector_v2.py --synthetic     # hybrid: aggregate features + GRU hidden state
python detector_v3.py --demo          # serving loop: budget-tuned alerts + MTTD
python sweep.py                       # multi-seed robustness sweep across v1/v2/v3
python inspect_dataset.py --demo      # dataset column-mapping helper
python adapter_winlogs.py --demo      # Windows/Sysmon event-log adapter
```

## Project status

Tasks 1–3 from the [v1 plan](./ai-attack-detector-v1-plan.md) are shipped:
ATT&CK multi-label output, hybrid aggregate+sequence model, and a streaming
serving loop with MTTD measurement. The real-data path (HuggingFace
temporal-attack-pattern dataset, Windows/Sysmon logs via `adapter_winlogs.py`)
is wired and code-exercised on demo loaders; running against a live dataset
needs a networked environment.

### Sibling labs

- **`web-harness/`** — localhost-only purple-team lab that asks the
  web-side of the same question (is this visitor an autonomous LLM
  agent?). DVWA + capture proxy + GRU+MLP detector. Phases 6–9 added
  a `benign_bot` family, multi-target captures (Juice Shop / WebGoat /
  VAmPI), three new agent families (sqlmap / Selenium / Puppeteer),
  per-family / per-target_app / agent-vs-benign_bot eval rollups, and
  stealth twins of every agent. See [`web-harness/README.md`](./web-harness/README.md).
- **`pipeline/`** — host telemetry ingest path. Sysmon dump + CALDERA
  op report (or Atomic Red Team invocations log) → labeled normalized
  events → 32-event windows → detector. Phase 1 ships ingest +
  per-campaign provenance; phase 2 adds Atomic Red Team as the
  held-out emulation family, normal-workload + hard-negative
  generators (5 subtypes), and a train-CALDERA-eval-Atomic-and-reverse
  held-out emulation eval. See [`pipeline/README.md`](./pipeline/README.md).

## License

[MIT](./LICENSE) © 2026 Jack Adams-Lovell
