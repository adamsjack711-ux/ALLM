# Aardvark— AI-Attack Detector

ALLM is a tool that helps spot computer attacks run by an AI. It reads
security logs and tries to tell when an AI agent — not a person — is doing
the attack.

## What it does

ALLM watches a stream of events from a computer system. Each event says
what happened, what it touched, how deep it went, and when. ALLM reads
these events as they come in and answers two questions right away:

1. **Is an AI agent behind this?** It gives a risk score for each short
   slice of time.
2. **What is the attack doing?** For each slice, it picks from six kinds of
   attack steps: looking around, finding things, stealing passwords,
   running commands, jumping to other machines, and taking data out. It
   also points to the exact events that made it say so.

The six steps come from a well-known list called MITRE ATT&CK. It is a
common, trusted way to name attack moves.

## How it is built

ALLM is a small set of Python programs:

- a simple baseline model
- a model that reads events in order (a GRU)
- a model that labels the attack steps
- a model that mixes the first two together
- a live loop that raises alerts and keeps the false alarms low

You can run every program on fake test data with `--synthetic` or
`--demo`. So you can try the whole thing offline. You do not need the
internet.

## Why it matters

AI attacks move in a way human attacks do not. They go fast. They follow a
neat order. They speed up as they go. And they touch many targets. Old
tools miss this because each single action looks normal on its own. The
give-away is the *pattern*: the order, the speed, and how wide it spreads.

ALLM learns this pattern from the logs. Then it shows a security analyst
what it found: which step, which events, and how sure it is. It also tries
hard not to cry wolf.

**What it does not do:** ALLM only *finds* attacks on systems we run. It
does not stop an AI from making an attack in the first place. That is a
different job and is not part of this project.

## How we test it (the honest way)

- **We look at behavior, not fixed clues.** The models use timing, depth,
  spread, and the order of actions. They never key on exact text or known
  bad words.
- **We use fair scores.** We use PR-AUC and false alarms per hour. We do
  not use plain accuracy, which can lie when most events are safe.
- **We split the data the careful way.** The training set and the test set
  never share the same campaign. This stops the model from cheating.
- **We make the test data hard on purpose.** Some fake attacks are slow and
  quiet, so they are tough to catch. A perfect score would be a warning
  sign, not a win.
- **We run it many times.** Every headline number is checked across three
  runs (seeds 0–2). One lucky run does not count.

### What the scores mean (in plain words)

- **PR-AUC** — a score from 0 to 1. Higher is better. It tells how well the
  model finds real attacks without flagging safe stuff.
- **False alarms per hour** — how often the tool raises an alert when
  nothing bad is going on. Lower is better.
- **Time-to-detect** — how many seconds it takes to catch an attack after it
  starts. Lower is better.

## Results

These numbers come from **fake (synthetic) test data**, split by campaign.
Real-world results may be different. Full numbers and methods are in
[`ai-attack-detector-v1-plan.md`](./ai-attack-detector-v1-plan.md).

Seed 0:

| part | what we measured | value |
|---|---|---|
| v1 multi-label GRU | risk PR-AUC | 0.766 (up 0.071 from the baseline) |
| v1 multi-label GRU | how many attack steps it catches (macro recall) | 0.538 |
| **v2 hybrid (baseline + GRU)** | **PR-AUC** | **0.942** (up 0.183 from the best single model) |
| v3 live loop | PR-AUC / false alarms per hour | 0.942 / 1.23 |
| v3 live loop | attacks caught | 56 of 57 (98%) |
| v3 live loop | **time-to-detect** | **94.2 seconds** |

Across three runs (seeds 0–2), the numbers hold steady. They are not just
luck:

- hybrid PR-AUC: 0.927, give or take 0.012
- attacks caught: 96%, give or take 1.6%
- time-to-detect: 101.8 seconds, give or take 5.5

**One honest catch:** in a long, safe session, the tool may still fire at
least one alert, even when the per-slice false-alarm rate is low. A real
setup would add a rule to group these alerts so analysts are not flooded.

## Quick start

```bash
pip install numpy pandas scikit-learn torch

python detector_v0.py --synthetic     # simple baseline
python detector_v05.py                # GRU that reads events in order
python detector_v1.py --synthetic     # labels attack steps + points to events
python detector_v2.py --synthetic     # hybrid: baseline + GRU together
python detector_v3.py --demo          # live loop: alerts + time-to-detect
python sweep.py                       # runs v1/v2/v3 across three seeds
python inspect_dataset.py --demo      # helps map dataset columns
python adapter_winlogs.py --demo      # reads Windows/Sysmon event logs
```

## Project status

Tasks 1–3 from the [v1 plan](./ai-attack-detector-v1-plan.md) are done:
labeling attack steps, the hybrid model, and the live loop with
time-to-detect. The path for real data (a HuggingFace dataset and
Windows/Sysmon logs through `adapter_winlogs.py`) is built and tested on
demo loaders. Running it on a live dataset needs a machine with internet.

### Sibling labs

- **`web-harness/`** — a local-only lab that asks the same question for web
  traffic: is this visitor an AI agent? It uses DVWA, a capture proxy, and a
  GRU+MLP detector. Later phases added a benign-bot family, more target
  apps (Juice Shop, WebGoat, VAmPI), three new agent tools (sqlmap,
  Selenium, Puppeteer), more eval roll-ups, and quiet "stealth" copies of
  every agent. See [`web-harness/README.md`](./web-harness/README.md).
- **`pipeline/`** — the path that brings in host logs. It takes a Sysmon
  dump plus a CALDERA or Atomic Red Team report, turns it into labeled
  events, slices it into 32-event windows, and feeds the detector. Phase 1
  added the ingest path and per-campaign tracking. Phase 2 added Atomic Red
  Team as a held-out test family, normal-workload and hard-negative
  generators, and a train-on-one / test-on-the-other eval. See
  [`pipeline/README.md`](./pipeline/README.md).

## License

[MIT](./LICENSE) © 2026 Jack Adams-Lovell
