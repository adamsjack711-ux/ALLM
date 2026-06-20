# allm-web-harness

Localhost-only purple-team test harness that asks: **is this web visitor an
autonomous LLM agent or a human?** DVWA is the deliberately vulnerable
target; existing attack tools are pointed at it through a capture proxy
that logs request-level features and injects a JS beacon; a small hybrid
GRU + session-feature detector is trained and evaluated against an
FP/hour budget (never accuracy).

This is a **detection lab**. No new exploits are written. Attacks come
from existing tools (a Playwright spray bot scripted with classic SQLi/XSS
payload lists, and a PentesterPro-flavored multi-step agent — see
[the PentesterPro section](#pentesterpro-flavored-agent-not-the-real-framework))
pointed at DVWA at security levels low → high.

## Phase status

| Phase | What | Status |
|---|---|---|
| 1 | DVWA + MariaDB + capture proxy logging redacted sessions | ✅ |
| 2 | Playwright bot + human simulator → labeled dataset | ✅ |
| 3 | Honeypots (`/__canary`, hidden form, robots tarpit, hidden DOM hint) | ✅ |
| 4 | Hybrid GRU+MLP detector + PR-AUC / FP-hour eval + StreamingAlerter | ✅ |
| 5 | PentesterPro-flavored agent + orchestrator + held-out-attacker eval | ✅ |
| 6 | benign_bot family + per-session provenance manifest + label-schema columns | ✅ |

## Hard constraints (enforced in code, not docs)

- All ports are loopback / internal. Only the capture proxy publishes
  `127.0.0.1:8090`. Generator services run on the `allm_lab` bridge
  network and never expose ports.
- Each traffic generator imports `generators/shared/target_guard.py` and
  reads its target from `ALLM_TARGET` only. The guard rejects any host
  whose name isn't in `{capture, 127.0.0.1, ::1, localhost}` — hard
  process exit before any I/O. CLI overrides are deliberately not
  supported.
- The capture proxy strips `Authorization`, `Cookie`, and `Set-Cookie`
  *values* from every log row before write. Only presence bits
  (`has_auth_header`, `has_cookie_header`) and the sorted header *name
  set* hash (`header_hash`) are persisted.
- No new attack code. Both bots draw from a fixed `payloads.txt` of
  textbook SQLi / XSS / cmd-injection examples.

## Run

```sh
cd ~/allm-web-harness
cp .env.example .env                  # optional; defaults are fine

# Phase 1: target + capture
docker compose up -d --build
python3 tests/smoke.py                # phase 1 gate

# Phase 2-3: labelled bot vs human data + honeypot rates
python3 tests/phase2_smoke.py
python3 tests/phase3_smoke.py

# Phase 4: detector
python3 tests/phase4_smoke.py

# Phase 5 (and the canonical "run the whole pipeline" entrypoint):
python3 tests/phase5_smoke.py
# or directly:
python3 orchestrator/run_loop.py --sessions 6

# Phase 6: benign_bot family + provenance manifest
python3 tests/phase6_smoke.py
# or run the benign profile by hand:
docker compose --profile benign up -d --build
```

Each `phase{N}_smoke.py` rebuilds whatever needs rebuilding, generates
the data, and asserts the gate. Reports land in `data/reports/`.
Tear down: `docker compose down -v`.

DVWA default creds: `admin` / `password`. To seed real-human traffic,
browse `http://127.0.0.1:8090/login.php` in your normal browser — the
proxy tags every request on :8090 as `src_label=human_real` and writes
sessions exactly like the generators.

## Architecture

```
                docker network: allm_lab
 ┌─────────────────────────────────────────────────────────────────┐
 │                                                                 │
 │  generators/        ─┐                                          │
 │   playwright_bot     │                                          │
 │   pentesterpro       ├──► capture (reverse proxy + honeypots)   │
 │   human_sim          │         │  redacted request JSONL +      │
 │                     ─┘         │  beacon JSONL + honeypots JSONL│
 │                                ▼                                │
 │                            DVWA  ──►  MariaDB                   │
 │                                                                 │
 │  detector (one-shot per train/eval): GRU(seq) ⊕ agg ⊕ hp        │
 │  orchestrator (host script): interleaves + retrains + heldout   │
 └─────────────────────────────────────────────────────────────────┘
              ▲
   127.0.0.1:8090  (human_real label, your real browser)
```

Two listeners on the capture proxy: `:8080` is bound only inside the
docker network and labels incoming sessions from the `X-Allm-Source`
header (set by each generator container). `:8090` is host-loopback and
hard-labels every session `human_real`.

## What's measured

The detector reports, per evaluation:

- **PR-AUC** and **FP/hour** — *never accuracy*. PR-AUC handles the
  agent/human imbalance; FP/hour is what an on-call rotation actually
  cares about.
- **Per-source alert rate** — TPR for agent classes
  (`playwright_bot`, `pentesterpro`), FPR for benign classes
  (`human_sim`, `human_real`).
- **Honeypot precision** — pure data-only metric: of all sessions that
  tripped ≥1 honeypot, what fraction are actually agents. This is the
  honeypot system's standalone quality.
- **ML-only PR-AUC** — same architecture trained without honeypot
  inputs; tells you what the model knows from cadence + path + byte-size
  features alone.
- **StreamingAlerter time-to-flag** — at the chosen τ, scoring every 5
  requests, time from session start to a 2-window over-threshold alert.

## Alert-fatigue arithmetic

The detector reports `FP/hour`, not `FP/session`. The relationship matters
for staffing.

If the chosen threshold τ produces per-session false-positive rate `p` and
benign traffic averages `μ` minutes per session, expected false alarms
per hour:

```
E[FP/hour]  =  p × (60 / μ)
```

Concrete examples:

- p = 0.01, μ = 2 min sessions → E[FP/hour] = 0.3 — one false alarm
  every ~3 hours, manageable.
- p = 0.01, μ = 20 sec sessions (this lab's typical bot durations) →
  E[FP/hour] = 1.8 — once every 33 minutes, painful.

The harness's default gate (FP/hour ≤ 0.5) gets *strictly harder* as
sessions get shorter. To make the budget realistic for high-volume,
short-session contexts, either raise the budget, fold lower-FP features
(longer aggregate windows, richer beacon telemetry) into the model, or
combine streams of contiguous sessions before scoring.

The eval also reports the actual `session_hours_test` so you can
re-derive a comparable FP rate at any threshold from the PR curve sample.

## Simulator-vs-real-human limitation

`human_sim` uses Playwright + Chromium — the **same browser engine** as
both attack generators. The JS beacon distinguishes them on **cadence**
(typing rhythm, mouse jitter, scroll, dwell) — *not* on browser engine,
plugins, fonts, or system fingerprint.

Two practical consequences:

1. PR-AUC numbers measured against `human_sim` benign sessions are an
   **upper bound** on what you'd see in production where real humans use
   Safari, Firefox, mobile browsers, with very different feature
   distributions. The lab's 1.0 PR-AUC is partly a function of how
   distinctly the simulator and the bots behave.
2. `human_real` (your own browsing on :8090) is the only ground-truth
   benign source. Use it: 10 minutes of real browsing seeds enough data
   to recompute the FP/hour budget against a meaningful denominator.

Small `human_real` N also widens the confidence interval on benign
recall, which the eval doesn't explicitly compute — eyeball the
`per_source` `alert_rate` cells and treat anything below 30 sessions per
class as indicative, not conclusive.

## Held-out attacker evaluation

A detector can overfit to whichever attack class it saw at training time.
`detector/heldout.py` checks this:

- Baseline: random 70/30 split on session_id over **all** classes. Pick
  τ at the FP/hour budget. Record per-attacker recall at that τ.
- For each attacker class `A` in `{playwright_bot, pentesterpro}`:
  - Train a fresh model excluding every session labelled `A`.
  - Score the held-out `A` sessions with the same τ.
- Flag `overfits_attacker[A] = True` if held-out recall < 0.5 ×
  in-distribution recall.

**Caveat**: the same τ is applied across models trained on different
data, even though score calibration may differ run-to-run. Treat the
ratio as a diagnostic, not a hard verdict — when the eval flags
something, look at the absolute scores in `heldout.json` rather than
trusting the boolean alone. With small N (<30 per attacker), the
ranking-based PR-AUC of the heldout model is more reliable than the
recall-at-τ number.

## PentesterPro-flavored agent (not the real framework)

The phase 5 plan named the second attacker class `pentesterpro` and
locked the harness to a Mock LLM (no Gemini egress). `generators/pentesterpro/`
implements that as a **behavioral stand-in**: same multi-step plan/act
loop, same hidden-DOM-reading reasoning, deterministic local planner in
`mock_llm.py` instead of the Gemini call PentesterPro would otherwise
make. The X-Allm-Source label is `pentesterpro`.

Why not run the real PentesterPro framework?

- The plan's "Mock LLM" decision guts `llm_engine.py` regardless. With
  that removed, the framework around it (Flask + Postgres + worker pool +
  migrations) costs ops effort without changing the request signature
  the detector sees.
- The behavioral parts that matter for detection — hidden-DOM reading,
  multi-step plan/act, payload selection by form context, link-followed
  crawl — are what we reproduce, faithfully and in <200 LOC.

The honest tradeoff: if you specifically want to detect signatures from
PentesterPro's HTTP client stack, this stand-in isn't a substitute. For
detecting *LLM-agent-style behavior* (which is what the harness is for),
it is.

The plan also stubbed two patches (`patches/001-target-guard.patch` and
`patches/002-mock-llm.patch`) for wrapping the real `main_scan.py` and
`ScopeEnforcer`. The harness doesn't ship them — running real
PentesterPro is out of scope for this lab. They can be reconstructed
from the references at `Hellsender01/PentesterPro:main_scan.py:47` and
`app/exploration/core/scope.py::ScopeEnforcer.is_in_scope`.

## Layout

```
allm-web-harness/
├── docker-compose.yml          # db + dvwa + capture + generators + detector
├── capture/                    # aiohttp proxy + JS beacon + honeypot layer
│   ├── proxy.py                # middleware: session, redacted log, honeypot check
│   ├── honeypots.py            # canary, invisible field, robots, hidden hint
│   ├── beacon.js               # injected on every HTML response
│   ├── Dockerfile, requirements.txt
├── generators/
│   ├── shared/target_guard.py  # loopback-only ALLM_TARGET enforcer
│   ├── shared/manifest.py      # provenance helper (httpx + Playwright variants)
│   ├── playwright_bot/         # spray fuzzer: greedy form fill + robots recon
│   ├── human_sim/              # slow typing + mouse jitter + dwell
│   ├── pentesterpro/           # multi-step + hidden-DOM + mock LLM
│   └── benign_bots/            # googlebot / uptime / rss / unfurl / ci (class=benign_bot)
├── detector/
│   ├── features.py             # JSONL → per-session seq + agg + hp
│   ├── model.py                # GRU + MLP head, ablate_hp flag
│   ├── train.py                # GroupShuffleSplit on session_id, BCE
│   ├── eval.py                 # PR-AUC, FP/hr, per-source alert rate
│   ├── alerter.py              # StreamingAlerter, time-to-flag
│   ├── heldout.py              # cross-attacker eval + overfit flag
│   └── Dockerfile, requirements.txt
├── orchestrator/run_loop.py    # interleave + train + eval + heldout
├── scripts/init_dvwa.py        # idempotent DB bootstrap
├── tests/                      # per-phase verification gates
├── data/                       # (gitignored) JSONL logs + models + reports
└── README.md
```

## Pinning the DVWA image

The compose pulls `ghcr.io/digininja/dvwa:latest` for now. After the
first successful `up`, capture the digest and pin it:

```sh
docker image inspect ghcr.io/digininja/dvwa:latest --format '{{index .RepoDigests 0}}'
```

Replace the `image:` line in `docker-compose.yml` with that `@sha256:…`
form for reproducibility.

## Phase 6 — benign_bot family + provenance manifest

Phase 6 adds the **negative class** the detector needs to be measured
against beyond `human_sim` / `human_real`: legitimate non-browser
automation that looks superficially agent-like (high request rate,
non-Chrome UA, no JS execution) but is not adversarial.

Five families ship, all under `class=benign_bot`, all loopback-bound,
all non-stealthy (`stealth=false`) — stealth variants land in phase 7:

| family | UA | what it does |
|---|---|---|
| `googlebot` | `Googlebot/2.1` | reads `robots.txt`, walks `Disallow` paths, BFS from `/` |
| `uptime_monitor` | `UptimeRobot/2.0` | `HEAD`+`GET /` on a fixed cadence |
| `rss_reader` | `Feedfetcher-Google` | polls `/feed`, `/rss`, `/atom.xml` (mostly 404s — that's the point) |
| `link_unfurler` | `Slackbot-LinkExpanding 1.0` | `HEAD`+`GET` then parses `og:` / `twitter:` meta |
| `ci_health_check` | `GitHub-Hookshot/<sha>` | polls `/health`, `/healthz`, `/ping` |

Each family lives in `generators/benign_bots/<family>.py` and ships in
one shared image — the runner dispatches on `ALLM_BENIGN_BOT`. None of
them publish ports; the loopback invariant is unchanged.

### Label schema (additive, group key = `session_id`)

Every `requests.jsonl` row now carries:

| column | values |
|---|---|
| `class` | `agent` / `human` / `benign_bot` / `unknown` |
| `family` | `playwright_bot`, `pentesterpro`, `human_sim`, `human_real`, `googlebot`, `uptime_monitor`, `rss_reader`, `link_unfurler`, `ci_health_check`, … |
| `target_app` | `dvwa` for now (phase 7 adds Juice Shop / WebGoat / vulnerable API) |
| `security_level` | `low` / `medium` / `high` / `na` |
| `stealth` | bool |

Existing `src_label` is preserved for back-compat with the phase-4
detector. Legacy generators (phases 1-5) that only set `X-Allm-Source`
are mapped onto `(class, family)` by the capture proxy so eval code
can group by the new axes without per-row guards.

### Provenance manifest

One row per session in `data/sessions.jsonl`:

```json
{"ts": 1718000000.123, "session_id": "abc…", "src_label": "googlebot",
 "class": "benign_bot", "family": "googlebot", "target_app": "dvwa",
 "security_level": "na", "stealth": false,
 "generator": "googlebot", "generator_version": "0.1.0",
 "generator_config_sha": "ab12cd34", "extra": {}}
```

Generators write provenance via `generators/shared/manifest.py`. The
helper exposes `record_provenance_httpx()` (for the non-browser bots
and the future framework / scanner generators) and
`record_provenance_playwright()` (for browser-driven generators —
shares the `allm_sid` cookie with the BrowserContext). Per-session
`ts_start`/`ts_end` are recovered at read time by joining
`sessions.jsonl` against `requests.jsonl`.

### What phase 6 explicitly does not do

- New attack generators (Selenium, Puppeteer, sqlmap, nikto, ffuf,
  Scrapy, real OpenAI / Gemini PentesterPro). These land in phase 7.
- Multi-target support (Juice Shop, WebGoat, VAmPI / crAPI). Phase 7.
- Stealth variants. Phase 7. The `stealth=true` axis is already a
  manifest field so existing rows don't need re-keying.
- New detector eval (per-family recall, agent-vs-benign_bot confusion,
  held-out family). The label-schema columns are persisted; the
  detector-side rollup lands in phase 8.

## Out of scope

- Windows agents / cross-OS deployment.
- Production deployment, TLS, auth — lab is loopback-only by design.
- Authoring new exploits. Attacks come exclusively from existing tools
  pointed at DVWA.
- Reporting accuracy as a metric. Anywhere. If you ever find one in this
  repo, that's a bug — please file it.
