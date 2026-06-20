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
| 7 | Multi-target (Juice Shop / WebGoat / VAmPI) + sqlmap / Selenium / Puppeteer agents | ✅ |
| 8 | Detector eval rollup: per-family / per-target_app / agent-vs-benign_bot + held-out family | ✅ |
| 9 | Stealth twins of every agent + per-stealth / per-(family, stealth) eval cells | ✅ |
| 10 | Held-out-stealth eval + orchestrator sweep `{target}×{family}×{security_level}×{stealth}` | ✅ |
| 11 | Scanner family (nikto / ffuf / raw_httpx / scrapy) + proxy session-schema cache | ✅ |
| 12 | crAPI as fourth target (OWASP API security demo, 7 backing services) | ✅ |

## Hard constraints (enforced in code, not docs)

- All ports are loopback / internal. Only the capture proxy publishes
  `127.0.0.1:8090`. Generator services run on the `allm_lab` bridge
  network and never expose ports.
- Each traffic generator imports `generators/shared/target_guard.py` and
  reads its target from `ALLM_TARGET` only. The guard rejects any host
  whose name isn't in `{capture, capture_dvwa, capture_juiceshop,
  capture_webgoat, capture_vampi, 127.0.0.1, ::1, localhost}` — hard
  process exit before any I/O. CLI overrides are deliberately not
  supported. The Node-based `puppeteer_bot` runs the Python guard as a
  pre-exec step in its container so the JS process never starts against
  a non-loopback target either.
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

# Phase 7: multi-target + extended attack generators
python3 tests/phase7_smoke.py
# or run the new targets + extended agents by hand:
docker compose --profile multitarget up -d --build         # juice shop / webgoat / vampi + their captures
docker compose --profile attack-extended up -d --build     # sqlmap / selenium / puppeteer

# Phase 8: detector eval rollup (per-family / per-target_app / agent-vs-benign_bot)
python3 tests/phase8_smoke.py                              # synth-fed, no docker, ~10s

# Phase 9: stealth twins + per-stealth eval cells
python3 tests/phase9_smoke.py                              # synth-fed, no docker, ~7s
# or run the stealth profile by hand:
docker compose --profile stealth up -d --build             # 4 stealth twins (family unchanged)

# Phase 10: held-out-stealth eval + orchestrator sweep
python3 tests/phase10_smoke.py                             # synth-fed, no docker, ~20s
# or the canonical end-to-end sweep:
python3 orchestrator/sweep.py --sessions 2                 # 70 cells (post-phase-11), benign continuous

# Phase 11: scanner family (nikto / ffuf / raw httpx / scrapy) + proxy schema cache
python3 tests/phase11_smoke.py                             # synth-fed, no docker, ~8s
# or build + run the new generators by hand:
docker compose --profile attack-extended up -d --build raw_httpx_bot ffuf_bot scrapy_bot nikto_bot

# Phase 12: crAPI fourth target
python3 tests/phase12_smoke.py                             # structural, no docker, <1s
# crAPI is heavy (7 backing services) — under its own profile:
docker compose --profile crapi up -d --build
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
│   ├── benign_bots/            # googlebot / uptime / rss / unfurl / ci (class=benign_bot)
│   ├── sqlmap_bot/             # python CLI, no browser (class=agent, family=sqlmap)
│   ├── selenium_bot/           # Chromium via chromedriver (class=agent, family=selenium_bot)
│   └── puppeteer_bot/          # Chromium via Node + CDP (class=agent, family=puppeteer_bot)
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
  Scrapy, real OpenAI / Gemini PentesterPro). Phase 7 ships the first
  three; nikto / ffuf / Scrapy / real-LLM agents land in phase 8.
- Multi-target support (Juice Shop, WebGoat, VAmPI / crAPI). Phase 7.
- Stealth variants. Phase 8. The `stealth=true` axis is already a
  manifest field so existing rows don't need re-keying.
- New detector eval (per-family recall, agent-vs-benign_bot confusion,
  held-out family). The label-schema columns are persisted; the
  detector-side rollup lands in phase 8.

## Phase 7 — multi-target + extended attack generators

Phase 6 widened the label schema (`class / family / target_app /
security_level / stealth`). Phase 7 finally exercises the `target_app`
axis: each new vulnerable app gets its own sibling capture proxy that
fronts it, and three new agent families (`sqlmap`, `selenium_bot`,
`puppeteer_bot`) join the existing `playwright_bot` and `pentesterpro`
on `class=agent`.

### Targets + captures

| target_app | upstream | capture service | profile |
|---|---|---|---|
| `dvwa` (default) | `dvwa:80` | `capture` | base |
| `juice_shop` | `juiceshop:3000` (bkimminich/juice-shop) | `capture_juiceshop` | `multitarget` |
| `webgoat` | `webgoat:8080` (webgoat/webgoat) | `capture_webgoat` | `multitarget` |
| `vampi` | `vampi:5000` (erev0s/vampi — vulnerable API, no DOM) | `capture_vampi` | `multitarget` |

All four captures share `./data:/data` so `requests.jsonl`,
`sessions.jsonl`, `beacons.jsonl`, and `honeypots.jsonl` remain
single-stream — the `target_app` column on every row tells you which
capture wrote it. JSONL appends from different processes are
crash-safe (POSIX `O_APPEND` is atomic for the line sizes we write).

Only the original `capture` still publishes `127.0.0.1:8090` for
human-real DVWA browsing; the new captures publish nothing. Generators
inside the docker network address them as `capture_juiceshop:8080` etc.
The `ALLOWED_HOSTS` set in `target_guard.py` enforces this.

### VAmPI = no DOM, no beacon

VAmPI is a JSON API with no HTML — the proxy's beacon-inject pass
(`should_inject` checks `text/html`) skips it, so beacon-derived
features (`js_ran`, `ttfi`, `dom_read`) stay zero for VAmPI sessions.
`detector/features.py` already handles this gracefully (zero-init
when `by_sid_bcn[sid]` is empty), so the detector degrades to
timing/sequence/path features without code changes. The phase 8 eval
will be the first to verify VAmPI sessions actually train cleanly
against the existing model architecture.

### Extended attack generators

All three use the existing `shared/manifest.py` provenance helper +
`X-Allm-*` label headers; they don't draw any new exploit code — just
established tools pointed at the existing targets.

| family | engine | distinctive HTTP signal | targets so far |
|---|---|---|---|
| `sqlmap` | Python CLI, no browser | no beacon callback; high request rate against a single endpoint with structured payload mutations | DVWA SQLi, VAmPI debug |
| `selenium_bot` | Chromium via chromedriver + W3C WebDriver | beacon fires, but request initiator + nav timing differs from CDP-driven Playwright | DVWA SQLi/XSS/exec |
| `puppeteer_bot` | Chromium via Node + CDP | beacon fires, Node's HTTP stack on the host side (proxy sees it as the browser, but the runtime telemetry differs) | DVWA SQLi/XSS/exec |

The phase 7 sweep deliberately mixes generator × target_app so the
detector eval in phase 8 has sessions to slice by both axes.

### What phase 7 explicitly does not do

- nikto, ffuf, raw httpx / Scrapy generators. Phase 9.
- Real OpenAI- / Gemini-backed PentesterPro (still mocked). Phase 9.
- Stealth variants (timing jitter, simulated mouse, human-speed
  throttle, honeypot-avoidant). Phase 9 — the `stealth=true` axis
  is already a manifest field.
- Detector eval that consumes the new `target_app` / `family` axes.
  **Phase 8 ships this** (see below).
- crAPI as a fourth target. VAmPI covers the no-DOM API case for
  phase 7; crAPI is heavier (Docker Compose with several services)
  and lands in phase 9 if needed.

## Phase 8 — detector eval rollup

Phase 6 widened the per-row label schema; phase 7 finally exercised
it with multi-target + 3 new agent families. Phase 8 makes the
detector eval consume it.

### What `eval.py` now reports per head

Existing (back-compat preserved):
- `pr_auc`, `fp_per_hour`, `threshold`, `per_source` (keyed on
  legacy `src_label`), `pr_curve_sample`, `alerter` metrics.

New blocks:

| key | shape | what it answers |
|---|---|---|
| `per_family` | `{family: {test_sessions, alerts, alert_rate, kind, recall_if_agent, fp_rate_if_benign}}` | Per the resolved provenance family. `kind` ∈ `{agent, benign_bot, human, unknown}` so consumers don't have to guess. |
| `per_target_app` | `{app: {test_sessions, alerts, alert_rate, n_agent_truth, n_benign_truth}}` | Multi-target slice — does the detector behave differently on DVWA vs juice_shop vs vampi (no-DOM)? |
| `agent_vs_benign_bot` | `{n_agent_truth, n_benign_bot_truth, agent_recall, benign_bot_fp_rate, confusion{2×2}, per_benign_family_fp}` | The load-bearing question once benign automation is in the data: can we alert on agents without flagging Googlebot / uptime monitors / RSS readers? |

`ml_only` (the "honeypots-disabled run") gets the same blocks — that's
the spec's "honeypots-disabled run" reported alongside.

### What `heldout.py` now does

Replaces the phase-5 held-out-attacker scan with a held-out-FAMILY
scan over the resolved `family` axis, run on BOTH directions:

- **Agent side** (existing semantics, broader scope): for each agent
  family present, retrain without it, score the held-out sessions,
  compare recall to in-distribution. `overfits_attacker` if
  held-out recall < 0.5 × in-distribution.
- **Benign_bot side** (new): for each benign_bot family present,
  retrain without it, score the held-out sessions, compare false-
  positive rate to in-distribution. `fp_generalization_fail` if
  held-out FP rate > 2 × in-distribution. This catches "the detector
  flags any non-Chrome UA it didn't see at training time" failure
  modes — the symmetric concern to attacker overfit.

### Back-compat with pre-phase-6 data

`features.build_sessions` resolves `class / family / target_app` in
priority order:
1. The row in `sessions.jsonl` (phase 6+ provenance manifest).
2. The majority value across the session's `requests.jsonl` rows.
3. A legacy derivation from `src_label` (mirrors the proxy's
   `_LEGACY_SRC_TO_LABEL` map).

So phase-5 runs that pre-date the schema migration still parse: their
sessions get `class = "agent"` / `"human"` based on the hardcoded
`AGENT_LABELS` / `HUMAN_LABELS` sets in `features.py`, and the new
eval blocks degrade to whatever signal those labels carry.

### What phase 8 explicitly does not do

- Wire the new blocks into the orchestrator / phase 5 smoke. Existing
  phase 5 already asserts on the legacy `per_source` block; that
  still works. The new blocks are produced, just not gate-asserted
  there. `tests/phase8_smoke.py` asserts the new blocks directly.
- ~~Stealth variants of generators~~ — **phase 9** ships these.
- Real-LLM PentesterPro, more scanners (nikto / ffuf / Scrapy). Phase 10.

## Phase 9 — stealth twins of every agent + per-stealth eval

Phase 6 introduced the `stealth` manifest axis but no generator ever
set it to `true`. Phase 9 exercises it: each existing agent gets a
stealth-mode code path gated by `ALLM_STEALTH=true`. Family stays the
same (per the spec); the `stealth` flag is the distinguishing axis.

### Stealth knobs per agent

| family | stealth=false (default) | stealth=true |
|---|---|---|
| `playwright_bot` | spray-fuzzer: greedy fill-all (incl. invisible_field), robots.txt-driven recon, no delays | one visible input per page, human-typed payload, mouse jitter, 2.5–6.5s pauses, no robots recon, real-browser UA |
| `sqlmap` | `--level=2 --risk=2 --smart --threads=4`, UA `sqlmap/1.7`, no delay | `--level=1 --risk=1 --threads=1 --delay=3`, real-browser UA |
| `selenium_bot` | spray fill, no pauses | one visible input only, slow per-char typing, post-submit pause, real-browser UA |
| `puppeteer_bot` | spray fill via puppeteer's `type()` | drop off-screen inputs (skip invisible_field honeypot), one visible input, post-submit pause, real-browser UA |

Stealth mode for browser bots also **skips the recon pass** — no
`/robots.txt` read, no Disallow-path follow — which means stealth
sessions don't trip `robots_read` or `admin_secrets` honeypots
organically. Stealth sqlmap doesn't read robots either (it never did).

### Compose

Four new services under `profiles: ["stealth"]`, each reusing the
matching non-stealth image with `ALLM_STEALTH=true`:

```sh
docker compose --profile stealth up -d --build       # 4 stealth twins
```

### Eval cells added

Both `with_hp` and `ml_only` heads get two new blocks alongside
phase 8's `per_family` / `per_target_app` / `agent_vs_benign_bot`:

| key | shape | what it answers |
|---|---|---|
| `per_stealth` | `{"true": {test_sessions, alerts, alert_rate, n_agent_truth, n_benign_truth}, "false": {…}}` | Stealth-vs-not as a top-level cut. Agent-truth and benign-truth counts let consumers interpret alert_rate as TPR or FPR. |
| `per_family_stealth` | `{"<family>::stealth=true": {family, stealth, kind, test_sessions, alerts, alert_rate, recall_if_agent, fp_rate_if_benign}, "<family>::stealth=false": {…}, …}` | The load-bearing block: does stealth degrade recall for this specific family? Compute `recall_if_agent_stealth_true / recall_if_agent_stealth_false` per family. |

The phase 6+ Session dataclass picks up `stealth` from the
`sessions.jsonl` provenance row, falling back to a majority vote
across the session's request rows. Pre-phase-9 data parses as
`stealth=false` (no provenance, no per-row stealth column → falsy
majority).

### Run

```sh
python3 tests/phase9_smoke.py                              # synth-fed, no docker, ~7s
```

Smoke asserts: `Session.stealth` resolves both truthy and falsy, at
least one agent family has both stealth=true AND stealth=false
sessions, and the eval JSON `per_stealth` + `per_family_stealth`
blocks are populated on both heads with no "accuracy" leak.

### What phase 9 explicitly does not do

- Real OpenAI / Gemini PentesterPro (still mocked). Phase 11+.
- nikto / ffuf / Scrapy / raw httpx generators. Phase 11+.
- crAPI as a fourth target. Phase 11+.
- ~~Held-out-stealth eval (train stealth=false only, eval stealth=true)~~
  **Phase 10 ships this** — see below.

## Phase 10 — held-out-stealth eval + orchestrator sweep

Phases 6–9 added the schema axes (`target_app`, `family`, `stealth`,
`security_level`) and the stealth twins, and phase 8/9 added the
per-axis eval cells. Phase 10 connects them end-to-end:

### Held-out-stealth eval (`detector/heldout.py`)

For each agent family that has BOTH stealth=true AND stealth=false
sessions, train the detector WITHOUT that family's stealth=true
sessions and eval recall on them. Compare to in-distribution recall
on the same family's stealth=false sessions.

Symmetric to phase 5/8's `overfits_attacker` gate, applied to the
stealth axis:

```
stealth_evades_detector := held-out stealth=true recall
                          < 0.5 × in-distribution stealth=false recall
```

Heldout JSON gains a `per_family_stealth_holdout` block per family:

```json
{
  "playwright_bot": {
    "in_dist_nonstealth_recall": 0.85,
    "heldout_stealth_recall": 0.30,
    "heldout_ratio": 0.35,
    "stealth_evades_detector": true,
    "n_train_sessions": 33,
    "n_holdout_sessions": 6
  },
  ...
}
```

Families missing one of the two stealth values get `{"skipped":
"family missing one of stealth=true/false in data"}` so the gate
fails cleanly rather than silently dropping.

### Orchestrator sweep (`orchestrator/sweep.py`)

Per the spec — **"sweep `{target} × {family} × {security_level} ×
{stealth}`, with benign traffic running continuously and
interleaved"** — `sweep.py` builds a plan of cells across those four
axes, drives `docker compose run --rm` per cell, then assembles a
single sweep report on top of the merged data:

| component | what |
|---|---|
| `default_config()` | returns a `SweepConfig` with sensible axis values: DVWA + Juice Shop + VAmPI; the 4 agent families; `low` + `medium` security; both stealth values. Trims combinations that don't make sense (Selenium/Puppeteer at VAmPI — no DOM; sqlmap-stealth × high security — yields nothing). Default ≈ 34 cells. |
| `build_sweep_plan(config)` | pure-Python; returns `list[SweepCell]`. Testable without docker. |
| `start_benign(config)` | brings up the 5 benign_bot services once; they run continuously underneath the sweep so the FP/hour denominator stays meaningful. |
| `execute_sweep(plan)` | drives `docker compose run --rm` per cell with `ALLM_TARGET / ALLM_TARGET_APP / DVWA_SECURITY_LEVEL / ALLM_SESSIONS / ALLM_STEALTH` env. Cells continue after a failure — the eval already tolerates partial data. |
| `per_cell_census(plan, sessions_path)` | joins each planned cell to the actual `sessions.jsonl` provenance rows so the report shows which cells actually produced data. |
| `build_sweep_report(data_dir, plan)` | runs `train.py + eval.py + heldout.py` as subprocesses, attaches the census, and returns one report dict that the CLI writes to `data/reports/sweep_<ts>.json`. |

```sh
# the canonical end-to-end sweep on the operator's machine
python3 orchestrator/sweep.py --sessions 2 --benign-sessions 3

# retry the report after an aborted sweep without re-running cells
python3 orchestrator/sweep.py --skip-docker
```

### Smoke

```sh
python3 tests/phase10_smoke.py   # synth-fed, no docker, ~20s
```

Asserts: `default_config()` covers ≥3 targets / ≥4 families / both
stealth values and VAmPI is sqlmap-only; `per_family_stealth_holdout`
has at least one family that actually ran (not just `skipped`);
`per_cell_census` correctly joins planned cells to provenance rows
(matches the 4 cells our synth produced, leaves the nonexistent
fifth cell as `any_provenance_seen=False`); `build_sweep_report`
emits `summary / per_cell_census / eval / heldout` blocks; "accuracy"
never appears.

### What phase 10 explicitly does not do

- ~~The 4 remaining scanner generators (nikto, ffuf, raw httpx, Scrapy)~~
  **Phase 11 ships these.**
- Real OpenAI / Gemini PentesterPro. Phase 12+.
- crAPI as a fourth target. Phase 12+.
- Held-out-(target_app) eval. Not asked for in the original spec.

## Phase 11 — scanner family + proxy session-schema cache

The original spec's "non-browser scanners: sqlmap, nikto, ffuf, raw
httpx/Scrapy" was sqlmap-only after phase 7. Phase 11 ships the
remaining four under `profiles: ["attack-extended"]`.

### Generators

| family | engine | distinctive HTTP signal |
|---|---|---|
| `raw_httpx` | Python + httpx | tight per-request loops, no external tool — rotates SQLi / XSS / path-traversal / CMDi payloads through fixed endpoint list. Sets X-Allm-* natively. |
| `ffuf` | Go binary (pinned 2.1.0, downloaded at build) | path fuzzer; uses `-H` to attach X-Allm-* to every probe; rate-bounded via `-rate` / `-t` (1 thread + rate 5 in stealth, 10 threads + rate 50 in fast). |
| `scrapy` | Python Scrapy crawler | `LinkExtractor` walks the site + submits the first form on every page with a SQLi payload. `DEFAULT_REQUEST_HEADERS` attaches X-Allm-* framework-wide. |
| `nikto` | Perl (sullo/nikto pinned 2.5.0, cloned at build) | comprehensive web vuln scanner. Can't set per-request headers — uses the proxy schema cache (below) plus `-StaticCookies` for sid carriage. Stealth uses `-Tuning x6` + `-Pause 2`. |

All four ship a single image per family; `ALLM_STEALTH=true` at run
time switches the bot into stealth mode. No separate stealth services
(would be redundant — the same binary handles both modes).

### Proxy session-schema cache

nikto can't set per-request HTTP headers easily. Phase 11 adds a
small cache in `capture/proxy.py`:

```
_session_schema_cache: dict[str, dict]  # session_id -> {class, family, ...}
_session_src_label_cache: dict[str, str]  # session_id -> src_label
```

On every request:
- If the request **carries X-Allm-* headers**, resolve the schema
  fresh and `setdefault` it into the cache (first-write-wins per sid).
- If the request **doesn't carry X-Allm-* headers** but the cache has
  an entry for its sid, hydrate the log row's schema from the cache.

So nikto's bootstrap → labeled httpx request mints the sid + populates
the cache, then nikto's scan requests inherit the cached labels.
Result: `requests.jsonl` rows from nikto's scan still carry
`class=agent, family=nikto, target_app=…`, and `per_family` /
`per_target_app` slices stay clean instead of collapsing to
`"unknown"`.

The same cache helps any future tool that follows the bootstrap-then-
run pattern (raw HTTP-replay attackers, custom scanners, etc).

### Sweep config update

`orchestrator/sweep.py` `_FAMILY_SERVICES` and `_TARGETS` now include
the four new families. Default sweep grew from **34 cells → 70 cells**
(VAmPI now covers `sqlmap` + `raw_httpx` + `ffuf`; everything else
covers all 4 new + 4 old browser/sqlmap families across DVWA +
Juice Shop, low + medium security, both stealth values).

### Smoke

```sh
python3 tests/phase11_smoke.py   # synth-fed, no docker, ~8s
```

Asserts: all 4 modules compile; sweep config covers them and VAmPI
is non-browser-only (sqlmap + raw_httpx + ffuf); proxy schema cache
populates from a labeled request and hydrates an unlabeled one (if
aiohttp is installed locally — otherwise the docker-side smoke
exercises it for real); synth-feeding the 4 new families through
train + eval produces `per_family` entries for each, all classified
as `kind=agent`. No "accuracy" leak.

### What phase 11 explicitly does not do

- Real OpenAI / Gemini PentesterPro (still mocked). Phase 13+.
- ~~crAPI as a fourth target.~~ **Phase 12 ships this.**
- A production-side passive ingest. Phase 13 candidate.

## Phase 12 — crAPI fourth target

crAPI (OWASP's vulnerable API security playground) joins DVWA + Juice
Shop + WebGoat + VAmPI as the fourth bundled target. Unlike VAmPI
(which is a single Flask app), crAPI is a 4-microservice React-SPA-
fronted application with its own dependency stack — 7 backing
services total. Big surface area for a single target, but it brings
realistic API-side attack patterns: JWT / OAuth misuse, BOLA-style
authorization bugs, mass assignment, business-logic abuse.

### Compose layout (under `profiles: ["crapi"]`)

| service | image | role |
|---|---|---|
| `crapi` | `crapi/crapi-web` | user-facing gateway (port 8888, internally reverse-proxies to the 3 backends) |
| `crapi_identity` | `crapi/crapi-identity` | auth / JWT / OAuth |
| `crapi_community` | `crapi/crapi-community` | forum / posts microservice |
| `crapi_workshop` | `crapi/crapi-workshop` | vehicle workshop business logic |
| `crapi_mongodb` | `mongo:6` | community service DB |
| `crapi_postgresdb` | `postgres:14` | identity + workshop DB |
| `crapi_rabbitmq` | `rabbitmq:3-management-alpine` | message broker |
| `crapi_mailhog` | `mailhog/mailhog` | SMTP capture for password reset flows |
| `capture_crapi` | `allm-capture` (reused phase 6 image) | sibling capture proxy fronting `crapi:8888` with `ALLM_TARGET_APP=crapi` |

All 9 services on `allm_lab`, none publish ports. crAPI is heavier
than the other targets so it sits behind its own `crapi` profile
instead of `multitarget` — bring it up explicitly:

```sh
docker compose --profile crapi up -d --build
```

### Sweep matrix grew 70 → 102

`orchestrator/sweep.py` `_TARGETS` gains a `crapi` entry that allows
**both browser and non-browser families** (unlike VAmPI which is
non-browser-only). crAPI has a React SPA frontend that the browser
families can crawl (exercising the XHR-to-API path) and a JSON API
that sqlmap / raw_httpx / ffuf can probe directly. 32 of the 102
default cells now exercise crAPI.

### Smoke

```sh
python3 tests/phase12_smoke.py   # structural, no docker, <1s
```

Asserts: all 9 crAPI services are declared under `profiles:["crapi"]`
on the `allm_lab` network with NO published ports; `target_guard`
accepts `capture_crapi` and still rejects external hosts; the sweep
plan produces crAPI cells across browser + non-browser families with
both stealth values; `per_cell_census` joins planned crAPI cells to
provenance rows correctly.

### What phase 12 explicitly does not do

- Pull labels / forms / specific endpoints from the crAPI source.
  The browser generators land on whatever the React SPA links to;
  the non-browser scanners probe a fixed list of generic API paths
  (`/api/users`, `/search`, etc.) that may or may not exist on crAPI.
  Real crAPI-specific attack scripts (token replay against the
  identity service, BOLA against `/identity/api/v2/user/dashboard`,
  etc.) are out of scope — the original spec was about
  detection-side, not attack-side fidelity.
- Bring crAPI under the `multitarget` profile. Too heavy — it gets
  its own opt-in profile.
- Run the actual crAPI containers in the in-sandbox smoke. The
  structural check covers what we can verify without docker; the
  real test is `docker compose --profile crapi up -d --build` on
  your machine.

## Out of scope

- Windows agents / cross-OS deployment.
- Production deployment, TLS, auth — lab is loopback-only by design.
- Authoring new exploits. Attacks come exclusively from existing tools
  pointed at DVWA.
- Reporting accuracy as a metric. Anywhere. If you ever find one in this
  repo, that's a bug — please file it.
