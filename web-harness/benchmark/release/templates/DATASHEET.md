# Cernis benchmark — DATASHEET

Following Gebru et al., "Datasheets for Datasets" (Communications of the
ACM 64.12, 2021). Section ordering matches the original. Every
quantitative claim references either the release manifest
(`manifest.json`) or `data/excluded.json` so the numbers can be
audited mechanically.

This datasheet describes release **{{VERSION}}** (built
**{{BUILT_AT}}**, splits version **{{SPLITS_VERSION}}**).

---

## 1. Motivation

### For what purpose was the dataset created?

To make it possible to **detect autonomous LLM-driven web agents** in
HTTP traffic, and to make that work *measurable*. The premise: agentic
LLM browsers (browser-use, Devin-style tools, Anthropic's computer-use,
real production browser-agent products) generate distinct behavioral
signatures from real humans and from legacy automation tools — and
those signatures matter for fraud, abuse, scraping, and security
operations. Existing public benchmarks for "is this traffic a bot?"
predate the LLM agent class entirely.

This dataset is the public face of the **Cernis benchmark**: a fixed,
versioned, family-disjoint evaluation set so claims about generalisation
to new agent families and to stealth variants are pinned to concrete
numbers, not handwaved.

### Who created the dataset?

Jack Adams-Lovell (independent). Released under MIT (code) and CC BY 4.0
(data). The development repository is at
<https://github.com/adamsjack711-ux/Cernis>.

### Who funded the dataset's creation?

Self-funded, no external grants. Cloud LLM API calls for the real-agent
capture channel are paid out of pocket by the maintainer; the
real-agent generator (`generators/real_agent/`) is the only lab
component that calls any cloud API, gated behind its own compose
profile.

---

## 2. Composition

### What do the instances represent?

Each instance is one **browser session**, identified by a `session_id`
(a UUID hex string minted by the capture proxy on first request). A
session is a sequence of HTTP requests carrying the same `cernis_sid`
cookie within a 30-minute inactivity window.

Sessions belong to one of three classes:

- **`agent`** — autonomous, intentionally adversarial / agentic. Either
  a real LLM-driven browser agent (`real_agent`, family
  `llm_browser_agent`) or a non-LLM attack tool (Playwright payload
  spray, sqlmap, ffuf, nikto, Scrapy, selenium, puppeteer,
  PentesterPro-flavored prompt-driven agent).
- **`benign_bot`** — legitimate non-human automation: googlebot
  crawler, uptime monitor, RSS reader, link unfurler, CI health check.
- **`human`** — either `human_real` (a real consented browser session
  on the bundled DVWA target) or `human_sim` (a Playwright-driven
  simulator standing in for bulk benign data).

### How many instances are there?

See `manifest.json::counts`. The current release composition:

- `total_sessions_published: {{N_PUBLISHED}}`
- `n_excluded_by_consent: {{N_EXCLUDED}}` (dropped by the consent
  filter — see §3.6 + `data/excluded.json`)

By-class / by-family / by-target / by-stealth rollups are at:

{{COUNTS_TABLE}}

### What data does each instance consist of?

Each row in `data/features.jsonl` carries the public feature schema:

| field | shape | meaning |
|---|---|---|
| `session_id` | str | opaque join key |
| `target_app` | str | which deliberately-vulnerable target the session hit (`dvwa` / `juice_shop` / `webgoat` / `vampi` / `crapi`) |
| `agg` | list[12] | session aggregates: request volume, cadence statistics, path breadth, error rates, peak rate, beacon-derived timings |
| `seq` | list[T × 9] | per-request features in chronological order |
| `hp`  | list[4]  | honeypot trip flags (`canary`, `invisible_field`, `admin_secrets`, `robots_read`) |

The matching row in `data/truth.jsonl` carries the held-back labels:

| field | meaning |
|---|---|
| `y` | binary — 1 if `klass == "agent"` else 0 |
| `family` | finer-grained label (e.g. `playwright_bot`, `googlebot`, `human_real`) |
| `klass` | one of `agent` / `benign_bot` / `human` / `unknown` |
| `stealth` | `true` if the generator ran in stealth mode (slow cadence, honeypot-avoidant) |
| `target_app` | duplicates the features row's value |
| `duration_s` | session wall-clock duration |

### Is there a label or target associated with each instance?

Yes. The detection target is binary `y = (klass == "agent")`. The
finer-grained `family` label is used for the held-out-family and
held-out-stealth slices.

### Are there recommended data splits?

Yes. This release ships the public splits (`splits/v1/`):

- `public_train.json` — 60% of publishable sessions (shuffled
  deterministically by seed)
- `public_dev.json` — 20% (for early-stopping / threshold tuning)
- `public_test.json` — 20% (for in-distribution PR-AUC + FP/hour)

The hidden splits (held by the maintainers, NOT in this release):

- `private_heldout_family.json` — all sessions of N agent families
  picked deterministically; those families never appear in any
  public split.
- `private_heldout_stealth.json` — the `stealth=true` sessions of
  public agent families that have both stealth axes.

The split-building rules and family-disjointness invariants are in
`benchmark/splits.py`; the deterministic checksum on each split file
catches accidental edits.

### Are there errors / noise / redundancies in the dataset?

- Synthetic data dominates v0.1. The real-agent channel
  (`llm_browser_agent`) and the real-human channel (`human_real`) are
  newer than the bot generators; counts may be small or absent in
  early releases. The detector eval already breaks out per-family
  recall so this is observable in the metrics, not hidden.
- Synthetic humans (`human_sim`) and synthetic agents share the same
  Playwright / Chromium fingerprint. This is documented as a known
  limitation; per `web-harness/README.md` §"Simulator-vs-real-human
  limitation", the JS-beacon discriminates on cadence rather than
  browser engine.
- Honeypot trips are sparse — many sessions never trip any. This is
  by design (honeypots are precision tools, not coverage tools).

### Does the dataset contain data that might be considered confidential?

No. The dataset is restricted to two surfaces:

- Deliberately-vulnerable test apps (DVWA, Juice Shop, WebGoat,
  VAmPI, crAPI). All are public open-source targets specifically
  built for purple-team practice. No live customer or production data.
- Consented human browsing of those same targets. See §3 (Collection)
  for the consent flow.

There are no business confidential records, no private chats, no
financial data, no medical data. **No real customer or production
traffic is included.**

---

## 3. Collection Process

### How was the data acquired?

Two distinct collection channels:

1. **Generator-produced sessions** (synthetic agents + benign bots
   + `human_sim`). Each generator is a containerized client (Playwright
   bot, sqlmap, ffuf, etc.) that drives the bundled targets through a
   capture reverse proxy. The proxy logs request-level features
   (`data/requests.jsonl`) and proxy-injected JS beacons
   (`data/beacons.jsonl`). All loopback-bound; nothing leaves the
   host except the optional real-agent's LLM calls.

2. **Consented real-human sessions** (`human_real`). The capture
   proxy runs a `:8090` listener gated behind a consent landing page
   (`capture/consent.html`). The flow is:
   - User visits `http://127.0.0.1:8090/__consent`.
   - Reads the consent text — what is and isn't collected, the
     purpose, the explicit statement that the dataset may be released
     publicly.
   - Clicks **"I agree — start the session"**.
   - The proxy mints a `consent_id` (UUID) and a session id
     (`cernis_sid` cookie), writes one row to `data/consent.jsonl`
     (with the consent text version and a coarse browser bucket) and
     one row to `data/sessions.jsonl` (provenance, including the
     consent_id linkage), then 302-redirects the user to the target.
   - Every other path on the `:8090` listener returns `403 Consent
     required` until the consent cookie is present.

3. **Real-LLM-agent sessions** (`real_agent`, family
   `llm_browser_agent`). A `browser-use`-backed agent drives DVWA via
   the capture proxy. This is the only lab component with cloud
   egress; gated under a `real-agent` compose profile so it does not
   auto-start. The agent calls `target_guard.get_target()` BEFORE any
   LLM client is instantiated, so an injected prompt cannot steer the
   browser off the bundled-target allow-list.

### Who was involved in the data collection process?

- Generators run unattended in containers.
- Real-human capture is operated by the maintainer for himself plus
  invited collaborators on the consent listener. **No third-party
  recruitment platform was used.** No compensation, no IRB review (the
  data is non-PII by construction — see §4 below).
- The real-LLM-agent runs are operated by the maintainer.

### Over what timeframe was the data collected?

Capture started 2026-06-20 with the phase-bench-1 consent infrastructure.
The release manifest's `built_at` field pins the snapshot timestamp.

### Were any ethical review processes conducted?

No formal IRB. The maintainer's reasoning:

- The dataset contains zero personally-identifying information by
  construction. The capture proxy drops raw IP and replaces raw
  User-Agent with a coarse bucket (`chrome-desktop`, `firefox-mobile`,
  …) at write time. Request bodies are never logged. Auth /
  cookie / set-cookie values are reduced to `has_*_header` booleans
  before any row hits disk.
- Real-human sessions are opt-in only, with a consent text that
  explicitly names public release. Sessions whose consent doesn't
  cover redistribution are dropped at release-build time (see
  `data/excluded.json` for the audit trail).
- The detection target (the LLM agent class) is the maintainer's own
  data — same project member operates the real-agent runs.

A formal review process is appropriate if the dataset expands to
recruit external participants outside the maintainer's circle.

---

## 4. Preprocessing / Cleaning / Labeling

### Was any preprocessing done?

Yes — *anonymization*, not transformation. The pipeline in order:

1. **In-redaction at write time** (capture/proxy.py). Before any row
   touches disk:
   - `Authorization` / `Cookie` / `Set-Cookie` are reduced to
     `has_*_header: bool` (the values never persist).
   - Request bodies are never logged.
   - For `human_real` sessions specifically: `src_ip` → `None`,
     raw `User-Agent` → coarse bucket (e.g. `chrome-desktop`).
2. **Consent coverage filter** (release/scrub.py
   `filter_publishable_session_ids`). For every `human_real` session,
   the release builder checks the matching consent row's
   `consent_text_version` against the `CONSENT_COVERAGE` map.
   Sessions without publishable coverage are dropped + logged to
   `data/excluded.json`.
3. **Regex scrub gate** (release/scrub.py `scan_directory`). Before
   tarring, the release builder grep-scans every released file for:
   IPv4, IPv6, raw User-Agent fragments (`Mozilla/`, `Chrome/d`,
   …), `Authorization:` values, `Cookie:` values, length-gated API
   keys (`sk-{live|ant|proj|test|or}-…`), PEM private keys, GitHub
   PATs, AWS access keys, JWTs. Any hit aborts the release.

The full pipeline is documented in `benchmark/release/scrub.py` with
per-pattern rationales.

### Was the "raw" data saved?

The proxy's raw JSONL files (`data/requests.jsonl`,
`data/sessions.jsonl`, `data/beacons.jsonl`, `data/honeypots.jsonl`)
exist on the maintainer's host but are **gitignored**. The release
ships only the derived public-schema features
(`data/features.jsonl`) plus the held-back truth (`data/truth.jsonl`),
because the public feature schema has a smaller privacy surface than
the raw rows and is everything the eval needs.

### What was labelled, and how?

`y`, `family`, `klass`, `target_app`, `stealth` are determined at
**capture time**, not annotated after the fact. Every generator
identifies itself via `X-Cernis-*` headers and a one-shot provenance
POST to `/__provenance`. The capture proxy persists those labels on
every per-row entry. No human labelling, no inferred labels, no
auto-labeling. Family-misclassification therefore reduces to "did the
generator label itself correctly?" — auditable in
`benchmark/release/build_release.py` (the manifest's `by_family` count
is the answer).

---

## 5. Uses

### What tasks has the dataset been used for?

Currently: training and evaluating the in-repo Cernis detector (a
hybrid GRU + session-aggregate + honeypot model). The eval surface
reported never includes accuracy (see TASK.md).

### What (other) tasks could the dataset be used for?

- Anti-abuse / anti-fraud research on agentic web traffic
- Comparative benchmarking of new bot-detection approaches
- Calibration studies on FP/hour budgets for security alerting
- Ablation studies on which feature families carry which class signal

### Is there anything about the dataset's composition that may impact future use?

Yes — call out *up front* so users don't get burned:

- **Synthetic-vs-real proportions are skewed.** The bulk of v0.1 is
  generator-produced (deterministic, easy to overfit). The real
  human and real LLM agent channels are newer and smaller. A
  detector that crushes the public test set may still collapse on
  the (hidden) held-out-family split — which is exactly the gap
  the benchmark is built to surface.
- **Simulator-vs-real-human limitation.** `human_sim` and the
  generator-side agent bots share the Playwright + Chromium
  fingerprint. Detection must discriminate on cadence / structure,
  not browser engine. Documented in `web-harness/README.md`.
- **Small-N caveat for stealth.** Stealth variants ship for a subset
  of agent families only; per-family stealth recall on small N is
  noisier than the headline numbers suggest. The
  `per_family_stealth` cells in `results.json` carry the per-cell
  count so noise is visible.
- **Single-target dominance.** DVWA accounts for most sessions in
  v0.1. The `per_target_app` slice surfaces this. Detectors that
  overfit DVWA's HTML conventions will not generalise.

### Are there tasks for which the dataset should NOT be used?

- **Real adversarial attribution.** This dataset is for *behavioural
  pattern* research. It is not a fingerprint database; it cannot
  identify or attribute a specific organisation, IP, or human.
- **Training models that key on PII.** None is present, by
  construction. Don't try to recover it.
- **Drawing security operations conclusions for production systems
  without your own data.** The lab is synthetic; FP/hour numbers from
  the benchmark do not transfer 1:1 to your production alerting.

---

## 6. Distribution

### How is the dataset distributed?

- Source repository: <https://github.com/adamsjack711-ux/Cernis>
- Release artifacts: `dist/cernis-benchmark-{{VERSION}}.tar.gz` +
  `.sha256` side-car, produced by `benchmark.release.build_release`.

### When will the dataset be distributed?

Releases are tagged by the maintainer when a milestone lands. v0.1
is the framework + scrub gate + reference baselines release. Future
releases land as the real-human and real-LLM-agent capture channels
accumulate sessions.

### What licenses apply?

- **Code:** MIT (see `LICENSE` and SPDX header)
- **Data:** CC BY 4.0 (see `LICENSE-DATA` and SPDX header)

### Will the dataset be updated?

Yes. Splits and feature schema are versioned (`splits_version`,
`FEATURE_SCHEMA_VERSION` in `benchmark/contract.py`). Bumping either
means a new release. Baselines published against v0.1 are not
comparable to those against v0.2 unless the bump notes say otherwise.

---

## 7. Maintenance

### Who maintains the dataset?

Jack Adams-Lovell. Contact via the GitHub repo's issue tracker.

### Is there an erratum?

Errata for each release land in the GitHub release notes attached to
the version tag (e.g. `v0.1`).

### How can someone contribute?

The repo accepts PRs for harness improvements, new baselines, bug
fixes. Data contributions require operating the capture proxy on
your own host AND running the consent flow against the maintainer's
agreed consent text (`v1` or later — see
`benchmark/release/scrub.py::CONSENT_COVERAGE`). The maintainer
reserves the right to refuse data contributions whose collection
process can't be verified end-to-end.
