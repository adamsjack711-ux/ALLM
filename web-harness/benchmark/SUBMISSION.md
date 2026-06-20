# Cernis benchmark — submission contract

A submission is a directory with one required file (`submission.py`) and
optional siblings. The harness imports it, optionally calls `train()` on
the public training features, calls `predict()` on the evaluation split's
features, joins the returned scores with the held-back truth, and emits
the metric suite.

This phase ships the **Python entrypoint** flavor only. A container
flavor (`docker run --network none`) is planned for a follow-up phase.

## Required interface

```python
# submission.py

def predict(features: list[dict]) -> list[dict]:
    """Score every session.

    Input:  list of public-feature dicts (see "Public feature schema"
            below). The list is unordered and may include thousands
            of sessions.

    Output: list of {session_id: str, agent_score: float in [0, 1]}.
            One row per input session_id. Order doesn't matter.
    """
```

That's the minimum. Optional sibling that the harness will call before
`predict` if defined:

```python
def train(train_features: list[dict], dev_features: list[dict]) -> None:
    """One-time training step (or no-op).

    Called before `predict` whenever the harness has access to the
    public training splits. `dev_features` is for early-stopping /
    threshold tuning; you do NOT have to use it.

    Hold all state on a module-level variable or a class instance.
    The harness does not pickle / serialize anything between train
    and predict — they happen in the same process.

    Training features carry labels (see "Train vs predict schemas"
    below). Eval (predict) features do not.
    """
```

If `train` is not defined, the harness skips straight to `predict`.

### Train vs predict schemas

Two distinct shapes, deliberately:

- **`train()` / `dev_features`** include the supervised labels (`y`,
  `family`, `klass`, `stealth`). Any supervised baseline needs them.
- **`predict()` features** never include labels. The submission scores
  blind.

The harness builds both shapes from the same `data/` JSONL but never
hands the eval input to a submission with the truth still attached.

## Public feature schema (v1)

Every feature dict has:

| key | type | description |
|---|---|---|
| `session_id` | str | the join key. Treat as opaque. |
| `target_app` | str | one of `dvwa` / `juice_shop` / `webgoat` / `vampi` / `crapi`. Useful for slicing if your model is target-aware. |
| `agg` | list[float] (len 12) | session aggregates: `[n_req, delta_mean, delta_std, delta_p95, n_paths, frac_4xx, frac_5xx, max_rps, js_ran, ttfi, dom_read, duration_ms]`. All numeric, log1p'd where indicated by the source code (`detector/features.py::_agg_features`). |
| `seq` | list[list[float]] (T × 9) | per-request features in chronological order: `[delta_ms, status, is_post, path_bucket, req_bytes, resp_bytes, ua_bucket, header_count, header_hash]`. Variable T per session. |
| `hp` | list[float] (len 4) | honeypot trip flags: `[canary, invisible_field, admin_secrets, robots_read]`. Each is 0.0 or 1.0. |

Fields **never** present in `predict()` features (held back so the
submission can't peek): `y`, `family`, `klass`, `stealth`, `duration_s`,
`src_label`.

The train features (`train()` / `dev_features`) additionally include
`y` + `family` + `klass` + `stealth` — supervised baselines need
them to fit. `duration_s` and `src_label` are NEVER exposed.

## Submission output schema

```jsonl
{"session_id": "abc123…", "agent_score": 0.87}
{"session_id": "def456…", "agent_score": 0.02}
```

- One row per session in the evaluation split. Missing rows → eval fails.
- Extra rows (session_ids not in the requested split) → eval fails.
- `agent_score` must be a calibrated number in `[0, 1]`. Higher = more
  confident this session is an autonomous agent.
- Duplicate `session_id` → eval fails.

A `label` field is allowed but ignored. The harness derives every
threshold from the score distribution and the FP/hour budget.

## What the harness does NOT do

- **Network isolation.** The Python entrypoint flavor does not sandbox
  the submission. Don't write a submission that fetches a model from
  the internet at predict-time — your numbers will not be comparable
  across runs. The planned container flavor will enforce
  `--network none`; until then this is an honor system.
- **GPU.** Submissions run on the same machine that runs the eval. If
  you need a GPU, train one elsewhere and ship the weights inside your
  submission dir.
- **Multi-process.** `predict` is called once with the full feature
  list. Parallelize internally if you like.

## What the metric suite looks like

The harness emits `results.json` with this shape:

```json
{
  "split": "public_test|heldout",
  "seed": 0,
  "submission": "benchmark/baselines/<name>",
  "n_sessions": 123,
  "session_hours": 4.5,
  "fp_per_hour_budget": 1.0,
  "primary": {
    "pr_auc": 0.876,
    "fp_per_hour": 0.92,
    "threshold": 0.41
  },
  "per_family": { "<family>": {"n": …, "recall_if_agent": …, "fp_rate_if_benign": …, "kind": "agent|benign_bot|human"}, … },
  "per_target_app": { "<app>": {"n": …, "alert_rate": …}, … },
  "agent_vs_benign_bot": {
    "agent_recall": 0.83,
    "benign_bot_fp_rate": 0.04,
    "confusion": {…}
  }
}
```

When `--split heldout`, `primary` also includes:

```json
{
  "heldout_family_pr_auc": 0.51,
  "heldout_family_recall_at_budget": 0.34,
  "heldout_stealth_recall": 0.22
}
```

`accuracy` never appears in `results.json` (the harness asserts this).

## Picking baselines

Six reference baselines live under `benchmark/baselines/`. Read them as
documentation of the contract:

- `ua_rule/` — trivial regex floor (no training)
- `timing_threshold/` — sigmoid over median delta_ms (no training)
- `honeypot_only/` — score = honeypot trip presence (no training)
- `aggregate_only/` — sklearn LogisticRegression on the 12 agg features
- `gru_only/` — the existing GRU head, session + honeypot ablated
- `hybrid/` — the existing full detector (the in-repo champion model)

## Running

```sh
# Build the split set once (uses the populated data/ directory)
make build-splits

# Evaluate a submission on the public test split
make eval SUBMISSION=benchmark/baselines/hybrid

# Evaluate against the hidden splits (requires private_*.json present)
make eval SUBMISSION=benchmark/baselines/hybrid SPLIT=heldout
```
