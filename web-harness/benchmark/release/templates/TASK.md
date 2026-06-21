# Cernis benchmark — TASK

**Task:** given a sequence of HTTP requests grouped into a session,
decide whether the session is an *autonomous LLM-driven browser agent*
or *not* (human, benign automation bot, or simulated human).

This file is the short, formal task spec. For the I/O contract a
submission has to implement, see `benchmark/SUBMISSION.md`. For the
data, see `DATASHEET.md`. For licensing, see `LICENSE` (code) and
`LICENSE-DATA` (data).

## Input

One record per session, in the public feature schema:

```json
{
  "session_id": "abc123…",
  "target_app": "dvwa | juice_shop | webgoat | vampi | crapi",
  "agg": [n_req, delta_mean, delta_std, delta_p95, n_paths, frac_4xx,
           frac_5xx, max_rps, js_ran, ttfi, dom_read, duration_ms],
  "seq": [[delta_ms, status, is_post, path_bucket, req_bytes,
            resp_bytes, ua_bucket, header_count, header_hash], …],
  "hp":  [canary, invisible_field, admin_secrets, robots_read]
}
```

Truth is held back. The submission never sees `y` / `family` / `klass` /
`stealth` at predict time. See `benchmark/SUBMISSION.md` for the full
schema, including which fields ARE visible at train time.

## Output

One JSON object per session:

```json
{"session_id": "abc123…", "agent_score": 0.87}
```

`agent_score` ∈ [0, 1], higher = more confident the session is an
autonomous agent. Missing sessions or duplicate session_ids → eval fails.

## Metrics

### Primary

- **`public_test`:** PR-AUC and FP/hour at the FP/hour budget on the
  public test split. Threshold derived from the score distribution on
  the same split; the harness picks the most permissive τ such that
  FP/hour ≤ budget.
- **`heldout`** (when run against the hidden split set the maintainers
  hold locally): held-out-family PR-AUC at the FP/hour budget. The
  positives come from agent families the model has NEVER seen at train
  time; the negatives come from `public_test`'s benign sessions. This
  is the headline metric for "does this detector generalize to new
  agent families?"

### Secondary

- Per-family recall (for agents) and per-family FP rate (for benign
  automation / simulated humans)
- Per-target-app alert rate
- Agent-vs-benign_bot confusion (the load-bearing question: does the
  detector tell legitimate non-browser bots apart from agents?)
- For `heldout`: held-out-stealth recall — recall on the stealth
  variants of public families that the model only saw in their
  non-stealth form at train time.

### Forbidden

**Accuracy is never reported.** The harness asserts that the
`accuracy` substring does not appear in `results.json` or `report.txt`;
a violation raises before write. PR-AUC + FP/hour + per-family recall
together carry the load that accuracy used to pretend to.

## Rules

1. **No training on test.** The `public_test` split is for scoring only.
   The hidden splits (`private_heldout_family`, `private_heldout_stealth`)
   are not shipped with this release; they are held by the benchmark
   maintainers and can only be evaluated against by submitting your
   `submission.py` (or sending a clone of it) to the maintainers for an
   off-line run. Any submission whose code reads files outside the
   public splits at predict time is disqualified.

2. **The submission's `predict` is called once.** Parallelize
   internally; the harness does not parallelize for you.

3. **Network calls at predict time are honor-system-disallowed.**
   The Python-entrypoint flavor of the harness does not sandbox the
   submission. Submissions that fetch a model from the internet at
   predict time will produce non-reproducible numbers and will not be
   accepted onto any future leaderboard.

4. **`agent_score` must be calibrated to `[0, 1]`.** The harness picks
   a threshold from the FP/hour budget; if your scores are not on a
   meaningful scale, the threshold pick degenerates.

## Reproducing the baselines

```sh
make eval SUBMISSION=benchmark/baselines/ua_rule
make eval SUBMISSION=benchmark/baselines/timing_threshold
make eval SUBMISSION=benchmark/baselines/honeypot_only
make eval SUBMISSION=benchmark/baselines/aggregate_only
make eval SUBMISSION=benchmark/baselines/gru_only
make eval SUBMISSION=benchmark/baselines/hybrid
```

All six baselines are wrapped to the same submission contract — read
their `submission.py` files for working examples.

## Release version

Built from benchmark release **{{VERSION}}** on **{{BUILT_AT}}** with
splits version **{{SPLITS_VERSION}}**. See `manifest.json` for the
release-level checksums and counts.
