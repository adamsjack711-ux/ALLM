"""Cernis benchmark harness (phase-bench-2).

Three pieces a detector author cares about:

  - `splits`           deterministic, versioned, family-disjoint splits
  - `contract`         the (session_id, agent_score) submission interface
  - `evaluate`         one-command harness that scores a submission and
                        emits the metric suite (PR-AUC, FP/hour, per-family
                        recall, held-out-stealth recall, agent-vs-benign_bot
                        confusion). Never accuracy.

See `benchmark/SUBMISSION.md` for the public feature schema and the rules
a submission has to follow.
"""
