# Cernis benchmark — release {{VERSION}}

A benchmark for detecting **autonomous LLM-driven web agents**. Given a
sequence of HTTP requests grouped into a session, your detector decides
whether the session is an autonomous agent or not.

This release contains everything needed to run the public eval offline:
the harness, six reference baselines (from trivial floors to the
in-repo champion), the public train / dev / test splits, the task spec,
the dataset documentation, and licenses.

The hidden test splits (`private_heldout_family`, `private_heldout_stealth`)
are **deliberately not** in this release. They live on the maintainers'
hosts and are used to score submissions for "does your detector
generalize to new agent families and stealth variants it has never
seen?" If you want to evaluate against them, see `TASK.md` §Rules.

## Quick start

```sh
# Score the trivial UA-rule baseline on the public test split
make eval SUBMISSION=benchmark/baselines/ua_rule

# Score the in-repo champion (trained on public_train + public_dev)
make eval SUBMISSION=benchmark/baselines/hybrid
```

Results land in `data/reports/bench_public_test_<name>_seed0/`
(`results.json` + a readable `report.txt`).

## What's in this release

```
{{VERSION}}/
  README.md          ← you are here
  TASK.md            ← formal task spec + rules + metrics
  DATASHEET.md       ← Datasheets-for-Datasets data documentation
  LICENSE            ← MIT, code
  LICENSE-DATA       ← CC BY 4.0, data
  Makefile           ← `make eval SUBMISSION=…`
  manifest.json      ← release-level checksums + counts
  benchmark/
    SUBMISSION.md    ← submission contract (Python entrypoint)
    contract.py      ← features / truth schema + output validator
    evaluate.py      ← the eval harness
    splits.py        ← split-file read + checksum verification
    baselines/<6 baselines>/submission.py
  splits/v1/
    MANIFEST.json
    public_train.json   public_dev.json   public_test.json
  data/
    features.jsonl   ← public-schema feature dicts (no labels)
    truth.jsonl      ← held-back per-session truth
    excluded.json    ← consent-filter audit trail
```

The hidden split files (`private_*.json`) are **not** present.
`benchmark/evaluate.py` will refuse to read them under the public
`--split public_test` mode (allow-listed file enforcement).

## What's measured

PR-AUC + FP/hour + per-family recall + agent-vs-benign_bot confusion.
**Accuracy is never reported.** The harness asserts this.

See `TASK.md` for the full metric suite + the primary-vs-secondary
split + the FP/hour budget detail.

## Trust the data

The dataset documentation in `DATASHEET.md` follows the
"Datasheets for Datasets" convention (Gebru et al., 2018, updated
2021). Key points:

- No raw IP / raw User-Agent / request bodies / authorization /
  cookie values ever ship. The release-build pipeline runs a
  regex-based scrub gate that hard-blocks publication on any leak.
- Every `human_real` (real consented browser session) row originated
  from a session whose consent text explicitly permits public release.
  Sessions without that coverage are dropped before packaging; see
  `data/excluded.json` for the audit trail.
- The full anonymization + consent pipeline is documented in
  `DATASHEET.md` §3 (Collection) and §4 (Preprocessing).

## License

- **Code:** MIT — `LICENSE`
- **Data:** CC BY 4.0 — `LICENSE-DATA`

## Citation

```
Adams-Lovell, J. (2026). Cernis benchmark for AI-driven web agent
detection, version {{VERSION}}. https://github.com/adamsjack711-ux/Cernis
```

Built on **{{BUILT_AT}}** with splits version **{{SPLITS_VERSION}}**.
See `manifest.json` for the per-file checksums.
