"""Offline two-direction held-out eval DEMONSTRATION for the Anthropic
attacker family (phase-bench-5 machinery, synthetic sessions).

NOT a smoke / gate — a preflight artifact. `data/` has no captured
sessions yet (the real Claude batch hasn't run), so these PR-AUC / FP/hr
numbers are on a SYNTHETIC universe with random features: they prove the
two cuts run end-to-end and never leak accuracy, NOT the real model
footprint. Real numbers come after the live batch is captured.

Two cuts, each labeled precisely:
  (a) cross-BACKEND  — hold out one LLM backend (OpenAI vs Claude),
      both browser-use. Isolates "model footprint". Driven by
      build_split_set(heldout_super_family=...).
  (b) cross-FRAMEWORK — hold out the Playwright/Selenium agent families
      (browser-use LLM agents stay in train). Isolates "framework
      footprint". Driven by the per-family heldout (heldout_family_*).

Seeds 0-2, GroupShuffleSplit on session_id, PR-AUC + recall@FP-budget,
never accuracy.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "detector"))

from benchmark import evaluate as evalmod  # noqa: E402
from benchmark import splits as splitmod  # noqa: E402
from benchmark.build_splits import sessions_to_meta  # noqa: E402


def _universe():
    """Mixed universe: 2 OpenAI models + 2 Claude models (browser-use) +
    Playwright/Selenium framework agents + benign bots. Synthetic
    features — y=1 agents score high on the ua_rule curl bucket, benigns
    low — so the baseline produces a non-degenerate ranking."""
    from features import Session  # type: ignore
    rng = np.random.default_rng(0)
    sessions = []

    def add(family, klass, y, target_app, n, curl_bucket):
        for i in range(n):
            seq = rng.uniform(0, 1, size=(8, 9)).astype("float32")
            seq[:, 6] = curl_bucket
            sessions.append(Session(
                session_id=f"{family}-{target_app}-{i:02d}",
                src_label=family, family=family, klass=klass,
                y=y, duration_s=30.0 if y else 120.0, ts_start=0.0,
                seq=seq, agg=rng.uniform(0, 1, size=12).astype("float32"),
                hp=np.zeros(4, dtype="float32"),
                n_req=8, target_app=target_app, stealth=False,
            ))

    for fam in ("llm_openai_gpt_4o_mini", "llm_openai_gpt_4_turbo",
                "llm_anthropic_claude_haiku_4_5", "llm_anthropic_claude_sonnet_4_6"):
        for app in ("dvwa", "juice_shop"):
            add(fam, "agent", 1, app, 4, 0.3)
    # Non-LLM framework agents (the cross-framework heldout target)
    for fam in ("playwright_bot", "selenium_bot"):
        for app in ("dvwa", "juice_shop"):
            add(fam, "agent", 1, app, 4, 0.3)
    for fam in ("googlebot", "uptime_monitor"):
        for app in ("dvwa", "juice_shop"):
            add(fam, "benign_bot", 0, app, 4, 1.0)
    return sessions


def _run(sessions, *, seed, heldout_super_family=None, n_heldout_families=2):
    metas = sessions_to_meta(sessions)
    split_set = splitmod.build_split_set(
        metas, seed=seed, n_heldout_families=n_heldout_families,
        heldout_super_family=heldout_super_family,
    )
    with tempfile.TemporaryDirectory(prefix="cernis_evaldemo_") as td:
        tdp = pathlib.Path(td)
        splits_dir = tdp / "splits" / splitmod.SPLITS_VERSION
        splitmod.write_split_set(split_set, splits_dir)
        results = evalmod.run_eval(
            submission_dir=ROOT / "benchmark" / "baselines" / "ua_rule",
            split="heldout", splits_dir=splits_dir, data_dir=tdp / "data",
            seed=seed, fp_per_hour_budget=1.0, out_dir=tdp / "eval",
            sessions=sessions,
        )
        # Accuracy must never appear.
        assert "accuracy" not in str(results).lower(), "accuracy leaked"
    return results["primary"], split_set.manifest


def main() -> None:
    sessions = _universe()

    print("=" * 70)
    print("CUT (a) cross-BACKEND — OpenAI vs Claude, same browser-use framework")
    print("  isolates MODEL footprint · seeds 0-2 · PR-AUC + recall@FP-budget(1/hr)")
    print("=" * 70)
    for held in ("anthropic", "openai"):
        other = "openai" if held == "anthropic" else "anthropic"
        print(f"\n  train WITHOUT {held}  →  eval ON held-out {held} "
              f"(train sees {other} + non-LLM agents):")
        for seed in (0, 1, 2):
            p, _ = _run(sessions, seed=seed, heldout_super_family=held)
            print(f"    seed={seed}  PR-AUC={p['heldout_super_family_pr_auc']:.4f}  "
                  f"recall@budget={p['heldout_super_family_recall_at_budget']:.4f}  "
                  f"FP/hr={p['fp_per_hour']:.3f}  "
                  f"n_pos={p['n_heldout_super_family_positives']}  "
                  f"families={p['heldout_super_family_families']}")

    print("\n" + "=" * 70)
    print("CUT (b) cross-FRAMEWORK — browser-use LLM agents vs Playwright/Selenium")
    print("  isolates FRAMEWORK footprint · per-family heldout · seeds 0-2")
    print("=" * 70)
    print("  (per-family heldout picks N families per seed; rows where the "
          "held-out\n   set is a framework family are the cross-framework number)")
    for seed in (0, 1, 2):
        p, man = _run(sessions, seed=seed, n_heldout_families=2)
        print(f"    seed={seed}  PR-AUC={p['heldout_family_pr_auc']:.4f}  "
              f"recall@budget={p['heldout_family_recall_at_budget']:.4f}  "
              f"FP/hr={p['fp_per_hour']:.3f}  "
              f"held-out families={man['agent_families_heldout']}")

    print("\n[note] Synthetic features → numbers are pipeline-validation only, "
          "not the\n       real model/framework footprint. See the small-N "
          "caveat in the summary.")


if __name__ == "__main__":
    main()
