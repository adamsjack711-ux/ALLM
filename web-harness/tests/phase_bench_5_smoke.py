"""phase-bench-5 verification gate — cross-backend held-out splits.

Three offline parts. No docker. No API spend. No real data.

PART A — super_family() helper
  - `llm_openai_*` and `llm_anthropic_*` map to their backend strings
  - non-LLM families are their own super_family (no behavior change)
  - empty / None family maps to "" cleanly

PART B — build_split_set with heldout_super_family
  - holding out `openai`: every `llm_openai_*` session ends up in
    private_heldout_family.json regardless of model or target
  - no `llm_anthropic_*` session leaks into the heldout split
  - non-LLM agents in public_train/dev/test are preserved
  - assert_family_disjoint() passes; manifest carries
    heldout_super_family + heldout_super_family_families with the right
    constituent list
  - same-seed determinism: two builds produce byte-identical files

PART C — evaluate.py exposes heldout_super_family_* primary fields
  - synthesize a universe with `llm_openai_*` + `llm_anthropic_*` +
    non-LLM agents + benigns
  - build splits with heldout_super_family="openai"
  - run ua_rule baseline through evaluate.run_eval --split heldout
  - assert primary has heldout_super_family + heldout_super_family_pr_auc
    + heldout_super_family_recall_at_budget +
    n_heldout_super_family_positives + heldout_super_family_families
  - assert numerical equality with heldout_family_* fields (super-family
    heldout IS the family heldout in this configuration)
  - "accuracy" never appears in results.json or report.txt
"""

from __future__ import annotations

import filecmp
import json
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


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: super_family() ──────────────────────────────────────────


def part_a_super_family() -> None:
    print("\n[smoke-p5] PART A — super_family() helper")
    cases = [
        ("llm_openai_gpt_4o_mini",       "openai"),
        ("llm_openai_gpt_4_turbo",       "openai"),
        ("llm_anthropic_claude_haiku_4_5", "anthropic"),
        ("llm_anthropic_claude_opus_4_5",  "anthropic"),
        ("playwright_bot",  "playwright_bot"),
        ("sqlmap",          "sqlmap"),
        ("googlebot",       "googlebot"),
        ("",                ""),
        (None,              ""),
        ("llm_gemini_pro",  "llm_gemini_pro"),  # unknown backend → no match
    ]
    for fam, expected in cases:
        got = splitmod.super_family(fam)
        _assert(got == expected,
                f"[A] super_family({fam!r}) = {got!r}, expected {expected!r}")
    print("[smoke-p5] PART A passed")


# ── PART B: build_split_set with heldout_super_family ──────────────


def _synth_meta() -> list[splitmod.SessionMeta]:
    """Mixed universe: 4 LLM cells × 2 backends + 2 non-LLM agents +
    2 benign_bot families. Enough for a non-degenerate split."""
    out: list[splitmod.SessionMeta] = []
    targets = ("dvwa", "juice_shop")
    # 2 OpenAI models × 2 targets × 3 sessions = 12 OpenAI sessions
    for model_slug in ("gpt_4o_mini", "gpt_4_turbo"):
        for app in targets:
            for i in range(3):
                fam = f"llm_openai_{model_slug}"
                out.append(splitmod.SessionMeta(
                    session_id=f"{fam}-{app}-{i}",
                    family=fam, klass="agent", stealth=(i == 0),
                    target_app=app, duration_s=30.0,
                ))
    # 2 Anthropic models × 2 targets × 3 sessions = 12 Anthropic sessions
    for model_slug in ("claude_haiku_4_5", "claude_opus_4_5"):
        for app in targets:
            for i in range(3):
                fam = f"llm_anthropic_{model_slug}"
                out.append(splitmod.SessionMeta(
                    session_id=f"{fam}-{app}-{i}",
                    family=fam, klass="agent", stealth=(i == 0),
                    target_app=app, duration_s=30.0,
                ))
    # 2 non-LLM agent families × 4 sessions each
    for fam in ("playwright_bot", "sqlmap"):
        for app in targets:
            for i in range(2):
                out.append(splitmod.SessionMeta(
                    session_id=f"{fam}-{app}-{i}",
                    family=fam, klass="agent", stealth=False,
                    target_app=app, duration_s=30.0,
                ))
    # 2 benign_bot families × 4 sessions each
    for fam in ("googlebot", "uptime_monitor"):
        for app in targets:
            for i in range(2):
                out.append(splitmod.SessionMeta(
                    session_id=f"{fam}-{app}-{i}",
                    family=fam, klass="benign_bot", stealth=False,
                    target_app=app, duration_s=120.0,
                ))
    return out


def part_b_split_set(td: pathlib.Path) -> None:
    print("\n[smoke-p5] PART B — build_split_set with heldout_super_family")
    metas = _synth_meta()

    # Standard build (no super-family) for baseline comparison
    standard = splitmod.build_split_set(metas, seed=0)
    _assert(standard.manifest.get("heldout_super_family") is None,
            f"[B] standard build set heldout_super_family: "
            f"{standard.manifest.get('heldout_super_family')}")

    # Super-family heldout: openai
    sf_openai = splitmod.build_split_set(
        metas, seed=0, heldout_super_family="openai",
    )
    splitmod.assert_family_disjoint(sf_openai)
    splitmod.assert_no_session_in_two_public_splits(sf_openai)

    public_ids = (set(sf_openai.public_train) | set(sf_openai.public_dev)
                  | set(sf_openai.public_test))
    heldout_ids = set(sf_openai.private_heldout_family)

    by_id = {s.session_id: s for s in metas}
    openai_sids = {s.session_id for s in metas
                   if splitmod.super_family(s.family) == "openai"}
    anthropic_sids = {s.session_id for s in metas
                      if splitmod.super_family(s.family) == "anthropic"}

    # Every OpenAI session lands in heldout
    missing_openai = openai_sids - heldout_ids
    _assert(not missing_openai,
            f"[B] {len(missing_openai)} OpenAI sessions missing from "
            f"heldout: first={sorted(missing_openai)[:3]}")
    # No OpenAI session leaks into public
    leaked = openai_sids & public_ids
    _assert(not leaked,
            f"[B] {len(leaked)} OpenAI sessions leaked into public splits")
    # No Anthropic session ended up in the super-family heldout
    # (Anthropic families CAN be picked by the standard per-family
    # heldout — that's fine and separate. But they shouldn't have been
    # forced in by the super-family rule.)
    sf_only_heldout_families = set(
        sf_openai.manifest["heldout_super_family_families"]
    )
    for sid in anthropic_sids & heldout_ids:
        fam = by_id[sid].family
        _assert(fam not in sf_only_heldout_families,
                f"[B] anthropic family {fam} treated as super-family")

    # Manifest carries the right metadata
    _assert(sf_openai.manifest["heldout_super_family"] == "openai",
            f"[B] manifest.heldout_super_family wrong")
    sf_fams = sf_openai.manifest["heldout_super_family_families"]
    expected_openai_fams = {"llm_openai_gpt_4o_mini", "llm_openai_gpt_4_turbo"}
    _assert(set(sf_fams) == expected_openai_fams,
            f"[B] heldout_super_family_families wrong: got {sf_fams}")

    # Non-LLM agents survive in the public pool (subject to per-family
    # holdout). They should not be ALL removed.
    non_llm_in_public = sum(
        1 for sid in public_ids
        if by_id[sid].family in {"playwright_bot", "sqlmap"}
    )
    _assert(non_llm_in_public >= 1,
            f"[B] no non-LLM agents survived in public splits "
            f"(got {non_llm_in_public})")

    # Determinism: same seed → byte-identical written files
    out_a = td / "splits_a"
    out_b = td / "splits_b"
    sf_b = splitmod.build_split_set(
        metas, seed=0, heldout_super_family="openai",
    )
    splitmod.write_split_set(sf_openai, out_a)
    splitmod.write_split_set(sf_b, out_b)
    for name in ("public_train.json", "public_dev.json", "public_test.json",
                  "private_heldout_family.json",
                  "private_heldout_stealth.json"):
        _assert(filecmp.cmp(out_a / name, out_b / name, shallow=False),
                f"[B] determinism broken for {name}")
    # MANIFEST will differ on `built_at` only; check via JSON-load
    man_a = json.loads((out_a / "MANIFEST.json").read_text())
    man_b = json.loads((out_b / "MANIFEST.json").read_text())
    man_a.pop("built_at", None)
    man_b.pop("built_at", None)
    _assert(man_a == man_b,
            f"[B] manifest differs at same seed (excluding built_at): "
            f"diff in keys {set(man_a) ^ set(man_b)}")

    print("[smoke-p5] PART B passed")


# ── PART C: evaluate.py heldout_super_family_* primary fields ──────


def _synth_sessions_for_eval():
    """Build a 36-session universe for evaluate.run_eval. The phase-14
    family naming convention is preserved so the existing per_llm_*
    rollups still populate."""
    from features import Session  # type: ignore
    sessions = []
    rng = np.random.default_rng(0)

    llm_specs = [
        ("openai",    "gpt_4o_mini",       "dvwa"),
        ("openai",    "gpt_4o_mini",       "juice_shop"),
        ("openai",    "gpt_4_turbo",       "dvwa"),
        ("anthropic", "claude_haiku_4_5",  "dvwa"),
        ("anthropic", "claude_haiku_4_5",  "juice_shop"),
        ("anthropic", "claude_opus_4_5",   "dvwa"),
    ]
    for backend, model_slug, target_app in llm_specs:
        family = f"llm_{backend}_{model_slug}"
        for i in range(3):
            seq = rng.uniform(0, 1, size=(8, 9)).astype("float32")
            seq[:, 6] = 0.3  # curl-bucket → ua_rule scores high
            sessions.append(Session(
                session_id=f"{family}-{target_app}-{i:02d}",
                src_label=family, family=family, klass="agent",
                y=1, duration_s=30.0, ts_start=0.0,
                seq=seq, agg=rng.uniform(0, 1, size=12).astype("float32"),
                hp=np.zeros(4, dtype="float32"),
                n_req=8, target_app=target_app, stealth=False,
            ))

    # Non-LLM agents and benigns
    for fam in ("playwright_bot", "sqlmap"):
        for i in range(3):
            seq = rng.uniform(0, 1, size=(8, 9)).astype("float32")
            seq[:, 6] = 0.3
            sessions.append(Session(
                session_id=f"{fam}-{i:02d}",
                src_label=fam, family=fam, klass="agent",
                y=1, duration_s=30.0, ts_start=0.0,
                seq=seq, agg=rng.uniform(0, 1, size=12).astype("float32"),
                hp=np.zeros(4, dtype="float32"),
                n_req=8, target_app="dvwa", stealth=False,
            ))
    for fam in ("googlebot", "uptime_monitor"):
        for i in range(4):
            seq = rng.uniform(0, 1, size=(8, 9)).astype("float32")
            seq[:, 6] = 1.0
            sessions.append(Session(
                session_id=f"{fam}-{i:02d}",
                src_label=fam, family=fam, klass="benign_bot",
                y=0, duration_s=120.0, ts_start=0.0,
                seq=seq, agg=rng.uniform(0, 1, size=12).astype("float32"),
                hp=np.zeros(4, dtype="float32"),
                n_req=8, target_app="dvwa", stealth=False,
            ))
    return sessions


def part_c_evaluate(td: pathlib.Path) -> None:
    print("\n[smoke-p5] PART C — evaluate.py heldout_super_family_* fields")
    sessions = _synth_sessions_for_eval()
    metas = sessions_to_meta(sessions)
    split_set = splitmod.build_split_set(
        metas, seed=0, heldout_super_family="openai",
    )
    splits_dir = td / "splits" / splitmod.SPLITS_VERSION
    splitmod.write_split_set(split_set, splits_dir)

    submission = ROOT / "benchmark" / "baselines" / "ua_rule"
    out_dir = td / "eval"
    results = evalmod.run_eval(
        submission_dir=submission,
        split="heldout",
        splits_dir=splits_dir,
        data_dir=td / "data",
        seed=0,
        fp_per_hour_budget=1.0,
        out_dir=out_dir,
        sessions=sessions,
    )

    primary = results.get("primary") or {}
    for key in ("heldout_super_family",
                "heldout_super_family_pr_auc",
                "heldout_super_family_recall_at_budget",
                "n_heldout_super_family_positives",
                "heldout_super_family_families"):
        _assert(key in primary,
                f"[C] primary missing {key!r}: keys={sorted(primary)}")
    _assert(primary["heldout_super_family"] == "openai",
            f"[C] heldout_super_family wrong: "
            f"{primary['heldout_super_family']}")
    fams = primary["heldout_super_family_families"]
    _assert(set(fams) == {"llm_openai_gpt_4o_mini", "llm_openai_gpt_4_turbo"},
            f"[C] heldout_super_family_families wrong: {fams}")

    # Super-family metric values mirror the existing heldout_family
    # metrics because in this configuration the held-out positives are
    # exactly the same set.
    _assert(primary["heldout_super_family_pr_auc"] ==
            primary["heldout_family_pr_auc"],
            f"[C] super_family_pr_auc != family_pr_auc: "
            f"{primary['heldout_super_family_pr_auc']} vs "
            f"{primary['heldout_family_pr_auc']}")
    _assert(primary["heldout_super_family_recall_at_budget"] ==
            primary["heldout_family_recall_at_budget"],
            f"[C] super_family_recall != family_recall")
    _assert(primary["n_heldout_super_family_positives"] ==
            primary["n_heldout_family_positives"],
            f"[C] n_heldout_super_family_positives mismatch")

    # No accuracy
    results_text = json.dumps(results).lower()
    _assert("accuracy" not in results_text,
            "[C] 'accuracy' present in results")
    report_text = (out_dir / "report.txt").read_text().lower()
    _assert("accuracy" not in report_text,
            "[C] 'accuracy' present in report.txt")

    on_disk = json.loads((out_dir / "results.json").read_text())
    op = on_disk.get("primary") or {}
    _assert("heldout_super_family" in op,
            "[C] on-disk results.json missing heldout_super_family")

    print(f"[smoke-p5]   PR-AUC={primary['heldout_super_family_pr_auc']:.4f}  "
          f"recall@budget={primary['heldout_super_family_recall_at_budget']:.4f}  "
          f"n_pos={primary['n_heldout_super_family_positives']}")
    print("[smoke-p5] PART C passed")


def main() -> None:
    import time
    t0 = time.monotonic()
    part_a_super_family()
    with tempfile.TemporaryDirectory(prefix="cernis_p5_b_") as td:
        part_b_split_set(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_p5_c_") as td:
        part_c_evaluate(pathlib.Path(td))
    print()
    print(f"PHASE-BENCH-5 SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
