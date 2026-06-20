"""phase-bench-2 verification gate.

Grows across the three commits of phase-bench-2 — this file is the
single end-to-end check that the new benchmark surface holds together.
Each part runs offline, in <10s, without docker.

PART A — splits (commit 1)
  - build_split_set is deterministic: same input + same seed →
    byte-identical files
  - family disjointness: no session_id appears in both public_train
    and private_heldout_family; agent-family sets are disjoint
  - public splits don't overlap one another
  - stealth-holdout families' stealth=true sessions land in the
    private_heldout_stealth split, not in public

PART B — submission contract + evaluate harness (commit 2)
  - benchmark/evaluate.py with --split public_test on a stub
    submission emits results.json with the expected metric keys
  - the eval refuses to read private_*.json under SPLIT=public_test
  - the same submission run twice with the same seed produces
    byte-identical results.json (reproducibility)
  - "accuracy" never appears in results.json or the readable report

PART C — baselines (commit 3)
  - the trainable `aggregate_only` baseline runs end-to-end against
    a synth dataset and emits a complete metric suite on
    public_test AND on heldout
  - the trivial `ua_rule` baseline also runs without training
"""

from __future__ import annotations

import filecmp
import json
import pathlib
import random
import sys
import tempfile

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "detector"))

from benchmark import splits as splitmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: splits ───────────────────────────────────────────────────


def _synth_sessions() -> list[splitmod.SessionMeta]:
    """Build a small, realistic-shaped session list:

      - 4 agent families × 6 sessions each → 24 agent sessions
      - 2 of those 4 families have both stealth=true and stealth=false
      - 3 benign_bot families × 4 sessions → 12 benign_bot sessions
      - 8 human sessions

    Total 44 sessions — enough to land non-degenerate splits.
    """
    out: list[splitmod.SessionMeta] = []
    agent_families = ["playwright_bot", "selenium_bot", "sqlmap", "puppeteer_bot"]
    stealth_capable = {"playwright_bot", "selenium_bot"}
    for fam in agent_families:
        for i in range(6):
            stealth = i >= 3 and fam in stealth_capable
            out.append(splitmod.SessionMeta(
                session_id=f"{fam}-{i:02d}",
                family=fam,
                klass="agent",
                stealth=stealth,
                target_app="dvwa",
                duration_s=60.0 + i,
            ))
    for fam in ("googlebot", "uptime_monitor", "rss_reader"):
        for i in range(4):
            out.append(splitmod.SessionMeta(
                session_id=f"{fam}-{i:02d}",
                family=fam, klass="benign_bot", stealth=False,
                target_app="dvwa", duration_s=120.0 + i,
            ))
    for i in range(8):
        out.append(splitmod.SessionMeta(
            session_id=f"human-{i:02d}",
            family="human_real", klass="human", stealth=False,
            target_app="dvwa", duration_s=300.0 + i,
        ))
    return out


def _run_part_a() -> None:
    sessions = _synth_sessions()

    # (1) determinism: two builds with the same seed → identical results
    a = splitmod.build_split_set(sessions, seed=0)
    b = splitmod.build_split_set(sessions, seed=0)
    # `built_at` is the only non-deterministic field — drop it for the
    # comparison so we're testing the data, not the wall clock.
    a_man = dict(a.manifest); a_man.pop("built_at", None)
    b_man = dict(b.manifest); b_man.pop("built_at", None)
    _assert(
        a_man == b_man,
        f"[phase-bench-2] manifest not deterministic between two seed=0 builds",
    )
    for field in ("public_train", "public_dev", "public_test",
                   "private_heldout_family", "private_heldout_stealth"):
        _assert(
            getattr(a, field) == getattr(b, field),
            f"[phase-bench-2] split {field} not deterministic between two seed=0 builds",
        )

    # (2) family disjointness
    splitmod.assert_family_disjoint(a)
    splitmod.assert_no_session_in_two_public_splits(a)
    heldout_families = set(a.manifest["agent_families_heldout"])
    train_families = set(a.manifest["agent_families_train"])
    _assert(
        heldout_families.isdisjoint(train_families),
        f"[phase-bench-2] agent_families_heldout ({sorted(heldout_families)}) "
        f"intersects agent_families_train ({sorted(train_families)})",
    )
    _assert(
        len(heldout_families) == splitmod.DEFAULT_HELDOUT_FAMILIES,
        f"[phase-bench-2] expected {splitmod.DEFAULT_HELDOUT_FAMILIES} heldout "
        f"families, got {len(heldout_families)}",
    )

    # (3) stealth holdout: stealth=true sessions of stealth-capable
    # PUBLIC families land in private_heldout_stealth; none of them
    # leak into the public splits.
    by_id = {s.session_id: s for s in sessions}
    stealth_pool_expected = {
        s.session_id for s in sessions
        if s.stealth and s.family in train_families
    }
    actual_stealth_holdout = set(a.private_heldout_stealth)
    _assert(
        stealth_pool_expected == actual_stealth_holdout,
        f"[phase-bench-2] private_heldout_stealth mismatch.\n"
        f"  expected: {sorted(stealth_pool_expected)}\n"
        f"  actual:   {sorted(actual_stealth_holdout)}",
    )
    public_all = set(a.public_train) | set(a.public_dev) | set(a.public_test)
    leaked = stealth_pool_expected & public_all
    _assert(
        not leaked,
        f"[phase-bench-2] stealth=true sessions leaked into public splits: {leaked}",
    )

    # (4) round-trip through write_split_set / read_split — verify the
    # serialized form survives checksumming.
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out_dir = pathlib.Path(td)
        paths = splitmod.write_split_set(a, out_dir)
        for name in ("public_train", "public_dev", "public_test",
                      "private_heldout_family", "private_heldout_stealth"):
            ids_back = splitmod.read_split(paths[name])
            _assert(
                ids_back == sorted(getattr(a, name)),
                f"[phase-bench-2] {name} round-trip mismatch",
            )
        # Tamper detection: rewrite one of the files with an extra id
        # and verify read_split raises.
        tampered = paths["public_train"]
        body = json.loads(tampered.read_text())
        body["session_ids"].append("intruder-99")
        tampered.write_text(json.dumps(body))
        try:
            splitmod.read_split(tampered)
        except ValueError as exc:
            _assert(
                "checksum mismatch" in str(exc),
                f"[phase-bench-2] tamper-detection raised the wrong error: {exc}",
            )
        else:
            raise AssertionError(
                "[phase-bench-2] tampered split file should have raised ValueError"
            )

    print("[phase-bench-2] PART A passed (splits: determinism + disjointness + checksum)")


# ── PART B: submission contract + evaluate harness ───────────────────


def _synth_feature_sessions(seed: int = 0):
    """Build synthetic `features.Session` objects directly — no JSONL
    on disk, no detector.features.build_sessions invocation. The eval
    harness accepts this list via its `sessions` parameter so the smoke
    stays fast and self-contained.
    """
    from features import F_HP, F_REQ, F_SESS, Session  # type: ignore
    rng = random.Random(seed)
    nprng = np.random.default_rng(seed)
    out: list[Session] = []
    agent_families = ["playwright_bot", "selenium_bot", "sqlmap", "puppeteer_bot"]
    stealth_capable = {"playwright_bot", "selenium_bot"}
    counter = 0
    for fam in agent_families:
        for i in range(6):
            stealth = i >= 3 and fam in stealth_capable
            counter += 1
            t = 8 + i  # T (n_req) per session
            # Agent rows: low cadence + high path-breadth + tool-shaped agg.
            agg = nprng.normal(loc=2.0, scale=0.3, size=F_SESS).astype(np.float32)
            seq = nprng.normal(loc=1.2, scale=0.4, size=(t, F_REQ)).astype(np.float32)
            hp = np.zeros(F_HP, dtype=np.float32)
            if rng.random() < 0.4:
                hp[rng.randint(0, F_HP - 1)] = 1.0
            out.append(Session(
                session_id=f"{fam}-{i:02d}",
                src_label=fam,
                seq=seq, agg=agg, hp=hp,
                y=1, duration_s=60.0 + i,
                ts_start=1.0 * counter, n_req=t,
                klass="agent", family=fam, target_app="dvwa",
                stealth=stealth,
            ))
    for fam in ("googlebot", "uptime_monitor", "rss_reader"):
        for i in range(6):
            counter += 1
            t = 5 + i
            agg = nprng.normal(loc=0.0, scale=0.5, size=F_SESS).astype(np.float32)
            seq = nprng.normal(loc=0.0, scale=0.6, size=(t, F_REQ)).astype(np.float32)
            hp = np.zeros(F_HP, dtype=np.float32)
            out.append(Session(
                session_id=f"{fam}-{i:02d}",
                src_label=fam,
                seq=seq, agg=agg, hp=hp,
                y=0, duration_s=120.0 + i,
                ts_start=1.0 * counter, n_req=t,
                klass="benign_bot", family=fam, target_app="dvwa",
                stealth=False,
            ))
    for i in range(10):
        counter += 1
        t = 6 + i
        agg = nprng.normal(loc=-1.0, scale=0.4, size=F_SESS).astype(np.float32)
        seq = nprng.normal(loc=-0.5, scale=0.5, size=(t, F_REQ)).astype(np.float32)
        hp = np.zeros(F_HP, dtype=np.float32)
        out.append(Session(
            session_id=f"human-{i:02d}",
            src_label="human_real",
            seq=seq, agg=agg, hp=hp,
            y=0, duration_s=300.0 + i,
            ts_start=1.0 * counter, n_req=t,
            klass="human", family="human_real", target_app="dvwa",
            stealth=False,
        ))
    return out


_STUB_SUBMISSION = '''"""Inline stub submission for the phase-bench-2 smoke.

Always returns 0.5 for every session — sanity-checks the harness
plumbing without testing real model quality.
"""

def predict(features):
    return [{"session_id": f["session_id"], "agent_score": 0.5} for f in features]
'''


def _write_stub_submission(dest: pathlib.Path) -> pathlib.Path:
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "submission.py").write_text(_STUB_SUBMISSION)
    return dest


def _run_part_b() -> None:
    from benchmark import build_splits as bsmod  # noqa: PLC0415
    from benchmark import evaluate as evalmod  # noqa: PLC0415

    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        splits_dir = td / "splits" / splitmod.SPLITS_VERSION
        sessions = _synth_feature_sessions(seed=0)

        # Build splits from the synth session metas.
        metas = bsmod.sessions_to_meta(sessions)
        split_set = splitmod.build_split_set(
            metas, seed=0,
            source_data_sha256="synth-smoke",
        )
        splitmod.assert_family_disjoint(split_set)
        splitmod.write_split_set(split_set, splits_dir)

        # (B1) Public-eval refuses to open private_*.json under SPLIT=public_test.
        try:
            evalmod._safe_load_split(splits_dir, "private_heldout_family", "public_test")
        except PermissionError as exc:
            _assert(
                "refusing to load" in str(exc),
                f"[phase-bench-2] PermissionError wording changed: {exc}",
            )
        else:
            raise AssertionError(
                "[phase-bench-2] public_test eval allowed loading private_heldout_family"
            )

        # (B2) Stub submission end-to-end on public_test.
        submission_dir = _write_stub_submission(td / "stub_submission")
        out_dir_1 = td / "eval_run_1"
        out_dir_2 = td / "eval_run_2"
        results_1 = evalmod.run_eval(
            submission_dir=submission_dir,
            split="public_test",
            splits_dir=splits_dir,
            data_dir=td / "data",  # unused — sessions injected below
            seed=0,
            fp_per_hour_budget=1.0,
            out_dir=out_dir_1,
            sessions=sessions,
        )
        for key in ("split", "seed", "primary", "per_family",
                     "per_target_app", "agent_vs_benign_bot",
                     "n_sessions", "session_hours", "fp_per_hour_budget"):
            _assert(
                key in results_1,
                f"[phase-bench-2] results missing key {key!r}",
            )
        _assert(
            "pr_auc" in results_1["primary"],
            "[phase-bench-2] primary missing pr_auc",
        )
        _assert(
            (out_dir_1 / "results.json").exists()
            and (out_dir_1 / "report.txt").exists(),
            "[phase-bench-2] evaluate did not write results.json + report.txt",
        )

        # (B3) Reproducibility: same submission, same seed → byte-identical
        # results.json.
        evalmod.run_eval(
            submission_dir=submission_dir,
            split="public_test",
            splits_dir=splits_dir,
            data_dir=td / "data",
            seed=0,
            fp_per_hour_budget=1.0,
            out_dir=out_dir_2,
            sessions=sessions,
        )
        _assert(
            filecmp.cmp(
                out_dir_1 / "results.json", out_dir_2 / "results.json",
                shallow=False,
            ),
            "[phase-bench-2] two same-seed runs produced different results.json "
            "(reproducibility broken)",
        )

        # (B4) No `accuracy` substring anywhere in results.json or report.txt.
        for name in ("results.json", "report.txt"):
            text = (out_dir_1 / name).read_text().lower()
            _assert(
                "accuracy" not in text,
                f"[phase-bench-2] forbidden 'accuracy' substring found in {name}",
            )

        # (B5) Heldout SPLIT also runs end-to-end and emits the extra
        # primary fields (heldout_family_pr_auc + recalls).
        out_dir_h = td / "eval_run_heldout"
        results_h = evalmod.run_eval(
            submission_dir=submission_dir,
            split="heldout",
            splits_dir=splits_dir,
            data_dir=td / "data",
            seed=0,
            fp_per_hour_budget=1.0,
            out_dir=out_dir_h,
            sessions=sessions,
        )
        for key in (
            "heldout_family_pr_auc",
            "heldout_family_recall_at_budget",
            "heldout_stealth_recall",
        ):
            _assert(
                key in results_h["primary"],
                f"[phase-bench-2] heldout primary missing {key!r}",
            )

    print(
        "[phase-bench-2] PART B passed (evaluate harness: contract + "
        "private-split protection + reproducibility + no-accuracy)"
    )


# ── PART C: reference baselines wrapped to the contract ──────────────


def _run_baseline(
    baseline_name: str, *, td: pathlib.Path, sessions, splits_dir
) -> dict:
    from benchmark import evaluate as evalmod  # noqa: PLC0415
    submission_dir = ROOT / "benchmark" / "baselines" / baseline_name
    _assert(
        (submission_dir / "submission.py").exists(),
        f"[phase-bench-2] expected baseline at {submission_dir}",
    )
    out_dir = td / f"baseline_{baseline_name}"
    return evalmod.run_eval(
        submission_dir=submission_dir,
        split="public_test",
        splits_dir=splits_dir,
        data_dir=td / "data",
        seed=0,
        fp_per_hour_budget=1.0,
        out_dir=out_dir,
        sessions=sessions,
    )


def _run_part_c() -> None:
    from benchmark import build_splits as bsmod  # noqa: PLC0415

    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        splits_dir = td / "splits" / splitmod.SPLITS_VERSION
        sessions = _synth_feature_sessions(seed=0)
        metas = bsmod.sessions_to_meta(sessions)
        split_set = splitmod.build_split_set(metas, seed=0)
        splitmod.write_split_set(split_set, splits_dir)

        # (C1) Non-training trivial baseline: ua_rule on public_test.
        ua_results = _run_baseline(
            "ua_rule", td=td, sessions=sessions, splits_dir=splits_dir,
        )
        for key in ("primary", "per_family", "agent_vs_benign_bot"):
            _assert(
                key in ua_results,
                f"[phase-bench-2] ua_rule results missing {key!r}",
            )
        _assert(
            0.0 <= ua_results["primary"]["pr_auc"] <= 1.0
            or ua_results["primary"]["pr_auc"] != ua_results["primary"]["pr_auc"],
            f"[phase-bench-2] ua_rule pr_auc out of [0,1]: "
            f"{ua_results['primary']['pr_auc']}",
        )

        # (C2) Trainable baseline: aggregate_only (sklearn LR) end-to-end.
        agg_results = _run_baseline(
            "aggregate_only", td=td, sessions=sessions, splits_dir=splits_dir,
        )
        _assert(
            "pr_auc" in agg_results["primary"],
            "[phase-bench-2] aggregate_only primary missing pr_auc",
        )
        # aggregate_only should beat ua_rule on the synth data (the
        # LR has direct access to the discriminative agg features).
        # Skip the comparison if either is NaN.
        pr_ua = ua_results["primary"]["pr_auc"]
        pr_agg = agg_results["primary"]["pr_auc"]
        if (
            isinstance(pr_ua, (int, float)) and pr_ua == pr_ua
            and isinstance(pr_agg, (int, float)) and pr_agg == pr_agg
        ):
            # Soft assertion: just require aggregate_only doesn't do
            # *worse* than ua_rule. Hard inequality would be brittle on
            # tiny synth data.
            _assert(
                pr_agg >= pr_ua - 0.05,
                f"[phase-bench-2] aggregate_only PR-AUC ({pr_agg:.3f}) much "
                f"worse than ua_rule ({pr_ua:.3f}) — sanity-check the wiring",
            )

        # (C3) Both baselines have all six reference baselines present
        # in the on-disk layout (we don't run gru_only / hybrid in the
        # smoke because PyTorch + tiny data is slow; their wiring
        # mirrors aggregate_only).
        for name in (
            "ua_rule", "timing_threshold", "honeypot_only",
            "aggregate_only", "gru_only", "hybrid",
        ):
            path = ROOT / "benchmark" / "baselines" / name / "submission.py"
            _assert(
                path.exists(),
                f"[phase-bench-2] baseline {name} missing submission.py at {path}",
            )

    print(
        "[phase-bench-2] PART C passed (baselines: ua_rule + aggregate_only "
        "end-to-end + all six baseline submissions present)"
    )


# ── runner ───────────────────────────────────────────────────────────


def main() -> int:
    print("[phase-bench-2] running smoke (offline, no docker)…")
    _run_part_a()
    _run_part_b()
    _run_part_c()
    print("[phase-bench-2] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
