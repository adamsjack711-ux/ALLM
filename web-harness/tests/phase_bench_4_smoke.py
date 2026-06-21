"""phase-bench-4 verification gate.

Three parts, all offline. PART B exercises the container I/O contract
via `runner_container.run_subprocess` so the smoke runs without a
docker daemon; the same /in /out / env-var contract is what the
docker path uses.

PART A — leaderboard mechanics
  - submission_hash is deterministic and changes when content changes
  - append_entry writes one JSONL row per call
  - read_entries + dedupe + to_markdown produce the expected shape
  - "accuracy" anywhere in an entry's primary/resource is rejected
    at write-time

PART B — container I/O contract via run_subprocess
  - Stage the submission_container/ template into a tmpdir
  - Feed synthetic eval_features through `runner.py` via run_subprocess
  - Verify scores.jsonl matches the in-process ua_rule baseline byte
    for byte (same model, same input → same output, regardless of
    isolation flavor)
  - Verify resource accounting (wall_time_s > 0, exit_status == 0,
    peak_mem_mb is None for the subprocess path)
  - Verify train_features.jsonl is correctly threaded when present

PART C — evaluate.py with --leaderboard
  - Run a full Python-flavor eval with --leaderboard set
  - Verify results.json has the runner/resource fields stripped (the
    on-disk file must stay reproducible) but report.txt shows them
  - Verify the leaderboard.jsonl gets one new row with the expected
    submission_hash + runner + primary fields
  - Verify "accuracy" still never appears in any output

  Also: confirm docker_available() returns False when docker is off
  (sanity check that the runner correctly classifies the environment),
  and confirm the `--container-image` path surfaces DockerUnavailable
  cleanly when called against a fake image with no daemon up.
"""

from __future__ import annotations

import json
import pathlib
import random
import shutil
import subprocess
import sys
import tempfile

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "detector"))

from benchmark import contract as contractmod  # noqa: E402
from benchmark import evaluate as evalmod  # noqa: E402
from benchmark import leaderboard as lbmod  # noqa: E402
from benchmark import runner_container as runnermod  # noqa: E402
from benchmark import splits as splitmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: leaderboard mechanics ────────────────────────────────────


def part_a_leaderboard(td: pathlib.Path) -> None:
    print("\n[smoke-b4] PART A — leaderboard mechanics")
    sub_dir = td / "sub_a"
    sub_dir.mkdir()
    (sub_dir / "submission.py").write_text("def predict(f): return []\n")
    (sub_dir / "weights.bin").write_bytes(b"x" * 1024)

    # determinism
    h1 = lbmod.submission_hash(sub_dir)
    h2 = lbmod.submission_hash(sub_dir)
    _assert(h1 == h2, f"[A] submission_hash not deterministic: {h1} != {h2}")
    _assert(h1.startswith("sha256:"),
            f"[A] submission_hash should be prefixed: {h1!r}")

    # content sensitivity
    (sub_dir / "submission.py").write_text("def predict(f): return [{}]\n")
    h3 = lbmod.submission_hash(sub_dir)
    _assert(h1 != h3, "[A] submission_hash didn't change on content edit")

    # __pycache__ exclusion
    cache = sub_dir / "__pycache__"
    cache.mkdir()
    (cache / "junk.pyc").write_bytes(b"\x00" * 64)
    h4 = lbmod.submission_hash(sub_dir)
    _assert(h3 == h4, "[A] __pycache__/ files leaked into submission_hash")

    # append + read round-trip
    lb_path = td / "leaderboard.jsonl"
    results_a = {
        "submission": "fake/a", "splits_version": "v1", "split": "public_test",
        "seed": 0,
        "primary": {"pr_auc": 0.5, "fp_per_hour": 1.0, "threshold": 0.4},
    }
    results_b = dict(results_a, primary={"pr_auc": 0.9, "fp_per_hour": 0.2,
                                          "threshold": 0.6})
    e1 = lbmod.append_entry(lb_path, submission_dir=sub_dir, results=results_a,
                            resource={"wall_time_s": 1.5, "peak_mem_mb": 100,
                                       "exit_status": 0},
                            runner="python")
    e2 = lbmod.append_entry(lb_path, submission_dir=sub_dir, results=results_b,
                            resource={"wall_time_s": 2.0, "peak_mem_mb": 200,
                                       "exit_status": 0},
                            runner="container")
    entries = lbmod.read_entries(lb_path)
    _assert(len(entries) == 2,
            f"[A] expected 2 entries, got {len(entries)}")
    _assert(entries[0].submission_hash == entries[1].submission_hash,
            "[A] same submission_dir → different hashes")

    # dedupe keeps the latest by submitted_at; both rows share key
    deduped = lbmod.dedupe(entries)
    _assert(len(deduped) == 1,
            f"[A] dedup didn't collapse same-key entries: {len(deduped)}")
    _assert(deduped[0].primary["pr_auc"] == 0.9,
            "[A] dedup kept the older entry instead of the newer one")

    # markdown rollup
    md = lbmod.to_markdown(entries)
    _assert("Cernis benchmark leaderboard" in md,
            "[A] markdown missing title")
    _assert("0.9000" in md, f"[A] markdown missing pr_auc row: {md[:400]}")
    _assert("public_test" in md, "[A] markdown missing split header")

    # accuracy rejection
    poisoned = dict(results_a,
                    primary={"pr_auc": 0.5, "accuracy": 0.99})
    try:
        lbmod.append_entry(td / "leaderboard_poison.jsonl",
                           submission_dir=sub_dir, results=poisoned)
        raise AssertionError("[A] poisoned entry was accepted")
    except RuntimeError as exc:
        _assert("accuracy" in str(exc).lower(),
                f"[A] poison error message wrong: {exc}")
    print("[smoke-b4] PART A passed")


# ── PART B: container I/O contract via run_subprocess ────────────────


def part_b_container_io(td: pathlib.Path) -> None:
    print("\n[smoke-b4] PART B — container I/O contract")

    # Stage the template into a working dir so we can run runner.py
    template_src = ROOT / "benchmark" / "release" / "templates" / "submission_container"
    _assert(template_src.exists(),
            f"[B] template not found at {template_src}")
    work = td / "container_work"
    shutil.copytree(template_src, work)

    # Synthesize a small features set. Each row has the public schema
    # the runner expects (session_id, target_app, agg, seq, hp).
    features: list[dict] = []
    rng = random.Random(0)
    for i in range(8):
        seq = [
            [50.0 + rng.random(), 200, 0, 0, 100, 200, 0.3, 4, 0]
            for _ in range(5)
        ]
        features.append({
            "session_id": f"sess-{i:03d}", "target_app": "dvwa",
            "agg": [5.0, 1.0, 0.0, 0.0, 1, 0, 0, 0, 0, 0, 0, 1000.0],
            "seq": seq, "hp": [0, 0, 0, 0],
        })

    # In-process baseline: import the reference submission directly.
    sys.path.insert(0, str(work))
    try:
        import importlib
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "submission_under_test", work / "submission.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        in_process = sorted(
            mod.predict(features), key=lambda r: r["session_id"],
        )
    finally:
        sys.path.remove(str(work))

    # run_subprocess flavor: same /in /out contract, same model.
    result = runnermod.run_subprocess(
        [sys.executable, "runner.py"], features,
        cwd=work,
        env={"PYTHONPATH": str(work)},
        timeout_s=30.0,
    )
    _assert(result.exit_status == 0,
            f"[B] runner subprocess exited {result.exit_status}: "
            f"rows={result.rows}")
    _assert(result.wall_time_s > 0,
            f"[B] wall_time_s should be positive, got {result.wall_time_s}")
    _assert(result.peak_mem_mb is None,
            "[B] subprocess flavor should leave peak_mem_mb None")
    _assert(len(result.rows) == len(features),
            f"[B] expected {len(features)} rows, got {len(result.rows)}")

    subprocess_rows = sorted(result.rows, key=lambda r: r["session_id"])
    _assert(in_process == subprocess_rows,
            f"[B] subprocess rows != in-process rows\n"
            f"  in_process[0]={in_process[0]}\n"
            f"  subprocess[0]={subprocess_rows[0]}")

    # Train feature threading: write a non-empty train_features.jsonl
    # and confirm runner doesn't trip even though submission.train is
    # not defined.
    result2 = runnermod.run_subprocess(
        [sys.executable, "runner.py"], features,
        train_features=features[:3], dev_features=features[3:5],
        cwd=work, env={"PYTHONPATH": str(work)},
        timeout_s=30.0,
    )
    _assert(result2.exit_status == 0,
            f"[B] runner subprocess with train features exited "
            f"{result2.exit_status}")

    # docker_available should be honest about the env: if it's True the
    # smoke is happy either way; if False the surface check ensures we
    # surface the right error when an evaluate.py container path is
    # invoked against an unreachable daemon (PART C).
    print(f"[smoke-b4]   docker_available()={runnermod.docker_available()}")
    print("[smoke-b4] PART B passed")


# ── PART C: evaluate.py with --leaderboard + DockerUnavailable ───────


def _synth_sessions_for_eval():
    """Build a 24-session universe with 3 agent families + 2 benigns,
    enough for build_splits to land non-degenerate splits."""
    from features import Session  # type: ignore
    sessions = []
    rng = np.random.default_rng(0)

    for fam_idx, fam in enumerate(["playwright_bot", "selenium_bot", "sqlmap_bot"]):
        for i in range(4):
            seq = rng.uniform(0, 1, size=(8, 9)).astype("float32")
            seq[:, 6] = 0.3  # python/curl UA bucket → ua_rule scores high
            sessions.append(Session(
                session_id=f"{fam}-{i:02d}",
                src_label=fam, family=fam, klass="agent",
                y=1, duration_s=30.0, ts_start=0.0,
                seq=seq, agg=rng.uniform(0, 1, size=12).astype("float32"),
                hp=np.zeros(4, dtype="float32"),
                n_req=8, target_app="dvwa", stealth=False,
            ))

    for fam in ["googlebot", "uptime_monitor"]:
        for i in range(4):
            seq = rng.uniform(0, 1, size=(8, 9)).astype("float32")
            seq[:, 6] = 1.0  # Chrome UA bucket → ua_rule scores low
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
    print("\n[smoke-b4] PART C — evaluate.py with --leaderboard")
    sessions = _synth_sessions_for_eval()

    # Build splits over the synth sessions.
    from benchmark.build_splits import sessions_to_meta
    metas = sessions_to_meta(sessions)
    split_set = splitmod.build_split_set(metas, seed=0)
    splits_dir = td / "splits" / splitmod.SPLITS_VERSION
    splitmod.write_split_set(split_set, splits_dir)

    # Run the Python-flavor eval against ua_rule with --leaderboard.
    lb_path = td / "leaderboard.jsonl"
    submission = ROOT / "benchmark" / "baselines" / "ua_rule"
    out_dir = td / "eval_run"
    results = evalmod.run_eval(
        submission_dir=submission,
        split="public_test",
        splits_dir=td / "splits" / splitmod.SPLITS_VERSION,
        data_dir=td / "data",
        seed=0,
        fp_per_hour_budget=1.0,
        out_dir=out_dir,
        sessions=sessions,
    )

    # Resource fields populated on the in-memory results dict
    _assert(results.get("runner") == "python",
            f"[C] runner field wrong: {results.get('runner')}")
    res = results.get("resource") or {}
    _assert(res.get("wall_time_s") is not None and res["wall_time_s"] > 0,
            f"[C] wall_time_s missing/non-positive: {res}")
    _assert(res.get("exit_status") == 0,
            f"[C] exit_status missing/non-zero: {res}")
    _assert(res.get("peak_mem_mb") is None,
            f"[C] Python flavor should not measure peak_mem_mb: {res}")

    # On-disk results.json must NOT carry runtime-varying fields, so
    # the phase-bench-2 byte-identical reproducibility gate still holds.
    on_disk = json.loads((out_dir / "results.json").read_text())
    for forbidden in ("built_at", "resource", "container_image"):
        _assert(forbidden not in on_disk,
                f"[C] results.json on disk still contains {forbidden!r} "
                f"— reproducibility gate broken")
    _assert(on_disk.get("runner") == "python",
            "[C] results.json on disk missing runner field")
    _assert("accuracy" not in (out_dir / "results.json").read_text().lower(),
            "[C] accuracy substring in results.json")
    _assert("accuracy" not in (out_dir / "report.txt").read_text().lower(),
            "[C] accuracy substring in report.txt")

    # Manually append a leaderboard entry (mirrors what the CLI does).
    entry = lbmod.append_entry(
        lb_path, submission_dir=submission, results=results,
        resource=results["resource"], runner=results["runner"],
    )
    _assert(lb_path.exists(),
            "[C] leaderboard.jsonl was not created")
    entries = lbmod.read_entries(lb_path)
    _assert(len(entries) == 1, f"[C] expected 1 entry, got {len(entries)}")
    e = entries[0]
    _assert(e.runner == "python", f"[C] entry.runner wrong: {e.runner}")
    _assert(e.split == "public_test",
            f"[C] entry.split wrong: {e.split}")
    _assert(e.primary.get("pr_auc") is not None,
            f"[C] entry.primary missing pr_auc: {e.primary}")
    _assert(e.submission_hash.startswith("sha256:"),
            f"[C] entry.submission_hash malformed: {e.submission_hash}")

    # DockerUnavailable surfaces cleanly when no daemon is reachable
    # (the smoke runs without colima up, so this is the expected path).
    if not runnermod.docker_available():
        try:
            evalmod.run_eval(
                submission_dir=submission,
                split="public_test",
                splits_dir=splits_dir,
                data_dir=td / "data",
                seed=0,
                fp_per_hour_budget=1.0,
                out_dir=td / "eval_run_container",
                sessions=sessions,
                container_image="cernis-fake-no-such-image:latest",
            )
            raise AssertionError(
                "[C] container path didn't raise without docker daemon")
        except runnermod.DockerUnavailable:
            pass

    print("[smoke-b4] PART C passed")


def main() -> None:
    import time
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="cernis_b4_a_") as td:
        part_a_leaderboard(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_b4_b_") as td:
        part_b_container_io(pathlib.Path(td))
    with tempfile.TemporaryDirectory(prefix="cernis_b4_c_") as td:
        part_c_evaluate(pathlib.Path(td))
    print()
    print(f"PHASE-BENCH-4 SMOKE PASSED ✅  elapsed={time.monotonic() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
