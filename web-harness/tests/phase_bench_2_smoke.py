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

import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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


# ── runner ───────────────────────────────────────────────────────────


def main() -> int:
    print("[phase-bench-2] running smoke (offline, no docker)…")
    _run_part_a()
    # PART B (evaluate) and PART C (baselines) land in commits 2 + 3.
    print("[phase-bench-2] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
