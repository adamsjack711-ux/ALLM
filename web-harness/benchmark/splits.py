"""Deterministic, versioned, family-disjoint splits for the Cernis benchmark.

Three properties that make this a benchmark and not a dev split:

  1. **Versioned.** Splits live under `benchmark/splits/v<N>/`. v1 is
     frozen; rule changes get a new version directory. Any baseline
     ever published against the benchmark cites its splits_version so
     comparisons stay apples-to-apples.

  2. **Deterministic.** Given the same input session list and the same
     seed, this module produces byte-identical split files. The smoke
     test asserts this.

  3. **Family-disjoint where it matters.** Two agent families are
     held out entirely from the public splits (`private_heldout_family`).
     Their session_ids never appear in `public_{train,dev,test}`. The
     stealth=true sessions of the *public* agent families that have
     both stealth axes are held out as `private_heldout_stealth` so the
     in-distribution model has never seen them either.

Hidden splits (`private_*.json`) are gitignored and never leave the
host that built them. The public evaluate path refuses to even open
them (see `benchmark/evaluate.py`).
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import pathlib
import random
import re
from typing import Iterable, Optional

SPLITS_VERSION = "v1"
DEFAULT_HELDOUT_FAMILIES = 2
DEFAULT_PUBLIC_RATIOS = (0.6, 0.2, 0.2)  # train / dev / test


# Phase 14 family naming convention: `llm_<backend>_<model_slug>`.
# `super_family(fam)` returns the backend name for those, the family
# itself for everything else. The cross-backend held-out split
# (phase-bench-5) is implemented as `hold out everything whose
# super_family == X`.
_LLM_FAMILY_RE = re.compile(r"^llm_(openai|anthropic)_(.+)$")


def super_family(family: Optional[str]) -> str:
    """Map a family to its super-family (the cross-cutting bucket the
    heldout split uses). For `llm_<backend>_<model_slug>` families the
    super-family is `<backend>`; for everything else it's the family
    name itself (so non-LLM families behave exactly as before).

    Returns "" for empty / None input."""
    if not family:
        return ""
    m = _LLM_FAMILY_RE.match(family)
    return m.group(1) if m else family


@dataclasses.dataclass(frozen=True)
class SessionMeta:
    """Minimum per-session metadata for split decisions.

    Built from `features.Session` by the CLI; carried as its own type
    so `splits.py` doesn't pull in torch / sklearn just to allocate
    session_ids to splits (the smoke can call this with synthetic
    SessionMeta directly).
    """
    session_id: str
    family: str
    klass: str            # agent | benign_bot | human | unknown
    stealth: bool
    target_app: str
    duration_s: float


@dataclasses.dataclass(frozen=True)
class SplitSet:
    """The full output of build_split_set: five session_id lists plus
    a manifest dict ready to write to MANIFEST.json."""
    public_train: list[str]
    public_dev: list[str]
    public_test: list[str]
    private_heldout_family: list[str]
    private_heldout_stealth: list[str]
    manifest: dict


def _checksum(session_ids: Iterable[str]) -> str:
    """sha256 of the sorted session_ids — deterministic regardless of
    the order they were sliced into the split."""
    payload = "\n".join(sorted(session_ids)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _pick_heldout_families(
    agent_families: list[str], seed: int, n: int
) -> list[str]:
    """Deterministically pick N agent families to hold out.

    Seeded shuffle of the sorted family list, take the last N. Using
    `last N` instead of `first N` so that adding a new family at the
    start of the sorted list doesn't perturb the held-out picks for
    existing benchmarks.
    """
    if n <= 0 or not agent_families:
        return []
    rng = random.Random(seed)
    shuffled = sorted(agent_families)
    rng.shuffle(shuffled)
    return sorted(shuffled[-min(n, len(shuffled)):])


def _split_public_pool(
    pool: list[SessionMeta],
    seed: int,
    ratios: tuple[float, float, float],
) -> tuple[list[str], list[str], list[str]]:
    """Deterministic shuffle + 60/20/20 partition of the public pool.

    GroupShuffleSplit on session_id is trivially satisfied because each
    session_id appears in this list exactly once. The shuffle uses a
    seed-derived RNG so two builds with the same seed produce the same
    partition.
    """
    rng = random.Random(seed + 1)  # offset so it differs from family picker
    sorted_pool = sorted(pool, key=lambda s: s.session_id)
    indices = list(range(len(sorted_pool)))
    rng.shuffle(indices)
    n = len(indices)
    n_train = int(round(n * ratios[0]))
    n_dev = int(round(n * ratios[1]))
    train_idx = indices[:n_train]
    dev_idx = indices[n_train : n_train + n_dev]
    test_idx = indices[n_train + n_dev :]
    return (
        sorted(sorted_pool[i].session_id for i in train_idx),
        sorted(sorted_pool[i].session_id for i in dev_idx),
        sorted(sorted_pool[i].session_id for i in test_idx),
    )


def _counts_by_family(
    sessions: list[SessionMeta], ids: set[str]
) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in sessions:
        if s.session_id in ids:
            out[s.family or "?"] = out.get(s.family or "?", 0) + 1
    return out


def _counts_by_class(
    sessions: list[SessionMeta], ids: set[str]
) -> dict[str, int]:
    out: dict[str, int] = {}
    for s in sessions:
        if s.session_id in ids:
            out[s.klass or "?"] = out.get(s.klass or "?", 0) + 1
    return out


def build_split_set(
    sessions: list[SessionMeta],
    *,
    seed: int = 0,
    n_heldout_families: int = DEFAULT_HELDOUT_FAMILIES,
    public_ratios: tuple[float, float, float] = DEFAULT_PUBLIC_RATIOS,
    source_data_sha256: str | None = None,
    built_at: str | None = None,
    heldout_super_family: Optional[str] = None,
) -> SplitSet:
    """Build the full split set.

    Algorithm:
      1. If `heldout_super_family` is set (e.g. "openai"), ALL agent
         sessions whose family maps to that super-family go to
         `private_heldout_family`. The remaining families are then
         eligible for the standard per-family holdout step.
      2. Pick `n_heldout_families` agent families deterministically
         from the eligible (non-super-family-heldout) families. Their
         sessions also go to `private_heldout_family`.
      3. From the remaining (public) agent families, identify those
         that have BOTH stealth=true and stealth=false sessions; their
         stealth=true sessions go to `private_heldout_stealth`. Their
         stealth=false sessions stay in the public pool.
      4. Everything else is the public pool. Deterministic shuffle +
         60/20/20 partition into public_{train, dev, test}.

    `heldout_super_family` is the phase-bench-5 cross-backend
    generalization knob — pass "openai" to train the public splits on
    only Anthropic LLM-agent sessions (plus all non-LLM agents) and
    measure detection on the held-out OpenAI ones.
    """
    by_id = {s.session_id: s for s in sessions}
    if len(by_id) != len(sessions):
        raise ValueError(
            "duplicate session_id in input — splits cannot be deterministic"
        )

    # Step 1: super-family holdout (phase-bench-5)
    if heldout_super_family:
        super_family_heldout_families = sorted({
            s.family for s in sessions
            if s.klass == "agent" and s.family
            and super_family(s.family) == heldout_super_family
        })
        super_family_heldout_family_set = set(super_family_heldout_families)
    else:
        super_family_heldout_families = []
        super_family_heldout_family_set = set()

    # Step 2: standard per-family holdout, over the families NOT already
    # held out by the super-family rule
    eligible_agent_families = sorted({
        s.family for s in sessions
        if s.klass == "agent" and s.family
        and s.family not in super_family_heldout_family_set
    })
    heldout_families = _pick_heldout_families(
        eligible_agent_families, seed, n_heldout_families,
    )
    heldout_family_set = set(heldout_families) | super_family_heldout_family_set

    heldout_family_ids = sorted(
        s.session_id for s in sessions if s.family in heldout_family_set
    )

    public_agent_pool = [
        s for s in sessions
        if s.klass == "agent" and s.family not in heldout_family_set
    ]
    stealth_holdout_families = sorted({
        fam for fam in {s.family for s in public_agent_pool}
        if any(s.family == fam and s.stealth for s in public_agent_pool)
        and any(s.family == fam and not s.stealth for s in public_agent_pool)
    })
    stealth_holdout_set = set(stealth_holdout_families)

    heldout_stealth_ids = sorted(
        s.session_id for s in sessions
        if s.family in stealth_holdout_set and s.stealth
    )

    heldout_ids_all = set(heldout_family_ids) | set(heldout_stealth_ids)
    public_pool = [s for s in sessions if s.session_id not in heldout_ids_all]

    public_train, public_dev, public_test = _split_public_pool(
        public_pool, seed, public_ratios
    )

    # Manifest carries enough metadata to verify a split set without
    # rebuilding it: per-split count + checksum + class/family rollups,
    # plus the family lists, the seed, and the source-data hash.
    manifest: dict = {
        "splits_version": SPLITS_VERSION,
        "seed": seed,
        "n_heldout_families": n_heldout_families,
        "public_ratios": list(public_ratios),
        "source_data_sha256": source_data_sha256,
        "built_at": built_at or dt.datetime.utcnow().isoformat() + "Z",
        "agent_families_train": sorted(
            {s.family for s in sessions
             if s.klass == "agent" and s.family not in heldout_family_set}
        ),
        "agent_families_heldout": sorted(heldout_family_set),
        "stealth_holdout_families": stealth_holdout_families,
        # phase-bench-5: cross-backend held-out super-family. None when
        # the standard family-only holdout is used. Read by evaluate.py
        # to expose heldout_super_family_* metrics.
        "heldout_super_family": heldout_super_family,
        "heldout_super_family_families": super_family_heldout_families,
        "splits": {},
    }
    for name, ids in (
        ("public_train", public_train),
        ("public_dev", public_dev),
        ("public_test", public_test),
        ("private_heldout_family", heldout_family_ids),
        ("private_heldout_stealth", heldout_stealth_ids),
    ):
        id_set = set(ids)
        manifest["splits"][name] = {
            "n": len(ids),
            "sha256": _checksum(ids),
            "by_family": _counts_by_family(sessions, id_set),
            "by_class": _counts_by_class(sessions, id_set),
        }

    return SplitSet(
        public_train=public_train,
        public_dev=public_dev,
        public_test=public_test,
        private_heldout_family=heldout_family_ids,
        private_heldout_stealth=heldout_stealth_ids,
        manifest=manifest,
    )


def write_split_set(
    splits: SplitSet, out_dir: pathlib.Path
) -> dict[str, pathlib.Path]:
    """Serialize the split set to `<out_dir>/{name}.json` + MANIFEST.json.

    Each split file is `{"session_ids": [...], "__checksum": "..."}`
    so a quick re-read can verify the file wasn't tampered with.
    Returns a dict of split_name → path for callers that want to
    cross-check (e.g. the smoke).
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, pathlib.Path] = {}
    for name, ids in (
        ("public_train", splits.public_train),
        ("public_dev", splits.public_dev),
        ("public_test", splits.public_test),
        ("private_heldout_family", splits.private_heldout_family),
        ("private_heldout_stealth", splits.private_heldout_stealth),
    ):
        path = out_dir / f"{name}.json"
        body = {
            "split": name,
            "splits_version": SPLITS_VERSION,
            "n": len(ids),
            "session_ids": ids,
            "__checksum": _checksum(ids),
        }
        path.write_text(json.dumps(body, indent=2, sort_keys=True))
        paths[name] = path

    manifest_path = out_dir / "MANIFEST.json"
    manifest_path.write_text(json.dumps(splits.manifest, indent=2, sort_keys=True))
    paths["MANIFEST"] = manifest_path
    return paths


def read_split(path: pathlib.Path) -> list[str]:
    """Read a split file and verify its `__checksum` matches the body.

    Raises ValueError on checksum mismatch — that's how we catch
    accidental edits to a frozen split.
    """
    body = json.loads(path.read_text())
    ids = list(body.get("session_ids", []))
    expected = body.get("__checksum")
    actual = _checksum(ids)
    if expected != actual:
        raise ValueError(
            f"split {path.name} checksum mismatch (expected {expected!r}, "
            f"got {actual!r}); split file has been edited"
        )
    return ids


# ── invariants the smoke + the evaluator both check ──────────────────


def assert_family_disjoint(splits: SplitSet) -> None:
    """Public split session_ids must not intersect with the heldout-family
    private split — that's the load-bearing benchmark guarantee."""
    public_ids = set(splits.public_train) | set(splits.public_dev) | set(splits.public_test)
    heldout_ids = set(splits.private_heldout_family)
    overlap = public_ids & heldout_ids
    if overlap:
        raise AssertionError(
            f"family disjointness violated: {len(overlap)} session_ids "
            f"appear in both public splits and private_heldout_family"
        )


def assert_no_session_in_two_public_splits(splits: SplitSet) -> None:
    seen: set[str] = set()
    for split in (splits.public_train, splits.public_dev, splits.public_test):
        dup = seen & set(split)
        if dup:
            raise AssertionError(
                f"public split overlap: {len(dup)} session_ids appear in "
                f"more than one of public_{{train,dev,test}}"
            )
        seen |= set(split)
