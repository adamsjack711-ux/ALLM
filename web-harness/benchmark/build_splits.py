"""Build the frozen benchmark splits from a populated `data/` directory.

Usage:
    python3 -m benchmark.build_splits \\
        --data web-harness/data \\
        --out  web-harness/benchmark/splits/v1 \\
        --seed 0

Reads `data/{requests,sessions,beacons,honeypots}.jsonl` via the existing
`detector.features.build_sessions`, projects each Session down to the
minimum needed for split decisions, then delegates to `splits.py`. Writes
five `<name>.json` files plus a `MANIFEST.json` to `--out`.

`private_heldout_*.json` are gitignored. Public eval refuses to open
them. See `benchmark/splits.py` for the rules.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detector"))
sys.path.insert(0, str(ROOT))

from features import build_sessions  # type: ignore  # noqa: E402
from benchmark import splits as splitmod  # noqa: E402


def _source_data_sha256(data_dir: pathlib.Path) -> str:
    """Hash the four JSONL inputs so the manifest pins exactly which
    data the splits were built from. Order-stable, file-by-file."""
    h = hashlib.sha256()
    for name in ("requests.jsonl", "sessions.jsonl",
                  "beacons.jsonl", "honeypots.jsonl"):
        path = data_dir / name
        h.update(name.encode())
        h.update(b"\0")
        if path.exists():
            h.update(path.read_bytes())
        h.update(b"\0")
    return h.hexdigest()


def sessions_to_meta(sess_list) -> list[splitmod.SessionMeta]:
    """Project `features.Session` down to the split-relevant fields."""
    return [
        splitmod.SessionMeta(
            session_id=s.session_id,
            family=s.family,
            klass=s.klass,
            stealth=bool(s.stealth),
            target_app=s.target_app,
            duration_s=float(s.duration_s),
        )
        for s in sess_list
    ]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=pathlib.Path, default=ROOT / "data")
    ap.add_argument(
        "--out", type=pathlib.Path,
        default=ROOT / "benchmark" / "splits" / splitmod.SPLITS_VERSION,
    )
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument(
        "--n-heldout-families", type=int,
        default=splitmod.DEFAULT_HELDOUT_FAMILIES,
    )
    ap.add_argument(
        "--heldout-super-family", default=None,
        help="phase-bench-5: hold out ALL agent sessions belonging to "
             "this super-family. For LLM-agent families "
             "(`llm_<backend>_<model_slug>`) the super-family is the "
             "backend (e.g. `openai` or `anthropic`); for everything "
             "else it's the family name itself. Pass `openai` to "
             "measure cross-backend generalization by training public "
             "splits on Anthropic + non-LLM agents only.",
    )
    args = ap.parse_args()

    if not args.data.exists():
        print(f"[build_splits] data dir {args.data} does not exist", file=sys.stderr)
        return 2

    sessions = build_sessions(args.data)
    if not sessions:
        print(f"[build_splits] no sessions found in {args.data}", file=sys.stderr)
        return 3

    metas = sessions_to_meta(sessions)
    source_hash = _source_data_sha256(args.data)
    split_set = splitmod.build_split_set(
        metas, seed=args.seed,
        n_heldout_families=args.n_heldout_families,
        source_data_sha256=source_hash,
        heldout_super_family=args.heldout_super_family,
    )

    splitmod.assert_family_disjoint(split_set)
    splitmod.assert_no_session_in_two_public_splits(split_set)

    paths = splitmod.write_split_set(split_set, args.out)
    print(f"[build_splits] wrote splits to {args.out}")
    for name, info in split_set.manifest["splits"].items():
        print(
            f"  {name:>26s}  n={info['n']:>5d}  "
            f"sha256={info['sha256'][:12]}…  "
            f"classes={info['by_class']}"
        )
    print(f"  heldout agent families: {split_set.manifest['agent_families_heldout']}")
    print(f"  stealth holdout families: {split_set.manifest['stealth_holdout_families']}")
    if split_set.manifest.get("heldout_super_family"):
        sf = split_set.manifest["heldout_super_family"]
        sf_fams = split_set.manifest["heldout_super_family_families"]
        print(
            f"  heldout super-family: {sf} "
            f"({len(sf_fams)} constituent families: {sf_fams})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
