"""Assemble the Cernis benchmark public release.

Usage:
    python3 -m benchmark.release.build_release \\
        --data web-harness/data \\
        --out  web-harness/dist/cernis-benchmark-v0.1 \\
        --version v0.1 \\
        --seed 0

Pipeline (in order — the scrub gate runs in the middle, before tarring):

  1. Load sessions via `detector.features.build_sessions(--data)`.
  2. Consent filter via `scrub.filter_publishable_session_ids` —
     drops `human_real` sessions whose `consent_text_version` is not
     in CONSENT_COVERAGE with `publish=True`. Synthetic families pass
     through.
  3. Build splits from the publishable session metas via
     `benchmark.splits.build_split_set` (deterministic, seeded).
  4. Project sessions to the public feature schema:
       data/features.jsonl   — public features (no labels)
       data/truth.jsonl      — held-back truth for the eval harness
       data/excluded.json    — consent-filter audit trail
  5. Copy code: benchmark/{contract,evaluate,splits,SUBMISSION.md} +
     benchmark/baselines/*/submission.py. Splits ship public_*.json +
     MANIFEST.json only — `private_*.json` is excluded by construction.
  6. Copy docs from `benchmark/release/templates/` with simple
     `{{placeholder}}` substitution; placeholders get hard-checked
     downstream (commit 3 ships the real templates).
  7. Run `scrub.scan_directory(out_dir)` — any hit aborts the build
     and removes the partial output.
  8. Compute per-file sha256, build `manifest.json` with version +
     splits_version + source_data_sha256 + counts.
  9. Tar to `<out>.tar.gz` + write `<out>.tar.gz.sha256`.

Output:
    dist/cernis-benchmark-v0.1/         (browsable release tree)
    dist/cernis-benchmark-v0.1.tar.gz   (shareable artifact)
    dist/cernis-benchmark-v0.1.tar.gz.sha256
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import shutil
import sys
import tarfile
from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent  # web-harness/
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "detector"))

from features import build_sessions  # type: ignore  # noqa: E402

from benchmark import contract as contractmod  # noqa: E402
from benchmark import splits as splitmod  # noqa: E402
from benchmark.build_splits import sessions_to_meta, _source_data_sha256  # noqa: E402
from benchmark.release import scrub as scrubmod  # noqa: E402


# Files copied verbatim into the release's benchmark/ directory.
_CODE_FILES = (
    "__init__.py",
    "contract.py",
    "evaluate.py",
    "splits.py",
    "SUBMISSION.md",
    # phase-bench-6: phase-bench-4's container-submission runner +
    # append-only leaderboard. Shipping them in the release means
    # external submitters can use --container-image and
    # `make leaderboard` without re-deriving the contract.
    "runner_container.py",
    "leaderboard.py",
)

# Phase-bench-6: the container submission template tree. Lives at
# `benchmark/release/templates/submission_container/` in-repo; the
# release puts it at `<release>/submission_container/` so submitters
# discover it next to README.md.
_SUBMISSION_CONTAINER_FILES = (
    "Dockerfile", "README.md", "requirements.txt",
    "runner.py", "submission.py",
)

# Document templates copied (with substitution) into the release root.
_DOC_FILES = ("README.md", "TASK.md", "DATASHEET.md", "LICENSE", "LICENSE-DATA")

# What the release's own Makefile knows. Trimmed from web-harness/Makefile:
# the consumer's primary entry points (`eval`, `eval-container`,
# `leaderboard`).
_RELEASE_MAKEFILE = """\
# Cernis benchmark — release {VERSION}
#
# This Makefile is what an outsider runs after unpacking the release.
# All paths are relative to the unpacked release root.

PYTHON ?= python3
SEED ?= 0
FP_BUDGET ?= 1.0
SPLIT ?= public_test
LEADERBOARD ?= data/reports/leaderboard.jsonl

.PHONY: help eval eval-container leaderboard

help:
\t@echo "Cernis benchmark — release {VERSION}"
\t@echo ""
\t@echo "  make eval SUBMISSION=<path>                   # eval on public_test"
\t@echo "  make eval SUBMISSION=<path> SEED=N            # different seed"
\t@echo "  make eval-container SUBMISSION=<path> SUBMISSION_IMAGE=<tag>"
\t@echo "                                                # eval via docker --network none"
\t@echo "  make leaderboard                              # regenerate leaderboard.md"
\t@echo ""
\t@echo "Examples:"
\t@echo "  make eval SUBMISSION=benchmark/baselines/ua_rule"
\t@echo "  make eval SUBMISSION=benchmark/baselines/aggregate_only"
\t@echo "  make eval-container SUBMISSION=benchmark/baselines/ua_rule \\\\"
\t@echo "                      SUBMISSION_IMAGE=my-cernis-submission"
\t@echo ""
\t@echo "See ./submission_container/README.md for the container flavor."

eval:
\t@if [ -z "$(SUBMISSION)" ]; then \\
\t\techo "usage: make eval SUBMISSION=<path> [LEADERBOARD=<path>]"; exit 2; \\
\tfi
\t$(PYTHON) -m benchmark.evaluate \\
\t\t--submission $(SUBMISSION) \\
\t\t--split $(SPLIT) \\
\t\t--seed $(SEED) \\
\t\t--splits-dir splits/v1 \\
\t\t--features-jsonl data/features.jsonl \\
\t\t--truth-jsonl data/truth.jsonl \\
\t\t--fp-per-hour-budget $(FP_BUDGET) \\
\t\t$(if $(LEADERBOARD),--leaderboard $(LEADERBOARD),)

eval-container:
\t@if [ -z "$(SUBMISSION)" ] || [ -z "$(SUBMISSION_IMAGE)" ]; then \\
\t\techo "usage: make eval-container SUBMISSION=<path> SUBMISSION_IMAGE=<docker tag>"; \\
\t\texit 2; \\
\tfi
\t$(PYTHON) -m benchmark.evaluate \\
\t\t--submission $(SUBMISSION) \\
\t\t--container-image $(SUBMISSION_IMAGE) \\
\t\t--split $(SPLIT) \\
\t\t--seed $(SEED) \\
\t\t--splits-dir splits/v1 \\
\t\t--features-jsonl data/features.jsonl \\
\t\t--truth-jsonl data/truth.jsonl \\
\t\t--fp-per-hour-budget $(FP_BUDGET) \\
\t\t$(if $(LEADERBOARD),--leaderboard $(LEADERBOARD),)

leaderboard:
\t$(PYTHON) -m benchmark.leaderboard --leaderboard $(LEADERBOARD)
"""

# Default placeholder for missing template files (commits 1+2 don't
# yet ship the real DATASHEET / TASK / README — they land in commit 3).
# Each placeholder names what should replace it so a stray placeholder
# trips the smoke's render check.
_PLACEHOLDER = """\
{{TEMPLATE_NAME}} — placeholder

This file should be replaced by `benchmark/release/templates/{name}`
in commit 3 of phase-bench-3. If you are reading this in a published
release, something went wrong in the release build pipeline.
"""


def _file_sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _render_template(
    template_path: Optional[pathlib.Path],
    placeholder_name: str,
    substitutions: dict[str, str],
) -> str:
    """Read a template (or a placeholder) and run a `{{key}}` -> value
    substitution over it. Used for the doc files."""
    if template_path is not None and template_path.exists():
        text = template_path.read_text()
    else:
        text = _PLACEHOLDER.format(name=placeholder_name)
    for k, v in substitutions.items():
        text = text.replace("{{" + k + "}}", v)
    return text


def _copy_code_files(src_root: pathlib.Path, dst_root: pathlib.Path) -> list[pathlib.Path]:
    """Copy the benchmark code subset that ships with a release."""
    copied: list[pathlib.Path] = []
    for rel in _CODE_FILES:
        src = src_root / rel
        if not src.exists():
            continue
        dst = dst_root / "benchmark" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(src.read_bytes())
        copied.append(dst)
    # Baselines: every submission.py under benchmark/baselines/<name>/.
    baselines_root = src_root / "baselines"
    if baselines_root.exists():
        for baseline in sorted(baselines_root.iterdir()):
            if not baseline.is_dir():
                continue
            sub = baseline / "submission.py"
            if sub.exists():
                dst = dst_root / "benchmark" / "baselines" / baseline.name / "submission.py"
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(sub.read_bytes())
                copied.append(dst)
    return copied


def _copy_submission_container(
    templates_dir: pathlib.Path, dst_root: pathlib.Path,
) -> list[pathlib.Path]:
    """Phase-bench-6: copy the container submission template tree from
    `templates_dir/submission_container/` to `<dst_root>/submission_container/`.

    Lives at the release root (alongside README.md) so submitters
    discover it without having to traverse `benchmark/release/templates/`.
    Returns the list of written paths so the manifest covers them.
    """
    src = templates_dir / "submission_container"
    copied: list[pathlib.Path] = []
    if not src.exists():
        return copied
    dst_dir = dst_root / "submission_container"
    dst_dir.mkdir(parents=True, exist_ok=True)
    for name in _SUBMISSION_CONTAINER_FILES:
        sp = src / name
        if not sp.exists():
            continue
        dp = dst_dir / name
        dp.write_bytes(sp.read_bytes())
        copied.append(dp)
    return copied


def _counts(sessions: list, manifest_splits: dict) -> dict:
    by_class: dict[str, int] = {}
    by_family: dict[str, int] = {}
    by_target: dict[str, int] = {}
    by_stealth: dict[str, int] = {"stealth=true": 0, "stealth=false": 0}
    for s in sessions:
        by_class[s.klass or "?"] = by_class.get(s.klass or "?", 0) + 1
        by_family[s.family or "?"] = by_family.get(s.family or "?", 0) + 1
        by_target[s.target_app or "?"] = by_target.get(s.target_app or "?", 0) + 1
        key = "stealth=true" if s.stealth else "stealth=false"
        by_stealth[key] += 1
    return {
        "total_sessions_published": len(sessions),
        "by_class": by_class,
        "by_family": by_family,
        "by_target_app": by_target,
        "by_stealth": by_stealth,
        "splits": {
            name: {"n": info["n"], "sha256": info["sha256"]}
            for name, info in manifest_splits.items()
            if not name.startswith("private_")
        },
    }


def _counts_table_md(counts: dict) -> str:
    """Render the counts dict as a markdown table suitable for
    inlining into the DATASHEET template via {{COUNTS_TABLE}}."""
    lines: list[str] = []
    for axis_key, axis_label in (
        ("by_class", "by class"),
        ("by_family", "by family"),
        ("by_target_app", "by target_app"),
        ("by_stealth", "by stealth"),
    ):
        rows = counts.get(axis_key) or {}
        if not rows:
            lines.append(f"- **{axis_label}:** (none)")
            continue
        lines.append(f"- **{axis_label}:**")
        for k in sorted(rows):
            lines.append(f"  - `{k}`: {rows[k]}")
    return "\n".join(lines) if lines else "(release has no published sessions)"


def build_release(
    *,
    data_dir: pathlib.Path,
    out_dir: pathlib.Path,
    version: str,
    seed: int = 0,
    sessions: Optional[list] = None,
    templates_dir: Optional[pathlib.Path] = None,
) -> dict:
    """Assemble the release at `out_dir`. Returns a summary dict
    (also persisted as `manifest.json` inside the release).
    """
    src_benchmark = ROOT / "benchmark"
    templates_dir = templates_dir or (src_benchmark / "release" / "templates")
    built_at = dt.datetime.utcnow().isoformat(timespec="seconds") + "Z"

    # Clean any previous output.
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Sessions.
    if sessions is None:
        sessions = build_sessions(data_dir)
    n_candidates = len(sessions)

    # 2. Consent filter.
    candidate_ids = [s.session_id for s in sessions]
    publishable_ids, excluded = scrubmod.filter_publishable_session_ids(
        candidate_ids,
        data_dir / "sessions.jsonl",
        data_dir / "consent.jsonl",
    )
    publishable_set = set(publishable_ids)
    publishable_sessions = [s for s in sessions if s.session_id in publishable_set]

    # 3. Build splits over publishable sessions only.
    metas = sessions_to_meta(publishable_sessions)
    if not metas:
        # An empty input is allowed (framework-only release). The split
        # set will have all-zero counts; the manifest reflects that.
        split_set = splitmod.SplitSet(
            public_train=[], public_dev=[], public_test=[],
            private_heldout_family=[], private_heldout_stealth=[],
            manifest={
                "splits_version": splitmod.SPLITS_VERSION,
                "seed": seed,
                "agent_families_train": [],
                "agent_families_heldout": [],
                "stealth_holdout_families": [],
                "splits": {
                    name: {"n": 0, "sha256": splitmod._checksum([]),
                            "by_family": {}, "by_class": {}}
                    for name in (
                        "public_train", "public_dev", "public_test",
                        "private_heldout_family", "private_heldout_stealth",
                    )
                },
            },
        )
    else:
        split_set = splitmod.build_split_set(
            metas, seed=seed,
            source_data_sha256=(
                _source_data_sha256(data_dir) if data_dir.exists() else None
            ),
            built_at=built_at,
        )
        splitmod.assert_family_disjoint(split_set)
        splitmod.assert_no_session_in_two_public_splits(split_set)

    # 4. Write splits dir — public files + MANIFEST only.
    splits_out = out_dir / "splits" / splitmod.SPLITS_VERSION
    splitmod.write_split_set(split_set, splits_out)
    for hidden in ("private_heldout_family.json", "private_heldout_stealth.json"):
        (splits_out / hidden).unlink(missing_ok=True)

    # 5. Project public sessions to features + truth.
    public_ids = (
        set(split_set.public_train)
        | set(split_set.public_dev)
        | set(split_set.public_test)
    )
    public_sessions = [s for s in publishable_sessions if s.session_id in public_ids]
    data_out = out_dir / "data"
    data_out.mkdir(parents=True, exist_ok=True)
    features = contractmod.sessions_to_public_features(public_sessions)
    truth_map = contractmod.sessions_to_truth(public_sessions)
    truth_rows = [{"session_id": sid, **t} for sid, t in truth_map.items()]
    contractmod.write_jsonl(features, data_out / "features.jsonl")
    contractmod.write_jsonl(truth_rows, data_out / "truth.jsonl")
    (data_out / "excluded.json").write_text(
        json.dumps({
            "n_candidates": n_candidates,
            "n_publishable": len(publishable_sessions),
            "n_excluded": len(excluded),
            "excluded": excluded,
        }, indent=2, sort_keys=True)
    )

    # 6. Copy code.
    _copy_code_files(src_benchmark, out_dir)

    # 6b. Phase-bench-6: copy the container submission template tree to
    # <release>/submission_container/ so external submitters can build
    # their own --network=none container without reverse-engineering it.
    _copy_submission_container(templates_dir, out_dir)

    # 7. Compute counts EARLY so the DATASHEET / TASK / README templates
    # can substitute them in. They're also re-used for the final manifest.
    counts = _counts(public_sessions, split_set.manifest["splits"])

    # 8. Render docs.
    substitutions = {
        "VERSION": version, "version": version,
        "BUILT_AT": built_at, "built_at": built_at,
        "SPLITS_VERSION": splitmod.SPLITS_VERSION,
        "N_PUBLISHED": str(counts["total_sessions_published"]),
        "N_EXCLUDED": str(len(excluded)),
        "COUNTS_TABLE": _counts_table_md(counts),
    }
    for name in _DOC_FILES:
        body = _render_template(
            templates_dir / name, placeholder_name=name,
            substitutions=substitutions,
        )
        (out_dir / name).write_text(body)

    # 8. Release Makefile (specific to consumer ergonomics).
    (out_dir / "Makefile").write_text(_RELEASE_MAKEFILE.replace("{VERSION}", version))

    # 9. SCRUB GATE. Any hit aborts the build with the report saved
    # alongside the (now-deleted) output dir for debugging.
    report = scrubmod.scan_directory(out_dir)
    if not report.clean:
        debug_path = out_dir.parent / f"{out_dir.name}-scrub-report.json"
        debug_path.write_text(json.dumps(report.as_dict(), indent=2))
        shutil.rmtree(out_dir)
        raise SystemExit(
            f"[build_release] scrub gate aborted release: {len(report.hits)} hits; "
            f"see {debug_path} for the per-file:line:pattern breakdown"
        )

    # 10. Manifest.
    release_files: dict[str, str] = {}
    for path in sorted(out_dir.rglob("*")):
        if path.is_file():
            release_files[str(path.relative_to(out_dir))] = _file_sha256(path)
    manifest = {
        "version": version,
        "built_at": built_at,
        "splits_version": splitmod.SPLITS_VERSION,
        "source_data_sha256": (
            _source_data_sha256(data_dir) if data_dir.exists() else None
        ),
        "seed": seed,
        "n_candidates": n_candidates,
        "n_publishable": len(publishable_sessions),
        "n_excluded_by_consent": len(excluded),
        "scrub": {
            "clean": True,
            "files_scanned": report.files_scanned,
        },
        "counts": counts,
        "release_files": release_files,
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))
    # Add the manifest itself to release_files after writing it (so
    # manifest.json's own checksum lands in manifest.json on the
    # next read — meta-checksum left to consumers if they need it).
    manifest["release_files"]["manifest.json"] = _file_sha256(manifest_path)

    # 11. Tar + sha256.
    tar_path = out_dir.parent / f"{out_dir.name}.tar.gz"
    if tar_path.exists():
        tar_path.unlink()
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(out_dir, arcname=out_dir.name)
    tar_sha = hashlib.sha256(tar_path.read_bytes()).hexdigest()
    (tar_path.with_name(tar_path.name + ".sha256")).write_text(
        f"{tar_sha}  {tar_path.name}\n"
    )

    return {
        "dir": str(out_dir),
        "tar": str(tar_path),
        "tar_sha256": tar_sha,
        "manifest": manifest,
        "excluded": excluded,
    }


# ── CLI ──────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=pathlib.Path, default=ROOT / "data")
    ap.add_argument("--out", type=pathlib.Path, required=True)
    ap.add_argument("--version", required=True)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    result = build_release(
        data_dir=args.data, out_dir=args.out,
        version=args.version, seed=args.seed,
    )
    counts = result["manifest"]["counts"]
    print(f"[build_release] release ready at {result['dir']}")
    print(f"[build_release] tar:       {result['tar']}")
    print(f"[build_release] tar.sha256:{result['tar_sha256']}")
    print(f"[build_release] published  {counts['total_sessions_published']} sessions")
    print(f"[build_release] excluded   {result['manifest']['n_excluded_by_consent']} "
          f"(consent filter — see data/excluded.json)")
    print(f"[build_release] by_class   {counts['by_class']}")
    print(f"[build_release] by_family  {counts['by_family']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
