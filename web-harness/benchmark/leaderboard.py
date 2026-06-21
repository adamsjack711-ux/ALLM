"""Append-only leaderboard for Cernis benchmark submissions.

`benchmark.evaluate` writes `results.json` per run. This module turns
those per-run artifacts into a persistent leaderboard:

  - `append_entry(...)` writes one line to `leaderboard.jsonl`. Every
    run is appended; nothing is overwritten. Re-running the same
    submission against the same splits/split/seed re-appends; dedup
    happens at read time.

  - `read_entries(path)` parses the JSONL back to a `list[Entry]`.

  - `dedupe(entries)` keeps the LATEST entry per
    (submission_hash, splits_version, split, seed). The "latest"
    semantics mean a re-run replaces the previous score — what an
    operator generally wants.

  - `to_markdown(entries, ...)` renders the deduped + sorted table.
    Default sort is `primary.pr_auc` desc within a fixed
    (splits_version, split, seed) selector; the markdown groups
    rows by that selector so the rollup makes sense even when the
    JSONL mixes splits.

  - `submission_hash(submission_dir)` is the stable identity used for
    dedup: SHA-256 over the sorted list of (relpath, sha256(file)) for
    every regular file in the submission directory.

The leaderboard itself NEVER contains the word `accuracy` — the
evaluate.py results that feed it have already had `scrub_accuracy_field`
applied, and `append_entry` re-checks at write time.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import pathlib
from typing import Optional

from benchmark import contract as contractmod


@dataclasses.dataclass
class Entry:
    submitted_at: str
    submission: str
    submission_hash: str
    splits_version: str
    split: str
    seed: int
    primary: dict
    resource: dict
    runner: str

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, raw: dict) -> "Entry":
        return cls(
            submitted_at=str(raw["submitted_at"]),
            submission=str(raw["submission"]),
            submission_hash=str(raw["submission_hash"]),
            splits_version=str(raw["splits_version"]),
            split=str(raw["split"]),
            seed=int(raw["seed"]),
            primary=dict(raw.get("primary", {})),
            resource=dict(raw.get("resource", {})),
            runner=str(raw.get("runner", "python")),
        )


def submission_hash(submission_dir: pathlib.Path) -> str:
    """Stable SHA-256 over the submission directory's regular file
    contents. Used as the dedup key so re-uploading byte-identical
    code produces a byte-identical hash.

    Excludes anything under `__pycache__/` or named `.DS_Store` —
    those are filesystem noise, not part of the submission.
    """
    rows: list[tuple[str, str]] = []
    for path in sorted(submission_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(submission_dir).as_posix()
        if rel.startswith("__pycache__/") or "/__pycache__/" in rel:
            continue
        if path.name == ".DS_Store":
            continue
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append((rel, h))
    blob = "\n".join(f"{r}\t{h}" for r, h in rows).encode()
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def append_entry(
    leaderboard_path: pathlib.Path,
    *,
    submission_dir: pathlib.Path,
    results: dict,
    resource: Optional[dict] = None,
    runner: str = "python",
) -> Entry:
    """Append one entry derived from `results` (the dict that
    `evaluate.run_eval` returns / writes to results.json).

    `resource` carries `wall_time_s` / `peak_mem_mb` / `exit_status`;
    omitted fields default to None.

    Re-checks scrub_accuracy_field on the constructed entry — the
    leaderboard MUST stay free of the forbidden word even if a future
    evaluate.py change drops the in-evaluate check.
    """
    resource = resource or {}
    entry = Entry(
        submitted_at=dt.datetime.now(tz=dt.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ"),
        submission=str(results.get("submission", submission_dir)),
        submission_hash=submission_hash(submission_dir),
        splits_version=str(results.get("splits_version", "")),
        split=str(results.get("split", "")),
        seed=int(results.get("seed", 0)),
        primary=dict(results.get("primary", {})),
        resource={
            "wall_time_s": resource.get("wall_time_s"),
            "peak_mem_mb": resource.get("peak_mem_mb"),
            "exit_status": resource.get("exit_status"),
        },
        runner=runner,
    )
    payload = entry.to_dict()
    leak = contractmod.scrub_accuracy_field(payload)
    if leak:
        raise RuntimeError(
            f"leaderboard entry contains forbidden 'accuracy' field at: {leak}"
        )
    leaderboard_path.parent.mkdir(parents=True, exist_ok=True)
    with leaderboard_path.open("a") as f:
        f.write(json.dumps(payload, sort_keys=True) + "\n")
    return entry


def read_entries(leaderboard_path: pathlib.Path) -> list[Entry]:
    if not leaderboard_path.exists():
        return []
    out: list[Entry] = []
    for line in leaderboard_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(Entry.from_dict(json.loads(line)))
    return out


def dedupe(entries: list[Entry]) -> list[Entry]:
    """Keep the latest entry per
    (submission_hash, splits_version, split, seed). "Latest" is by
    `submitted_at` (ISO-8601 strings sort lexicographically when the
    Z suffix is consistent — `append_entry` always writes UTC `…Z`)."""
    by_key: dict[tuple[str, str, str, int], Entry] = {}
    for e in entries:
        key = (e.submission_hash, e.splits_version, e.split, e.seed)
        prior = by_key.get(key)
        if prior is None or e.submitted_at >= prior.submitted_at:
            by_key[key] = e
    return list(by_key.values())


def _fmt_float(v, places: int = 4) -> str:
    if v is None:
        return "n/a"
    try:
        x = float(v)
    except (TypeError, ValueError):
        return "n/a"
    if x != x:  # NaN
        return "n/a"
    return f"{x:.{places}f}"


def _fmt_int(v) -> str:
    if v is None:
        return "n/a"
    try:
        return str(int(v))
    except (TypeError, ValueError):
        return "n/a"


def to_markdown(
    entries: list[Entry],
    *,
    title: str = "Cernis benchmark leaderboard",
    sort_by: str = "pr_auc",
) -> str:
    """Render deduped entries to a markdown rollup grouped by
    (splits_version, split, seed). Within each group, sort by
    `primary[sort_by]` descending (NaN sinks to the bottom).

    The deliberately wide column set surfaces resource cost alongside
    quality — a submission that hits PR-AUC 0.92 in 4 hours of
    wall-time is meaningfully different from one that hits 0.88 in
    seconds.
    """
    deduped = dedupe(entries)
    groups: dict[tuple[str, str, int], list[Entry]] = {}
    for e in deduped:
        groups.setdefault((e.splits_version, e.split, e.seed), []).append(e)

    lines: list[str] = [f"# {title}", ""]
    if not groups:
        lines.append("_No entries yet._")
        return "\n".join(lines) + "\n"

    for (sv, sp, seed) in sorted(groups):
        bucket = groups[(sv, sp, seed)]

        def _key(e: Entry) -> float:
            v = e.primary.get(sort_by)
            try:
                x = float(v)
            except (TypeError, ValueError):
                return float("-inf")
            return float("-inf") if x != x else x

        bucket.sort(key=_key, reverse=True)
        lines.append(
            f"## splits_version `{sv}` · split `{sp}` · seed `{seed}`"
        )
        lines.append("")
        lines.append(
            "| Rank | Submission | PR-AUC | FP/hour | Threshold "
            "| Wall (s) | Peak (MB) | Exit | Runner | Submitted |"
        )
        lines.append(
            "|---:|---|---:|---:|---:|---:|---:|---:|---|---|"
        )
        for rank, e in enumerate(bucket, start=1):
            pr_auc = e.primary.get("pr_auc")
            fp_h = e.primary.get("fp_per_hour")
            tau = e.primary.get("threshold")
            wall = e.resource.get("wall_time_s")
            mem = e.resource.get("peak_mem_mb")
            xs = e.resource.get("exit_status")
            lines.append(
                f"| {rank} | `{e.submission}` "
                f"| {_fmt_float(pr_auc, 4)} "
                f"| {_fmt_float(fp_h, 2)} "
                f"| {_fmt_float(tau, 3)} "
                f"| {_fmt_float(wall, 1)} "
                f"| {_fmt_float(mem, 1)} "
                f"| {_fmt_int(xs)} "
                f"| {e.runner} "
                f"| {e.submitted_at} |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


# ── CLI ──────────────────────────────────────────────────────────────


def main(argv: Optional[list[str]] = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Read leaderboard.jsonl and emit a sorted markdown rollup.",
    )
    ap.add_argument("--leaderboard", type=pathlib.Path,
                    default=pathlib.Path("data/reports/leaderboard.jsonl"))
    ap.add_argument("--out", type=pathlib.Path, default=None,
                    help="markdown output path (defaults to <leaderboard>.md)")
    ap.add_argument("--sort-by", default="pr_auc",
                    help="primary key to sort within each group (default pr_auc)")
    args = ap.parse_args(argv)

    entries = read_entries(args.leaderboard)
    md = to_markdown(entries, sort_by=args.sort_by)
    out = args.out or args.leaderboard.with_suffix(".md")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(md)
    print(f"[leaderboard] {len(entries)} entries → {len(dedupe(entries))} deduped")
    print(f"[leaderboard] wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
