"""Submission contract: the fixed I/O shape every submission targets.

A submission is a Python module that defines `predict(features) -> scores`
and optionally `train(train_features, dev_features) -> None`. The
evaluator imports it, optionally trains it on the public_train/dev
features, asks it to score the evaluation split's features, validates
the output shape, and joins with the held-back truth to compute the
metric suite.

The submission never sees `y` / `family` / `klass` / `stealth` — those
are part of the truth, deliberately kept out of the features file so a
submission can't peek at them and pass evaluation by reading the answer
key.

See SUBMISSION.md for the human-readable rules.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from typing import Any

# Public feature schema — these dimensions must match
# detector/features.py exactly. If features.py changes, bump
# FEATURE_SCHEMA_VERSION and add a per-version translator if old
# submissions need to keep running.
FEATURE_SCHEMA_VERSION = "v1"
AGG_FEATURE_NAMES = (
    "n_req", "delta_mean", "delta_std", "delta_p95",
    "n_paths", "frac_4xx", "frac_5xx", "max_rps",
    "js_ran", "ttfi", "dom_read", "duration_ms",
)
SEQ_FEATURE_NAMES = (
    "delta_ms", "status", "is_post", "path_bucket",
    "req_bytes", "resp_bytes", "ua_bucket",
    "header_count", "header_hash",
)
HP_FEATURE_NAMES = ("canary", "invisible_field", "admin_secrets", "robots_read")


def sessions_to_public_features(sess_list) -> list[dict]:
    """Project a list of `features.Session` down to the public feature
    schema for EVAL (no labels).

    Used for the records passed to `submission.predict()`. Truth fields
    (y, family, klass, stealth) are NOT included — the submission must
    score blind. Sequence features are returned as nested lists
    (JSON-serializable); the submission can convert to a numpy array
    if it wants.
    """
    out: list[dict] = []
    for s in sess_list:
        out.append({
            "session_id": s.session_id,
            "target_app": s.target_app,
            "agg": [float(x) for x in s.agg.tolist()],
            "seq": [[float(x) for x in row] for row in s.seq.tolist()],
            "hp": [float(x) for x in s.hp.tolist()],
        })
    return out


def sessions_to_train_features(sess_list) -> list[dict]:
    """Public features + the supervised label `y` + family/klass for
    stratification at TRAIN time only.

    `submission.train(train, dev)` receives this shape. The labels here
    are deliberate: any supervised model needs them. They are never
    present in the `predict()` input.
    """
    out: list[dict] = []
    for s in sess_list:
        row = {
            "session_id": s.session_id,
            "target_app": s.target_app,
            "agg": [float(x) for x in s.agg.tolist()],
            "seq": [[float(x) for x in row] for row in s.seq.tolist()],
            "hp": [float(x) for x in s.hp.tolist()],
            # Labels — train-only:
            "y": int(s.y),
            "family": s.family,
            "klass": s.klass,
            "stealth": bool(s.stealth),
        }
        out.append(row)
    return out


def sessions_to_truth(sess_list) -> dict[str, dict]:
    """Held-back per-session truth keyed by session_id. The submission
    never sees this; the evaluator uses it to compute metrics."""
    out: dict[str, dict] = {}
    for s in sess_list:
        out[s.session_id] = {
            "y": int(s.y),
            "family": s.family,
            "klass": s.klass,
            "stealth": bool(s.stealth),
            "target_app": s.target_app,
            "duration_s": float(s.duration_s),
            "src_label": s.src_label,
        }
    return out


def load_submission_module(submission_dir: pathlib.Path):
    """Import a submission.py from a directory by file path.

    The directory is added to sys.path so the submission can have
    sibling modules (e.g. `model.py`). Adds at the *end* of sys.path
    so the submission can't shadow benchmark / detector modules.
    """
    sub_path = submission_dir / "submission.py"
    if not sub_path.exists():
        raise FileNotFoundError(
            f"submission.py not found in {submission_dir}; expected "
            f"{sub_path}"
        )
    if str(submission_dir) not in sys.path:
        sys.path.append(str(submission_dir))
    spec = importlib.util.spec_from_file_location(
        f"_submission_{submission_dir.name}", sub_path,
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot create import spec for {sub_path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def validate_submission_output(
    rows: list[dict], expected_session_ids: set[str]
) -> list[str]:
    """Return a list of validation errors (empty list = valid)."""
    errors: list[str] = []
    seen: set[str] = set()
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"row {i}: not a dict (got {type(row).__name__})")
            continue
        sid = row.get("session_id")
        if not isinstance(sid, str) or not sid:
            errors.append(f"row {i}: missing or empty session_id")
            continue
        if sid in seen:
            errors.append(f"row {i}: duplicate session_id {sid!r}")
        seen.add(sid)
        score = row.get("agent_score")
        if not isinstance(score, (int, float)):
            errors.append(
                f"row {i} ({sid}): agent_score not numeric "
                f"({type(score).__name__})"
            )
            continue
        if not (0.0 <= float(score) <= 1.0):
            errors.append(
                f"row {i} ({sid}): agent_score {score} out of [0, 1]"
            )
    missing = expected_session_ids - seen
    if missing:
        errors.append(
            f"submission did not score {len(missing)} expected sessions "
            f"(first: {sorted(missing)[:3]}…)"
        )
    extra = seen - expected_session_ids
    if extra:
        errors.append(
            f"submission returned scores for {len(extra)} sessions NOT in the "
            f"requested split (first: {sorted(extra)[:3]}…)"
        )
    return errors


def scrub_accuracy_field(payload: Any) -> list[str]:
    """Return the JSON-paths where the substring 'accuracy' appears in
    a nested object. The harness uses this to fail-fast if a submission
    or a metric helper accidentally introduces the forbidden word."""
    hits: list[str] = []

    def walk(node, path: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if "accuracy" in str(k).lower():
                    hits.append(f"{path}.{k}")
                walk(v, f"{path}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            if "accuracy" in node.lower():
                hits.append(f"{path}={node!r}")

    walk(payload, "$")
    return hits


def write_jsonl(rows: list[dict], path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for r in rows:
            f.write(json.dumps(r, sort_keys=True) + "\n")


def read_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def sessions_from_features_jsonl(
    features_path: pathlib.Path, truth_path: pathlib.Path
):
    """Reconstruct `features.Session` objects from a public release's
    features.jsonl + truth.jsonl pair.

    Used when the eval harness runs against a packaged release rather
    than a populated `data/` directory. The reconstruction is faithful
    to every field downstream code touches; `ts_start` defaults to 0.0
    because it isn't part of the public feature schema (the eval
    doesn't need wall-clock ordering, only per-session features).
    """
    import numpy as np
    from features import Session  # type: ignore

    truth_by_sid = {r["session_id"]: r for r in read_jsonl(truth_path)}
    out = []
    for f in read_jsonl(features_path):
        sid = f["session_id"]
        t = truth_by_sid.get(sid)
        if t is None:
            continue
        seq = (
            np.array(f["seq"], dtype="float32")
            if f["seq"] else np.zeros((1, 9), dtype="float32")
        )
        agg = np.array(f["agg"], dtype="float32")
        hp = np.array(f["hp"], dtype="float32")
        out.append(Session(
            session_id=sid,
            src_label=t.get("src_label") or t.get("family", ""),
            seq=seq, agg=agg, hp=hp,
            y=int(t["y"]),
            duration_s=float(t["duration_s"]),
            ts_start=0.0,
            n_req=int(seq.shape[0]),
            klass=t["klass"], family=t["family"],
            target_app=t["target_app"],
            stealth=bool(t["stealth"]),
        ))
    return out
