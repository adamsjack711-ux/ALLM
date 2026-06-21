"""I/O wrapper that adapts `submission.predict(...)` to the Cernis
container contract.

The Cernis runner bind-mounts:
    $CERNIS_IN/eval_features.jsonl   one feature dict per line (read-only)
    $CERNIS_OUT/                     where we write scores.jsonl

Optional:
    $CERNIS_IN/train_features.jsonl  if present + `submission.train`
    $CERNIS_IN/dev_features.jsonl    is defined, we call train() first

Exit codes:
    0  scores.jsonl written
    2  predict() returned a malformed shape (caller will fail eval)
    3  CERNIS_IN / CERNIS_OUT missing required files

Submissions should NOT edit this file. They define `predict()` (and
optionally `train()`) in `submission.py`. The contract is identical to
the Python-entrypoint flavor: same input dict shape, same output row
shape.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys


def _read_jsonl(path: pathlib.Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def _write_jsonl(rows: list[dict], path: pathlib.Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")


def main() -> int:
    in_dir = pathlib.Path(os.environ.get("CERNIS_IN", "/in"))
    out_dir = pathlib.Path(os.environ.get("CERNIS_OUT", "/out"))
    eval_path = in_dir / "eval_features.jsonl"
    if not eval_path.exists():
        print(f"[runner] missing {eval_path}", file=sys.stderr)
        return 3

    sys.path.insert(0, "/app")
    import submission  # type: ignore

    train_path = in_dir / "train_features.jsonl"
    dev_path = in_dir / "dev_features.jsonl"
    if hasattr(submission, "train") and train_path.exists():
        train_rows = _read_jsonl(train_path)
        dev_rows = _read_jsonl(dev_path) if dev_path.exists() else []
        submission.train(train_rows, dev_rows)

    eval_rows = _read_jsonl(eval_path)
    out_rows = submission.predict(eval_rows)
    if not isinstance(out_rows, list):
        print(f"[runner] predict() returned {type(out_rows).__name__}, "
              f"expected list", file=sys.stderr)
        return 2

    _write_jsonl(out_rows, out_dir / "scores.jsonl")
    print(f"[runner] wrote {len(out_rows)} rows to /out/scores.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
