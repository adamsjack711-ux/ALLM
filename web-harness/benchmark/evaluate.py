"""Cernis benchmark eval harness — one command, full metric suite.

Usage (via Makefile):
    make eval SUBMISSION=benchmark/baselines/hybrid SPLIT=public_test
    make eval SUBMISSION=benchmark/baselines/hybrid SPLIT=heldout

Or directly:
    python3 -m benchmark.evaluate \\
        --submission benchmark/baselines/hybrid \\
        --split public_test --seed 0

Pipeline:
  1. Load the requested split set from `benchmark/splits/v1/`. The
     public-eval path NEVER opens any `private_*.json`.
  2. Build session features from `data/` (the existing
     detector.features.build_sessions does the work) and project to
     the public feature schema.
  3. Import the submission module, call its optional train() on the
     public training features, then call predict() on the evaluation
     features.
  4. Validate the submission's output shape.
  5. Join scores with held-back truth and compute the metric suite:
     PRIMARY (per split kind) + per-family + agent-vs-benign_bot.
  6. Write results.json + report.txt. Asserts "accuracy" never appears
     in either output.

Never reports accuracy. Never opens private_*.json on public_test.
Same seed → byte-identical results.json.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import random
import re
import sys
from typing import Optional

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "detector"))
sys.path.insert(0, str(ROOT))

from features import build_sessions  # type: ignore  # noqa: E402

from benchmark import contract as contractmod  # noqa: E402
from benchmark import splits as splitmod  # noqa: E402

# Paths the eval harness is allowed to open under each SPLIT name.
# public_train.json + public_dev.json are always readable (the
# submission may need them to train); the SPLIT controls what
# *additional* files the scoring step is allowed to load. Only the
# `heldout` SPLIT may open the `private_*.json` files.
_PUBLIC_TRAIN_DEV = ("public_train.json", "public_dev.json")
ALLOWED_SPLIT_FILES: dict[str, tuple[str, ...]] = {
    "public_test": _PUBLIC_TRAIN_DEV + ("public_test.json",),
    "heldout": _PUBLIC_TRAIN_DEV + (
        "public_test.json",
        "private_heldout_family.json", "private_heldout_stealth.json",
    ),
}


def _seed_everything(seed: int) -> None:
    random.seed(seed)
    np.random.seed(seed)
    try:
        import torch
        torch.manual_seed(seed)
    except Exception:
        pass


def _safe_load_split(
    splits_dir: pathlib.Path, split_name: str, requested: str
) -> list[str]:
    """Load a split file, but refuse if it isn't allowed under the
    requested SPLIT mode. This is the load-bearing check that prevents
    `--split public_test` from ever touching private_*.json."""
    allowed = ALLOWED_SPLIT_FILES.get(requested)
    if allowed is None:
        raise ValueError(
            f"unknown SPLIT {requested!r}; expected one of "
            f"{sorted(ALLOWED_SPLIT_FILES)}"
        )
    filename = f"{split_name}.json"
    if filename not in allowed:
        raise PermissionError(
            f"refusing to load {filename} under SPLIT={requested}: not in "
            f"the allow-list {list(allowed)}"
        )
    path = splits_dir / filename
    if not path.exists():
        raise FileNotFoundError(
            f"split file {path} does not exist. "
            f"Run `python3 -m benchmark.build_splits` to populate."
        )
    return splitmod.read_split(path)


# ── metric helpers (local, not imported from detector/eval.py) ──────


def _average_precision(y: np.ndarray, scores: np.ndarray) -> float:
    """sklearn.metrics.average_precision_score wrapped to return nan
    when the class set is degenerate (all-pos or all-neg)."""
    from sklearn.metrics import average_precision_score
    if y.size == 0 or y.sum() == 0 or y.sum() == y.size:
        return float("nan")
    return float(average_precision_score(y, scores))


def _pick_threshold_for_budget(
    y: np.ndarray, scores: np.ndarray, session_hours: float, budget: float
) -> tuple[float, int, float]:
    """Most permissive threshold whose FP/hour ≤ budget on (y, scores).

    Returns (threshold, fp_count_at_threshold, fp_per_hour_at_threshold).
    Same logic as detector/eval.py::pick_threshold_for_fp_budget but
    independent so the harness doesn't import the in-repo eval.
    """
    fp_allowed = max(0.0, budget * session_hours)
    order = np.argsort(-scores)
    cum_fp = 0
    chosen = 1.0
    for i in order:
        if y[i] == 0:
            cum_fp += 1
        if cum_fp <= fp_allowed:
            chosen = float(scores[i])
        else:
            break
    pred = (scores >= chosen).astype(int)
    n_fp = int(((pred == 1) & (y == 0)).sum())
    return chosen, n_fp, n_fp / max(session_hours, 1e-9)


def _per_family(
    truth: dict[str, dict], scores_by_sid: dict[str, float], threshold: float
) -> dict[str, dict]:
    """Per-family alert rate, with `kind` so the consumer can tell
    recall-on-agents from FP-rate-on-benigns at a glance."""
    by_fam: dict[str, list[tuple[int, int, str]]] = {}
    for sid, t in truth.items():
        fam = t["family"] or "?"
        pred = 1 if scores_by_sid.get(sid, 0.0) >= threshold else 0
        by_fam.setdefault(fam, []).append((int(t["y"]), pred, t["klass"]))
    out: dict[str, dict] = {}
    for fam, rows in by_fam.items():
        n = len(rows)
        alerts = sum(p for _, p, _ in rows)
        klasses = [k for _, _, k in rows]
        kind = max(set(klasses), key=klasses.count) if klasses else "unknown"
        rate = alerts / max(n, 1)
        out[fam] = {
            "n": n,
            "alerts": alerts,
            "alert_rate": rate,
            "kind": kind,
            "recall_if_agent": rate if kind == "agent" else None,
            "fp_rate_if_benign": rate if kind in ("benign_bot", "human") else None,
        }
    return out


def _per_target_app(
    truth: dict[str, dict], scores_by_sid: dict[str, float], threshold: float
) -> dict[str, dict]:
    by_app: dict[str, list[tuple[int, int]]] = {}
    for sid, t in truth.items():
        app = t["target_app"] or "?"
        pred = 1 if scores_by_sid.get(sid, 0.0) >= threshold else 0
        by_app.setdefault(app, []).append((int(t["y"]), pred))
    out: dict[str, dict] = {}
    for app, rows in by_app.items():
        n = len(rows)
        alerts = sum(p for _, p in rows)
        out[app] = {
            "n": n,
            "alerts": alerts,
            "alert_rate": alerts / max(n, 1),
            "n_agent_truth": sum(1 for y, _ in rows if y == 1),
            "n_benign_truth": sum(1 for y, _ in rows if y == 0),
        }
    return out


# Phase 14: real-LLM agent rollups. The `real_agent` generator names
# families `llm_<backend>_<model_slug>` (e.g. `llm_openai_gpt_4o_mini`,
# `llm_anthropic_claude_haiku_4_5`) so the existing `_per_family` rollup
# already surfaces per-(backend × model) numbers. The two functions
# below pivot on that prefix to give explicit per-backend and
# per-(backend × model × target_app) rollups — much easier for a
# consumer to read than scanning a long per_family table.
_LLM_FAMILY_RE = re.compile(r"^llm_(openai|anthropic)_(.+)$")


def _parse_llm_family(fam: str) -> Optional[tuple[str, str]]:
    """`llm_<backend>_<model_slug>` → (backend, model_slug), else None."""
    if not isinstance(fam, str):
        return None
    m = _LLM_FAMILY_RE.match(fam)
    return (m.group(1), m.group(2)) if m else None


def _per_llm_backend(
    truth: dict[str, dict], scores_by_sid: dict[str, float], threshold: float,
) -> dict[str, dict]:
    """Per-backend aggregate over all LLM-agent sessions. Returns
    `{}` when no `llm_*` families are present in the truth (no schema
    cost when LLM cells haven't been run yet)."""
    by_backend: dict[str, list[tuple[int, int]]] = {}
    by_backend_targets: dict[str, set[str]] = {}
    by_backend_models: dict[str, set[str]] = {}
    for sid, t in truth.items():
        parsed = _parse_llm_family(t.get("family") or "")
        if parsed is None:
            continue
        backend, model_slug = parsed
        pred = 1 if scores_by_sid.get(sid, 0.0) >= threshold else 0
        by_backend.setdefault(backend, []).append((int(t["y"]), pred))
        by_backend_targets.setdefault(backend, set()).add(
            t.get("target_app") or "?"
        )
        by_backend_models.setdefault(backend, set()).add(model_slug)
    out: dict[str, dict] = {}
    for backend, rows in by_backend.items():
        n = len(rows)
        n_alert = sum(p for _, p in rows)
        n_pos = sum(1 for y, _ in rows if y == 1)
        n_recall_num = sum(p for y, p in rows if y == 1)
        out[backend] = {
            "n": n,
            "alerts": n_alert,
            "alert_rate": n_alert / max(n, 1),
            "n_agent_truth": n_pos,
            "recall": n_recall_num / n_pos if n_pos else None,
            "n_target_apps": len(by_backend_targets.get(backend, set())),
            "n_models": len(by_backend_models.get(backend, set())),
        }
    return out


def _per_llm_model_x_target(
    truth: dict[str, dict], scores_by_sid: dict[str, float], threshold: float,
) -> dict[str, dict]:
    """Per-(backend × model_slug × target_app) breakdown for LLM-agent
    sessions. Empty dict when no `llm_*` families are present.

    Key shape: `"<backend>/<model_slug>/<target_app>"` — string-keyed
    so the JSON stays consumer-friendly (nested dicts here would force
    every reader to traverse three levels for a single number)."""
    out: dict[str, dict] = {}
    for sid, t in truth.items():
        parsed = _parse_llm_family(t.get("family") or "")
        if parsed is None:
            continue
        backend, model_slug = parsed
        target_app = t.get("target_app") or "?"
        key = f"{backend}/{model_slug}/{target_app}"
        pred = 1 if scores_by_sid.get(sid, 0.0) >= threshold else 0
        cell = out.setdefault(key, {
            "n": 0, "alerts": 0, "n_agent_truth": 0,
            "n_recall_numerator": 0, "stealth_seen": False,
        })
        cell["n"] += 1
        cell["alerts"] += pred
        if int(t["y"]) == 1:
            cell["n_agent_truth"] += 1
            if pred:
                cell["n_recall_numerator"] += 1
        if t.get("stealth"):
            cell["stealth_seen"] = True
    for key, cell in out.items():
        n_pos = cell["n_agent_truth"]
        cell["alert_rate"] = cell["alerts"] / max(cell["n"], 1)
        cell["recall"] = (
            cell["n_recall_numerator"] / n_pos if n_pos else None
        )
        # Drop the intermediate accumulator before serialization
        del cell["n_recall_numerator"]
    return out


def _agent_vs_benign_bot(
    truth: dict[str, dict], scores_by_sid: dict[str, float], threshold: float
) -> dict:
    n_agent_alert = n_agent_miss = n_benign_fp = n_benign_ok = 0
    per_benign_fam: dict[str, dict[str, int]] = {}
    for sid, t in truth.items():
        pred = 1 if scores_by_sid.get(sid, 0.0) >= threshold else 0
        if t["klass"] == "agent":
            if pred:
                n_agent_alert += 1
            else:
                n_agent_miss += 1
        elif t["klass"] == "benign_bot":
            fam = t["family"] or "?"
            d = per_benign_fam.setdefault(fam, {"n": 0, "fp": 0})
            d["n"] += 1
            if pred:
                d["fp"] += 1
                n_benign_fp += 1
            else:
                n_benign_ok += 1
    n_agent = n_agent_alert + n_agent_miss
    n_benign = n_benign_fp + n_benign_ok
    return {
        "n_agent_truth": n_agent,
        "n_benign_bot_truth": n_benign,
        "agent_recall": n_agent_alert / n_agent if n_agent else None,
        "benign_bot_fp_rate": n_benign_fp / n_benign if n_benign else None,
        "confusion": {
            "true_agent_pred_alert": n_agent_alert,
            "true_agent_pred_benign": n_agent_miss,
            "true_benign_bot_pred_alert": n_benign_fp,
            "true_benign_bot_pred_benign": n_benign_ok,
        },
        "per_benign_family_fp": {
            fam: {"n": d["n"], "false_positives": d["fp"],
                   "fp_rate": d["fp"] / max(d["n"], 1)}
            for fam, d in per_benign_fam.items()
        },
    }


def _session_hours(truth: dict[str, dict]) -> float:
    return sum(max(t["duration_s"], 0.0) for t in truth.values()) / 3600.0


# ── eval main flow ───────────────────────────────────────────────────


def _run_submission(
    submission_dir: pathlib.Path,
    train_features: list[dict],
    dev_features: list[dict],
    eval_features: list[dict],
) -> list[dict]:
    mod = contractmod.load_submission_module(submission_dir)
    if hasattr(mod, "train"):
        mod.train(train_features, dev_features)
    if not hasattr(mod, "predict"):
        raise RuntimeError(
            f"submission {submission_dir} missing predict(features) function"
        )
    rows = mod.predict(eval_features)
    if not isinstance(rows, list):
        raise RuntimeError(
            f"submission.predict() returned {type(rows).__name__}, expected list"
        )
    return rows


def _results_to_report(results: dict) -> str:
    """One-screen text view of the results.json — the thing a human
    actually reads. Never includes the word `accuracy`."""
    lines: list[str] = []
    lines.append(f"Cernis benchmark eval")
    lines.append(f"  submission        {results['submission']}")
    lines.append(f"  split             {results['split']}")
    lines.append(f"  seed              {results['seed']}")
    lines.append(f"  n_sessions        {results['n_sessions']}")
    lines.append(f"  session_hours     {results['session_hours']:.3f}")
    lines.append(f"  fp_per_hour_budget {results['fp_per_hour_budget']:.3f}")
    lines.append("")
    p = results.get("primary", {})
    lines.append("PRIMARY")
    for k, v in p.items():
        lines.append(
            f"  {k:<32s} "
            f"{(f'{v:.4f}' if isinstance(v, (int, float)) else v)}"
        )
    lines.append("")
    lines.append("PER-FAMILY")
    for fam, info in sorted(results.get("per_family", {}).items()):
        marker = (
            f"recall={info['recall_if_agent']:.2f}"
            if info["recall_if_agent"] is not None
            else f"fp={info['fp_rate_if_benign']:.2f}"
            if info["fp_rate_if_benign"] is not None
            else f"rate={info['alert_rate']:.2f}"
        )
        lines.append(
            f"  {fam:<24s} n={info['n']:>4d}  kind={info['kind']:<10s} {marker}"
        )
    lines.append("")
    a = results.get("agent_vs_benign_bot", {})
    if a:
        lines.append("AGENT vs BENIGN_BOT")
        ar = a.get("agent_recall")
        br = a.get("benign_bot_fp_rate")
        lines.append(
            f"  agent recall                   "
            f"{(f'{ar:.3f}' if ar is not None else 'n/a')}"
        )
        lines.append(
            f"  benign_bot FP rate              "
            f"{(f'{br:.3f}' if br is not None else 'n/a')}"
        )
    return "\n".join(lines) + "\n"


def run_eval(
    *,
    submission_dir: pathlib.Path,
    split: str,
    splits_dir: pathlib.Path,
    data_dir: pathlib.Path,
    seed: int,
    fp_per_hour_budget: float,
    out_dir: pathlib.Path,
    sessions: Optional[list] = None,
) -> dict:
    """Run the full eval pipeline; return the results dict and write
    results.json + report.txt to `out_dir`.

    `sessions` is an injection point for the smoke test: when provided,
    the harness skips `build_sessions(data_dir)` and uses the supplied
    list directly. Production callers leave it None.
    """
    _seed_everything(seed)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Build the session universe.
    if sessions is None:
        sessions = build_sessions(data_dir)
    if not sessions:
        raise RuntimeError(f"no sessions found in {data_dir}")
    by_id = {s.session_id: s for s in sessions}

    # 2. Load splits the public-eval path is allowed to see.
    train_ids = set(_safe_load_split(splits_dir, "public_train", split))
    dev_ids = set(_safe_load_split(splits_dir, "public_dev", split))
    train_sess = [by_id[i] for i in sorted(train_ids) if i in by_id]
    dev_sess = [by_id[i] for i in sorted(dev_ids) if i in by_id]

    if split == "public_test":
        eval_ids = set(_safe_load_split(splits_dir, "public_test", split))
        eval_sess = [by_id[i] for i in sorted(eval_ids) if i in by_id]
        public_test_sess = eval_sess  # threshold calibrated on this
    elif split == "heldout":
        public_test_ids = set(_safe_load_split(splits_dir, "public_test", split))
        heldout_fam_ids = set(_safe_load_split(splits_dir, "private_heldout_family", split))
        heldout_stealth_ids = set(_safe_load_split(
            splits_dir, "private_heldout_stealth", split,
        ))
        eval_ids = public_test_ids | heldout_fam_ids | heldout_stealth_ids
        eval_sess = [by_id[i] for i in sorted(eval_ids) if i in by_id]
        public_test_sess = [by_id[i] for i in sorted(public_test_ids) if i in by_id]
    else:
        raise ValueError(f"unsupported split {split!r}")

    # 3. Train features include labels (y / family / klass / stealth)
    #    so supervised baselines can fit. Eval features are public-only
    #    so the submission has no way to peek at the answer at predict
    #    time.
    train_features = contractmod.sessions_to_train_features(train_sess)
    dev_features = contractmod.sessions_to_train_features(dev_sess)
    eval_features = contractmod.sessions_to_public_features(eval_sess)
    truth = contractmod.sessions_to_truth(eval_sess)
    public_test_truth = contractmod.sessions_to_truth(public_test_sess)

    # 4. Run submission.
    raw_rows = _run_submission(
        submission_dir, train_features, dev_features, eval_features,
    )
    errors = contractmod.validate_submission_output(
        raw_rows, {f["session_id"] for f in eval_features},
    )
    if errors:
        raise RuntimeError(
            "submission output failed validation:\n  - " + "\n  - ".join(errors)
        )
    scores_by_sid = {r["session_id"]: float(r["agent_score"]) for r in raw_rows}

    # Fail fast if the submission tried to sneak `accuracy` into its rows.
    leak = contractmod.scrub_accuracy_field(raw_rows)
    if leak:
        raise RuntimeError(
            f"submission output contains forbidden 'accuracy' field at: {leak}"
        )

    # 5. Compute metrics.
    sids_pt = list(public_test_truth.keys())
    y_pt = np.array([public_test_truth[s]["y"] for s in sids_pt])
    scores_pt = np.array([scores_by_sid[s] for s in sids_pt])
    session_hours_pt = _session_hours(public_test_truth)
    threshold, fp_count_pt, fp_per_hour = _pick_threshold_for_budget(
        y_pt, scores_pt, session_hours_pt, fp_per_hour_budget,
    )

    primary: dict = {
        "pr_auc": _average_precision(
            np.array([truth[s]["y"] for s in truth]),
            np.array([scores_by_sid[s] for s in truth]),
        ),
        "fp_per_hour": fp_per_hour,
        "threshold": threshold,
        "session_hours_for_threshold": session_hours_pt,
    }

    if split == "heldout":
        # Held-out family PR-AUC: positives are the held-out agent
        # sessions, negatives are the public_test benigns (the only
        # known-distribution negatives we have for this split).
        heldout_fam_ids = set(_safe_load_split(
            splits_dir, "private_heldout_family", split,
        ))
        heldout_stealth_ids = set(_safe_load_split(
            splits_dir, "private_heldout_stealth", split,
        ))
        heldout_fam_truth = {
            sid: truth[sid] for sid in heldout_fam_ids if sid in truth
        }
        heldout_stealth_truth = {
            sid: truth[sid] for sid in heldout_stealth_ids if sid in truth
        }
        pt_negative_sids = [
            sid for sid, t in public_test_truth.items() if t["y"] == 0
        ]
        ho_pos_sids = [
            sid for sid in heldout_fam_truth if heldout_fam_truth[sid]["y"] == 1
        ]
        if ho_pos_sids and pt_negative_sids:
            combo_y = np.array([1] * len(ho_pos_sids) + [0] * len(pt_negative_sids))
            combo_scores = np.array(
                [scores_by_sid[s] for s in ho_pos_sids]
                + [scores_by_sid[s] for s in pt_negative_sids]
            )
            heldout_family_pr_auc = _average_precision(combo_y, combo_scores)
        else:
            heldout_family_pr_auc = float("nan")
        ho_fam_pred = np.array([
            1 if scores_by_sid[s] >= threshold else 0 for s in ho_pos_sids
        ])
        heldout_family_recall = (
            float(ho_fam_pred.mean()) if ho_fam_pred.size else float("nan")
        )
        ho_stealth_pos_sids = [
            sid for sid in heldout_stealth_truth
            if heldout_stealth_truth[sid]["y"] == 1
        ]
        ho_stealth_pred = np.array([
            1 if scores_by_sid[s] >= threshold else 0 for s in ho_stealth_pos_sids
        ])
        heldout_stealth_recall = (
            float(ho_stealth_pred.mean()) if ho_stealth_pred.size else float("nan")
        )
        primary["heldout_family_pr_auc"] = heldout_family_pr_auc
        primary["heldout_family_recall_at_budget"] = heldout_family_recall
        primary["heldout_stealth_recall"] = heldout_stealth_recall
        primary["n_heldout_family_positives"] = len(ho_pos_sids)
        primary["n_heldout_stealth_positives"] = len(ho_stealth_pos_sids)

    results = {
        "split": split,
        "seed": seed,
        "submission": str(submission_dir),
        "splits_version": splitmod.SPLITS_VERSION,
        "n_sessions": len(eval_sess),
        "session_hours": _session_hours(truth),
        "fp_per_hour_budget": fp_per_hour_budget,
        "primary": primary,
        "per_family": _per_family(truth, scores_by_sid, threshold),
        "per_target_app": _per_target_app(truth, scores_by_sid, threshold),
        "per_llm_backend": _per_llm_backend(
            truth, scores_by_sid, threshold,
        ),
        "per_llm_model_x_target": _per_llm_model_x_target(
            truth, scores_by_sid, threshold,
        ),
        "agent_vs_benign_bot": _agent_vs_benign_bot(
            truth, scores_by_sid, threshold,
        ),
        "built_at": dt.datetime.utcnow().isoformat() + "Z",
    }

    # Final accuracy-leak check on the full results object.
    leak = contractmod.scrub_accuracy_field(results)
    if leak:
        raise RuntimeError(
            f"results.json contains forbidden 'accuracy' field at: {leak}"
        )
    report_text = _results_to_report(results)
    if "accuracy" in report_text.lower():
        raise RuntimeError(
            "report.txt contains forbidden 'accuracy' substring"
        )

    # `built_at` is wall-clock — strip from the file so two same-seed
    # runs produce byte-identical results.json (reproducibility gate).
    results_for_disk = {k: v for k, v in results.items() if k != "built_at"}
    (out_dir / "results.json").write_text(
        json.dumps(results_for_disk, indent=2, sort_keys=True)
    )
    (out_dir / "report.txt").write_text(report_text)
    return results


# ── CLI ──────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--submission", type=pathlib.Path, required=True)
    ap.add_argument("--split", default="public_test",
                    choices=sorted(ALLOWED_SPLIT_FILES.keys()))
    ap.add_argument("--splits-dir", type=pathlib.Path,
                    default=ROOT / "benchmark" / "splits" / splitmod.SPLITS_VERSION)
    ap.add_argument("--data", type=pathlib.Path, default=ROOT / "data")
    ap.add_argument(
        "--features-jsonl", type=pathlib.Path, default=None,
        help="Public release mode: load sessions from this features.jsonl "
             "instead of detector.features.build_sessions(--data). Must be "
             "paired with --truth-jsonl.",
    )
    ap.add_argument("--truth-jsonl", type=pathlib.Path, default=None)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--fp-per-hour-budget", type=float, default=1.0)
    ap.add_argument("--out", type=pathlib.Path, default=None)
    args = ap.parse_args()

    out_dir = args.out or (
        ROOT / "data" / "reports"
        / f"bench_{args.split}_{args.submission.name}_seed{args.seed}"
    )

    sessions = None
    if args.features_jsonl or args.truth_jsonl:
        if not (args.features_jsonl and args.truth_jsonl):
            print(
                "[evaluate] --features-jsonl and --truth-jsonl must both be set",
                file=sys.stderr,
            )
            return 2
        sessions = contractmod.sessions_from_features_jsonl(
            args.features_jsonl, args.truth_jsonl,
        )

    results = run_eval(
        submission_dir=args.submission,
        split=args.split,
        splits_dir=args.splits_dir,
        data_dir=args.data,
        seed=args.seed,
        fp_per_hour_budget=args.fp_per_hour_budget,
        out_dir=out_dir,
        sessions=sessions,
    )
    print((out_dir / "report.txt").read_text(), end="")
    print(f"[evaluate] wrote {out_dir / 'results.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
