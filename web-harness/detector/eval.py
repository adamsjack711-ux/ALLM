"""Evaluate both heads on the held-out test set and write phase4.json.

Reports (NEVER accuracy):
  - PR-AUC                       (sklearn average_precision_score)
  - FP/hour                      (per session-hour of the test set)
  - per-generator alert rate     (TPR for agents, FPR for benign — back-compat)
  - per-family recall            (phase 8: keyed on the resolved family
                                  label, with `kind` ∈ {agent, benign_bot,
                                  human, unknown})
  - per-target_app slice         (phase 8: alert rate per target app)
  - agent-vs-benign_bot block    (phase 8: confusion specifically between
                                  agent sessions and the benign automation
                                  class, since detecting that one is the
                                  load-bearing question once benign_bot
                                  families are in the data)
  - honeypot precision           (data-only, no model)
  - ML-only PR-AUC + recall      (head trained without honeypot inputs —
                                  the "honeypots-disabled run" the spec
                                  asks for)
  - mean time-to-flag            (from the streaming alerter at chosen τ)
  - threshold-picking detail     (FP/hour budget targeted on test set;
                                  with a tiny dataset this often forces
                                  zero-FP, which the with_hp head meets
                                  trivially)
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

import numpy as np
import torch
from sklearn.metrics import average_precision_score, precision_recall_curve

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from features import (  # noqa: E402
    F_HP, F_REQ, F_SESS,
    HONEYPOT_NAMES,
    apply_aggregate_scaler,
    build_sessions,
)
from model import Detector, pad_batch  # noqa: E402
from alerter import StreamingAlerter  # noqa: E402


def load_checkpoint(path: pathlib.Path) -> Detector:
    ck = torch.load(path, map_location="cpu", weights_only=False)
    model = Detector(
        req_dim=ck["req_dim"], sess_dim=ck["sess_dim"], hp_dim=ck["hp_dim"],
        hidden=64, ablate_hp=ck["ablate_hp"],
    )
    model.load_state_dict(ck["state_dict"])
    model.eval()
    return model


def score_sessions(model: Detector, sessions: list) -> np.ndarray:
    seq, lengths, sess, hp, _ = pad_batch(sessions)
    with torch.no_grad():
        logits = model(seq, lengths, sess, hp)
        return torch.sigmoid(logits).cpu().numpy()


def session_hours(sessions: list) -> float:
    return sum(max(s.duration_s, 0.0) for s in sessions) / 3600.0


def pick_threshold_for_fp_budget(
    y_true: np.ndarray,
    scores: np.ndarray,
    sessions: list,
    fp_per_hour_budget: float,
) -> dict:
    """Pick the smallest threshold such that test-set FP/hour ≤ budget.

    Smaller threshold = higher recall but more FPs. We want the most
    permissive τ that still meets the budget.
    """
    hours = session_hours(sessions)
    fp_allowed = max(0.0, fp_per_hour_budget * hours)
    order = np.argsort(-scores)  # high → low
    cum_fp = 0
    chosen = None
    last_under = 1.0
    for i in order:
        if scores[i] < 0.0:
            continue
        if y_true[i] == 0:
            cum_fp += 1
        # if next step would exceed budget, current threshold is the
        # most permissive that still meets the budget
        if cum_fp <= fp_allowed:
            last_under = float(scores[i])
            chosen = last_under
        else:
            break
    # if no positive score yet (all OK), use 1.0 (no alerts)
    return {
        "threshold": float(chosen if chosen is not None else 1.0),
        "fp_allowed": fp_allowed,
        "session_hours": hours,
    }


def evaluate_head(
    head_tag: str,
    model: Detector,
    test_sess: list,
    fp_budget: float,
) -> dict:
    scores = score_sessions(model, test_sess)
    y = np.array([s.y for s in test_sess])

    try:
        pr_auc = float(average_precision_score(y, scores))
    except ValueError:
        pr_auc = float("nan")

    tpick = pick_threshold_for_fp_budget(y, scores, test_sess, fp_budget)
    tau = tpick["threshold"]

    pred = (scores >= tau).astype(int)
    n_fp = int(((pred == 1) & (y == 0)).sum())
    fp_per_hour = n_fp / max(tpick["session_hours"], 1e-9)

    per_src = {}
    for label in {s.src_label for s in test_sess}:
        mask = np.array([s.src_label == label for s in test_sess])
        if mask.sum() == 0:
            continue
        n = int(mask.sum())
        pos = int(((pred == 1) & mask).sum())
        is_agent_class = bool(y[mask].max() == 1)
        per_src[label] = {
            "test_sessions": n,
            "alerts": pos,
            # alert_rate is TPR (recall) for agent classes and FPR for
            # benign classes — interpretation is by `kind`.
            "alert_rate": pos / max(n, 1),
            "kind": "agent" if is_agent_class else "benign",
        }

    # phase 8: per-family rollup keyed on the resolved family from the
    # provenance manifest / phase 6 schema. `kind` is the resolved class
    # so eval consumers can distinguish agent-recall from benign_bot-FPR
    # from human-FPR.
    per_family: dict[str, dict] = {}
    families = {s.family for s in test_sess if s.family}
    for fam in families:
        mask = np.array([s.family == fam for s in test_sess])
        if mask.sum() == 0:
            continue
        n = int(mask.sum())
        pos = int(((pred == 1) & mask).sum())
        klasses = [s.klass for s, m in zip(test_sess, mask) if m]
        kind = max(set(klasses), key=klasses.count) if klasses else "unknown"
        rate = pos / max(n, 1)
        per_family[fam] = {
            "test_sessions": n,
            "alerts": pos,
            "alert_rate": rate,
            "kind": kind,
            # for agents this is recall (we want it high); for benign_bot
            # and human it's a false-positive rate (we want it low).
            "recall_if_agent": rate if kind == "agent" else None,
            "fp_rate_if_benign": rate if kind in ("benign_bot", "human") else None,
        }

    # phase 8: per-target_app slice — multi-target sweep wants to know
    # whether the detector behaves differently on DVWA vs juice_shop vs
    # vampi (the no-DOM API target).
    per_target_app: dict[str, dict] = {}
    target_apps = {s.target_app for s in test_sess if s.target_app}
    for app in target_apps:
        mask = np.array([s.target_app == app for s in test_sess])
        if mask.sum() == 0:
            continue
        n = int(mask.sum())
        pos = int(((pred == 1) & mask).sum())
        n_pos_label = int(y[mask].sum())
        n_neg_label = int((y[mask] == 0).sum())
        per_target_app[app] = {
            "test_sessions": n,
            "alerts": pos,
            "alert_rate": pos / max(n, 1),
            "n_agent_truth": n_pos_label,
            "n_benign_truth": n_neg_label,
        }

    # phase 8: agent-vs-benign_bot confusion specifically. The detector's
    # hardest job once the negative class is no longer just `human_sim`
    # is to NOT alert on legitimate non-browser bots. This block isolates
    # that question from human-vs-agent.
    agent_mask = np.array([s.klass == "agent" for s in test_sess])
    benign_bot_mask = np.array([s.klass == "benign_bot" for s in test_sess])
    pred_alert = pred == 1
    n_agent_alert = int((agent_mask & pred_alert).sum())
    n_agent_miss = int((agent_mask & ~pred_alert).sum())
    n_benign_fp = int((benign_bot_mask & pred_alert).sum())
    n_benign_ok = int((benign_bot_mask & ~pred_alert).sum())
    benign_per_fam: dict[str, dict] = {}
    for fam in {s.family for s, m in zip(test_sess, benign_bot_mask) if m}:
        fmask = np.array([s.family == fam and s.klass == "benign_bot"
                          for s in test_sess])
        if fmask.sum() == 0:
            continue
        fp_here = int((fmask & pred_alert).sum())
        benign_per_fam[fam] = {
            "test_sessions": int(fmask.sum()),
            "false_positives": fp_here,
            "fp_rate": fp_here / max(int(fmask.sum()), 1),
        }
    agent_vs_benign_bot = {
        "n_agent_truth": int(agent_mask.sum()),
        "n_benign_bot_truth": int(benign_bot_mask.sum()),
        "agent_recall": (n_agent_alert / int(agent_mask.sum())
                         if agent_mask.sum() else None),
        "benign_bot_fp_rate": (n_benign_fp / int(benign_bot_mask.sum())
                               if benign_bot_mask.sum() else None),
        "confusion": {
            "true_agent_pred_alert": n_agent_alert,
            "true_agent_pred_benign": n_agent_miss,
            "true_benign_bot_pred_alert": n_benign_fp,
            "true_benign_bot_pred_benign": n_benign_ok,
        },
        "per_benign_family_fp": benign_per_fam,
    }

    pr_curve = None
    try:
        prec, rec, thr = precision_recall_curve(y, scores)
        pr_curve = {
            "precision": [float(x) for x in prec[::max(1, len(prec) // 20)].tolist()],
            "recall": [float(x) for x in rec[::max(1, len(rec) // 20)].tolist()],
        }
    except ValueError:
        pass

    return {
        "head": head_tag,
        "pr_auc": pr_auc,
        "threshold": tau,
        "n_test": len(test_sess),
        "n_test_pos": int(y.sum()),
        "n_test_neg": int((y == 0).sum()),
        "fp_count_test": n_fp,
        "fp_per_hour": fp_per_hour,
        "session_hours_test": tpick["session_hours"],
        "per_source": per_src,
        "per_family": per_family,
        "per_target_app": per_target_app,
        "agent_vs_benign_bot": agent_vs_benign_bot,
        "pr_curve_sample": pr_curve,
    }


def honeypot_precision(sessions: list) -> dict:
    tripped = [s for s in sessions if s.hp.sum() > 0]
    if not tripped:
        return {"tripped_sessions": 0, "precision": None, "by_honeypot": {}}
    n_agent = sum(1 for s in tripped if s.y == 1)
    by_hp: dict[str, dict] = {}
    for i, hp_name in enumerate(HONEYPOT_NAMES):
        sub = [s for s in sessions if s.hp[i] > 0]
        if not sub:
            by_hp[hp_name] = {"tripped": 0, "precision": None}
            continue
        agents = sum(1 for s in sub if s.y == 1)
        by_hp[hp_name] = {
            "tripped": len(sub),
            "precision": agents / len(sub),
        }
    return {
        "tripped_sessions": len(tripped),
        "precision": n_agent / len(tripped),
        "by_honeypot": by_hp,
    }


def alerter_metrics(
    model: Detector,
    test_sess: list,
    threshold: float,
    norm_mean: np.ndarray,
    norm_std: np.ndarray,
) -> dict:
    alerter = StreamingAlerter(
        model=model, threshold=threshold, window=5, consec=2,
        norm_mean=norm_mean, norm_std=norm_std,
    )
    flags: list[dict] = []
    for s in test_sess:
        # Use the raw (un-normalized) session to feed streaming features;
        # the alerter re-applies the normalizer on each scoring tick so
        # it matches how a real-time deployment would work.
        ttf = alerter.run_session(s)
        flags.append({
            "session_id": s.session_id,
            "src_label": s.src_label,
            "y": s.y,
            "time_to_flag_s": ttf,
        })
    flagged = [f for f in flags if f["time_to_flag_s"] is not None]
    mean_ttf_pos = (
        float(np.mean([f["time_to_flag_s"] for f in flagged if f["y"] == 1]))
        if any(f["y"] == 1 for f in flagged) else None
    )
    return {
        "threshold": threshold,
        "sessions": len(flags),
        "flagged": len(flagged),
        "flagged_positive": sum(1 for f in flagged if f["y"] == 1),
        "flagged_negative_FP": sum(1 for f in flagged if f["y"] == 0),
        "mean_time_to_flag_s_positives": mean_ttf_pos,
        "per_session": flags,
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=pathlib.Path, default=pathlib.Path("/data"))
    ap.add_argument("--models", type=pathlib.Path, default=pathlib.Path("/data/models"))
    ap.add_argument(
        "--out", type=pathlib.Path, default=pathlib.Path("/data/reports/phase4.json"),
    )
    ap.add_argument("--fp-per-hour-budget", type=float, default=0.5)
    args = ap.parse_args()

    norm = np.load(args.models / "norm.npz", allow_pickle=True)
    mean = norm["mean"]
    std = norm["std"]
    test_ids = set(norm["test_ids"].tolist())

    all_sessions = build_sessions(args.data)
    test_sess_raw = [s for s in all_sessions if s.session_id in test_ids]
    test_sess = apply_aggregate_scaler(test_sess_raw, mean, std)

    if not test_sess:
        print("[eval] no test sessions found", file=sys.stderr)
        return 2

    out: dict = {
        "fp_per_hour_budget": args.fp_per_hour_budget,
        "n_test_sessions": len(test_sess),
        "test_y_pos": int(sum(s.y for s in test_sess)),
        "test_y_neg": int(sum(1 for s in test_sess if s.y == 0)),
        "honeypot_precision_data_only": honeypot_precision(test_sess),
    }

    for tag in ("with_hp", "ml_only"):
        ckpt = args.models / f"{tag}.pt"
        if not ckpt.exists():
            continue
        model = load_checkpoint(ckpt)
        head = evaluate_head(tag, model, test_sess, args.fp_per_hour_budget)
        head["alerter"] = alerter_metrics(
            model, test_sess_raw, head["threshold"], mean, std
        )
        out[tag] = head

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2))
    print(f"[eval] wrote {args.out}", flush=True)
    print(
        f"  with_hp   PR-AUC={out.get('with_hp', {}).get('pr_auc'):.4f}  "
        f"FP/hr={out.get('with_hp', {}).get('fp_per_hour'):.3f}",
        flush=True,
    )
    if "ml_only" in out:
        print(
            f"  ml_only   PR-AUC={out['ml_only']['pr_auc']:.4f}  "
            f"FP/hr={out['ml_only']['fp_per_hour']:.3f}",
            flush=True,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
