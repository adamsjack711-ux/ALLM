"""Train two heads: with-honeypot and ML-only (honeypot inputs ablated).

Splits sessions with GroupShuffleSplit(test_size=0.3, random_state=0) on
`session_id`. Loss = BCEWithLogits. Early-stop on val PR-AUC.

Writes checkpoints to <out>/with_hp.pt and <out>/ml_only.pt, and a
shared normalizer to <out>/norm.npz. The eval / alerter scripts pick
all three up by directory.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
import time

import numpy as np
import torch
import torch.nn as nn
from sklearn.metrics import average_precision_score
from sklearn.model_selection import GroupShuffleSplit

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from features import (  # noqa: E402
    F_HP, F_REQ, F_SESS,
    apply_aggregate_scaler,
    build_sessions,
    fit_aggregate_scaler,
    label_counts,
)
from model import Detector, pad_batch  # noqa: E402


def split_sessions(sessions, test_size=0.3, seed=0):
    y = np.array([s.y for s in sessions])
    groups = np.array([s.session_id for s in sessions])
    gss = GroupShuffleSplit(n_splits=1, test_size=test_size, random_state=seed)
    train_idx, test_idx = next(gss.split(sessions, y, groups=groups))
    return (
        [sessions[i] for i in train_idx],
        [sessions[i] for i in test_idx],
    )


def train_head(train_sess, val_sess, ablate_hp, epochs, lr, patience):
    model = Detector(
        req_dim=F_REQ, sess_dim=F_SESS, hp_dim=F_HP,
        hidden=64, ablate_hp=ablate_hp,
    )
    opt = torch.optim.AdamW(model.parameters(), lr=lr)
    loss_fn = nn.BCEWithLogitsLoss()

    best_auc = -1.0
    best_state = None
    bad_epochs = 0
    history = []

    for epoch in range(1, epochs + 1):
        model.train()
        seq, lengths, sess, hp, y = pad_batch(train_sess)
        opt.zero_grad()
        logits = model(seq, lengths, sess, hp)
        loss = loss_fn(logits, y)
        loss.backward()
        opt.step()

        model.eval()
        with torch.no_grad():
            vseq, vlen, vsess, vhp, vy = pad_batch(val_sess)
            vlog = model(vseq, vlen, vsess, vhp)
            scores = torch.sigmoid(vlog).cpu().numpy()
            try:
                auc = float(average_precision_score(vy.cpu().numpy(), scores))
            except ValueError:
                auc = float("nan")
        history.append({"epoch": epoch, "loss": float(loss.item()), "val_pr_auc": auc})

        if not np.isnan(auc) and auc > best_auc + 1e-6:
            best_auc = auc
            best_state = {k: v.detach().clone() for k, v in model.state_dict().items()}
            bad_epochs = 0
        else:
            bad_epochs += 1
            if bad_epochs >= patience:
                break

    if best_state is not None:
        model.load_state_dict(best_state)
    return model, best_auc, history


def save_checkpoint(model: Detector, path: pathlib.Path, meta: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(
        {
            "state_dict": model.state_dict(),
            "req_dim": model.req_dim,
            "sess_dim": model.sess_dim,
            "hp_dim": model.hp_dim,
            "ablate_hp": model.ablate_hp,
            "meta": meta,
        },
        path,
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=pathlib.Path, default=pathlib.Path("/data"))
    ap.add_argument("--out", type=pathlib.Path, default=pathlib.Path("/data/models"))
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--patience", type=int, default=20)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    sessions = build_sessions(args.data)
    if not sessions:
        print("[train] no sessions found in", args.data, file=sys.stderr)
        return 2
    counts = label_counts(sessions)
    print(f"[train] sessions={len(sessions)} by_label={counts}", flush=True)

    train_sess, test_sess = split_sessions(sessions, test_size=0.3, seed=args.seed)
    if not train_sess or not test_sess:
        print("[train] degenerate split", file=sys.stderr)
        return 3
    if all(s.y == train_sess[0].y for s in train_sess) or all(
        s.y == test_sess[0].y for s in test_sess
    ):
        print(
            "[train] split has a single-class split — increase data budget",
            file=sys.stderr,
        )
        return 4

    mean, std = fit_aggregate_scaler(train_sess)
    train_sess_n = apply_aggregate_scaler(train_sess, mean, std)
    test_sess_n = apply_aggregate_scaler(test_sess, mean, std)

    args.out.mkdir(parents=True, exist_ok=True)
    np.savez(
        args.out / "norm.npz",
        mean=mean, std=std,
        train_ids=np.array([s.session_id for s in train_sess]),
        test_ids=np.array([s.session_id for s in test_sess]),
    )

    for ablate in (False, True):
        tag = "ml_only" if ablate else "with_hp"
        t0 = time.time()
        model, best_auc, hist = train_head(
            train_sess_n, test_sess_n, ablate_hp=ablate,
            epochs=args.epochs, lr=args.lr, patience=args.patience,
        )
        elapsed = time.time() - t0
        save_checkpoint(
            model, args.out / f"{tag}.pt",
            meta={
                "best_val_pr_auc": best_auc,
                "epochs_trained": len(hist),
                "elapsed_s": elapsed,
            },
        )
        print(
            f"[train] {tag:>8}  best_val_pr_auc={best_auc:.4f}  "
            f"epochs={len(hist)}  {elapsed:.1f}s",
            flush=True,
        )

    summary = {
        "n_sessions": len(sessions),
        "n_train": len(train_sess),
        "n_test": len(test_sess),
        "by_label": counts,
        "train_y_pos": sum(s.y for s in train_sess),
        "test_y_pos": sum(s.y for s in test_sess),
    }
    (args.out / "train_summary.json").write_text(json.dumps(summary, indent=2))
    print("[train] done →", args.out, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
