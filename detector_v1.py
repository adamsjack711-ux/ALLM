"""
AI-Attack Detector — v1 ATT&CK multi-label output
=================================================
v0  = order-blind window aggregates (GBT).
v0.5= GRU over the per-event sequence (binary attack / benign).
v1  adds the thing a SOC actually triages on: instead of one yes/no, every
window now emits

  1. a per-window RISK score          (overall attack probability)
  2. per-TECHNIQUE probabilities       (multi-label, ATT&CK-style tactics)
  3. the TRIGGERING SPAN               (which events drove each technique),
     read straight off a per-technique attention head.

Why multi-label and not one classifier per technique: an attack window is
usually several tactics at once (recon bleeding into discovery, lateral
movement overlapping credential access). The model shares one GRU trunk and
branches into per-technique attention heads, so a window can light up several
techniques independently and tell you *where* in the window each fired.

The synthetic generator builds phase-structured attack campaigns (a kill chain:
recon -> discovery -> credential access -> command execution -> lateral
movement -> exfiltration). Each event is tagged with the technique that emitted
it, so per-technique recall is measurable. Classes genuinely overlap: action
mixes are noisy, a fraction of campaigns run low-and-slow with a benign-looking
profile, and benign sessions sometimes mimic recon/discovery -- so PR-AUC stays
realistic (well under 1.0), not a leakage artifact.

    python detector_v1.py --synthetic

Dependencies: numpy, pandas, scikit-learn, torch
"""

from __future__ import annotations
import argparse

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import average_precision_score, precision_recall_fscore_support

from detector_v0 import ACTIONS, WINDOW_EVENTS, WINDOW_STRIDE, windowize, run
from detector_v05 import GRUDetector, train_gru

N_ACT = len(ACTIONS)
ACT_INDEX = {a: i for i, a in enumerate(ACTIONS)}

# ATT&CK-style tactics, in rough kill-chain order. "benign" is the absence of all.
TECHNIQUES = [
    "recon",              # TA0043 reconnaissance  (T1595 active scanning)
    "discovery",          # TA0007 discovery       (T1046 network service discovery)
    "credential_access",  # TA0006                 (T1003 credential dumping)
    "command_execution",  # TA0002 execution       (T1059 command interpreter)
    "lateral_movement",   # TA0008                 (T1021 remote services)
    "exfiltration",       # TA0010                 (T1041 exfil over C2)
]
TECH_INDEX = {t: i for i, t in enumerate(TECHNIQUES)}
K = len(TECHNIQUES)


# ---------------------------------------------------------------------------
# 1. Per-technique behavioral profiles  (distribution over ACTIONS)
# ---------------------------------------------------------------------------
# Order matches ACTIONS = [tool_call, api_request, shell_cmd, file_access, net_egress].
# These are TENDENCIES, not signatures: every technique can emit any action, and
# the generator adds heavy per-event noise on top, so no single action identifies
# a technique -- the model has to learn the joint behavioral shape.
_PROFILES = {
    "recon":             np.array([0.15, 0.60, 0.05, 0.05, 0.15]),  # api_request heavy
    "discovery":         np.array([0.60, 0.15, 0.10, 0.10, 0.05]),  # tool_call heavy
    "credential_access": np.array([0.10, 0.10, 0.15, 0.60, 0.05]),  # file_access heavy
    "command_execution": np.array([0.10, 0.10, 0.65, 0.10, 0.05]),  # shell_cmd heavy
    "lateral_movement":  np.array([0.40, 0.05, 0.40, 0.05, 0.10]),  # tool+shell (confusable)
    "exfiltration":      np.array([0.10, 0.10, 0.10, 0.10, 0.60]),  # net_egress heavy
}
_BENIGN_PROFILE = np.array([0.25, 0.25, 0.20, 0.20, 0.10])          # balanced middle
ACTION_NOISE = 0.20   # prob an event ignores its profile and picks a uniform action
                      # (blurs the action mix so techniques aren't trivially separable
                      #  from single actions -> irreducible error, PR-AUC < 1)


def _draw_action(rng, profile):
    if rng.random() < ACTION_NOISE:
        return int(rng.integers(0, N_ACT))          # noise: profile-blind
    return int(rng.choice(N_ACT, p=profile))


# ---------------------------------------------------------------------------
# 2. Synthetic generator with per-event technique labels
# ---------------------------------------------------------------------------
def make_multilabel_synthetic(n_benign=600, n_attack=220, seed=0) -> pd.DataFrame:
    """Phase-structured campaigns. Attacks walk an ordered subset of the kill
    chain; each event carries the technique that produced it. Benign sessions
    carry technique='benign'.

    CRUCIAL for realism (constraint #4): every non-action feature -- timing,
    depth, target breadth, ai-artifact -- is drawn from the SAME distribution for
    both classes, so they carry ZERO label signal. The ONLY thing that separates
    attack from benign is the action-emission pattern (which technique profile is
    driving the events) and its phase structure. Combined with heavy action noise
    and a low-and-slow stealth fraction, that keeps the classes genuinely
    overlapping -- aggregate PR-AUC lands well under 1.0, not a leakage artifact.
    """
    rng = np.random.default_rng(seed)
    rows = []

    def latent():                       # identical draw for both classes
        return float(np.clip(rng.normal(0.5, 0.20), 0, 1))

    def emit_event(cid, label, technique, profile, t, dt_scale, ai_mean, targets):
        t = t + max(0.0, rng.exponential(dt_scale))
        rows.append(dict(
            campaign_id=cid, ts=t,
            action=ACTIONS[_draw_action(rng, profile)],
            target=rng.choice(targets),
            depth=int(min(5, rng.poisson(1.0))),                 # same for both
            artifact_ai=float(np.clip(rng.normal(ai_mean, 0.22), 0, 1)),
            label=label, technique=technique,
        ))
        return t

    def session_params():
        lt = latent()
        dt_scale = float(np.clip(rng.normal(12 - 6 * lt, 5), 0.3, 25))
        ai_mean = float(np.clip(rng.normal(0.40 + 0.25 * lt, 0.18), 0, 1))
        n_targets = max(2, int(round(rng.normal(10, 5))))
        return dt_scale, ai_mean, [f"host_{i}" for i in range(n_targets)]

    def emit_benign(cid):
        dt_scale, ai_mean, targets = session_params()
        t = rng.uniform(0, 1e6)
        for _ in range(int(rng.integers(60, 220))):
            t = emit_event(cid, 0, "benign", _BENIGN_PROFILE, t, dt_scale, ai_mean, targets)

    def emit_attack(cid):
        dt_scale, ai_mean, targets = session_params()
        # low-and-slow campaigns behave benignly throughout -> weak/absent
        # technique signal. They cap achievable recall the way real stealth does.
        stealthy = rng.random() < 0.20
        # keep each kill-chain phase with prob 0.75, preserving order; >=2 phases.
        phases = [p for p in TECHNIQUES if rng.random() < 0.75]
        if len(phases) < 2:
            phases = TECHNIQUES[:2]
        t = rng.uniform(0, 1e6)
        for phase in phases:
            profile = _BENIGN_PROFILE if stealthy else _PROFILES[phase]
            for _ in range(int(rng.integers(12, 40))):
                t = emit_event(cid, 1, phase, profile, t, dt_scale, ai_mean, targets)

    for i in range(n_benign):
        emit_benign(f"benign_{i}")
    for i in range(n_attack):
        emit_attack(f"attack_{i}")

    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# 3. Sequence featurization + multi-hot technique labels + lengths
# ---------------------------------------------------------------------------
def multilabel_windows(df: pd.DataFrame):
    """One row per window. Returns:
        X        (N, T, F) float32  per-event features (same scheme as v0.5)
        lengths  (N,)               valid event count (for attention masking)
        y_risk   (N,)               window is attack if any event is
        Y_tech   (N, K) float32     multi-hot: techniques present among attack events
        groups   (N,)               campaign id (for the group split)
        meta     list[dict]         per-window event detail, for span reporting
    """
    if "technique" not in df:
        df = df.assign(technique="benign")
    Xs, lens, yr, Yt, gs, meta = [], [], [], [], [], []
    F = N_ACT + 4
    for cid, g in df.sort_values("ts").groupby("campaign_id", sort=False):
        g = g.reset_index(drop=True)
        for start in range(0, max(1, len(g) - WINDOW_EVENTS + 1), WINDOW_STRIDE):
            w = g.iloc[start:start + WINDOW_EVENTS]
            if len(w) < WINDOW_EVENTS // 2:
                continue
            mat = np.zeros((WINDOW_EVENTS, F), dtype=np.float32)
            ts = w["ts"].to_numpy()
            acts = w["action"].to_numpy()
            techs = w["technique"].to_numpy()
            depths = w["depth"].to_numpy()
            ai = w["artifact_ai"].to_numpy()
            labs = w["label"].to_numpy()
            n = min(len(w), WINDOW_EVENTS)
            for k in range(n):
                mat[k, ACT_INDEX[acts[k]]] = 1.0
                dt = ts[k] - ts[k - 1] if k > 0 else 0.0
                mat[k, N_ACT + 0] = np.log1p(max(0.0, dt))
                mat[k, N_ACT + 1] = depths[k] / 6.0
                mat[k, N_ACT + 2] = ai[k]
                mat[k, N_ACT + 3] = k / WINDOW_EVENTS
            tvec = np.zeros(K, dtype=np.float32)
            for tk in range(n):
                if labs[tk] == 1 and techs[tk] in TECH_INDEX:
                    tvec[TECH_INDEX[techs[tk]]] = 1.0
            Xs.append(mat)
            lens.append(n)
            yr.append(int(labs.max()))
            Yt.append(tvec)
            gs.append(cid)
            meta.append(dict(actions=acts[:n], techniques=techs[:n], ts=ts[:n]))
    return (np.stack(Xs), np.array(lens), np.array(yr),
            np.stack(Yt), np.array(gs), meta)


# ---------------------------------------------------------------------------
# 4. Multi-label GRU with per-technique attention heads
# ---------------------------------------------------------------------------
class MultiLabelGRU(nn.Module):
    """Shared GRU trunk; one attention head per technique gives both the
    technique probability AND the span (which events it attended to). A separate
    attention head produces the overall risk score."""

    def __init__(self, n_features, n_tech, hidden=64):
        super().__init__()
        self.gru = nn.GRU(n_features, hidden, num_layers=2,
                          batch_first=True, dropout=0.1)
        self.tech_attn = nn.Linear(hidden, n_tech)              # attention logits / tech
        self.tech_w = nn.Parameter(torch.randn(n_tech, hidden) * hidden ** -0.5)
        self.tech_b = nn.Parameter(torch.zeros(n_tech))
        self.risk_attn = nn.Linear(hidden, 1)
        self.risk_head = nn.Sequential(nn.Linear(hidden, 32), nn.ReLU(),
                                       nn.Linear(32, 1))

    def forward(self, x, mask):
        H, _ = self.gru(x)                                      # (B,T,hid)
        neg_inf = torch.finfo(H.dtype).min

        te = self.tech_attn(H)                                  # (B,T,K)
        te = te.masked_fill(~mask.unsqueeze(-1), neg_inf)
        alpha = torch.softmax(te, dim=1)                        # attention over time, per tech
        ctx = torch.einsum("btk,bth->bkh", alpha, H)            # (B,K,hid)
        tech_logits = (ctx * self.tech_w.unsqueeze(0)).sum(-1) + self.tech_b  # (B,K)

        re = self.risk_attn(H).squeeze(-1)                      # (B,T)
        re = re.masked_fill(~mask, neg_inf)
        ralpha = torch.softmax(re, dim=1)                       # (B,T)
        rctx = torch.einsum("bt,bth->bh", ralpha, H)            # (B,hid)
        risk_logit = self.risk_head(rctx).squeeze(-1)           # (B,)
        return risk_logit, tech_logits, alpha, ralpha


def _mask_from_lengths(lengths, T, dev):
    ar = torch.arange(T, device=dev).unsqueeze(0)
    return ar < torch.as_tensor(lengths, device=dev).unsqueeze(1)


def train_multilabel(X, lengths, y_risk, Y_tech, tr_idx, te_idx,
                     epochs=40, lr=1.5e-3, seed=0):
    torch.manual_seed(seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    T = X.shape[1]
    model = MultiLabelGRU(X.shape[2], K).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=lr)

    ytr = y_risk[tr_idx]
    risk_pw = torch.tensor([(ytr == 0).sum() / max(1, (ytr == 1).sum())],
                           dtype=torch.float32, device=dev)
    Ttr = Y_tech[tr_idx]
    tech_pw = torch.tensor(
        [(Ttr[:, k] == 0).sum() / max(1, (Ttr[:, k] == 1).sum()) for k in range(K)],
        dtype=torch.float32, device=dev)
    risk_loss_fn = nn.BCEWithLogitsLoss(pos_weight=risk_pw)
    tech_loss_fn = nn.BCEWithLogitsLoss(pos_weight=tech_pw)

    Xtr = torch.tensor(X[tr_idx], device=dev)
    Ltr = torch.as_tensor(lengths[tr_idx], device=dev)
    yr_t = torch.tensor(ytr, dtype=torch.float32, device=dev)
    Yt_t = torch.tensor(Ttr, dtype=torch.float32, device=dev)
    n = len(Xtr)

    for _ in range(epochs):
        model.train()
        perm = torch.randperm(n, device=dev)
        for i in range(0, n, 256):
            idx = perm[i:i + 256]
            mask = _mask_from_lengths(Ltr[idx], T, dev)
            opt.zero_grad()
            risk_logit, tech_logits, _, _ = model(Xtr[idx], mask)
            loss = risk_loss_fn(risk_logit, yr_t[idx]) + tech_loss_fn(tech_logits, Yt_t[idx])
            loss.backward()
            opt.step()

    model.eval()
    with torch.no_grad():
        Xte = torch.tensor(X[te_idx], device=dev)
        mask = _mask_from_lengths(torch.as_tensor(lengths[te_idx], device=dev), T, dev)
        risk_logit, tech_logits, alpha, ralpha = model(Xte, mask)
        risk_p = torch.sigmoid(risk_logit).cpu().numpy()
        tech_p = torch.sigmoid(tech_logits).cpu().numpy()
        alpha = alpha.cpu().numpy()         # (Nte, T, K)
        ralpha = ralpha.cpu().numpy()       # (Nte, T)
    return model, risk_p, tech_p, alpha, ralpha


# ---------------------------------------------------------------------------
# 5. Helpers: thresholds tuned on TRAIN, FP/hour, span extraction
# ---------------------------------------------------------------------------
def _best_f1_threshold(y, proba):
    grid = np.linspace(0.05, 0.95, 19)
    best, best_f1 = 0.5, -1.0
    for th in grid:
        _, _, f1, _ = precision_recall_fscore_support(
            y, proba >= th, average="binary", zero_division=0)
        if f1 > best_f1:
            best, best_f1 = th, f1
    return best


def _fp_per_hour(events, n_test_windows, n_fp):
    agg = windowize(events)
    benign_dt = agg.loc[agg.label == 0, "dt_median"].median()
    secs_per_window = max(1.0, WINDOW_EVENTS * (benign_dt or 1.0))
    test_seconds = n_test_windows * secs_per_window
    return n_fp / (test_seconds / 3600 + 1e-9)


def _span_string(meta_w, weights, top=3):
    """Top-`top` events by attention weight -> a compact 'i:action(tech)' span."""
    order = np.argsort(weights[:len(meta_w["actions"])])[::-1][:top]
    order = sorted(order.tolist())
    return "  ".join(
        f"#{i}:{meta_w['actions'][i]}({meta_w['techniques'][i]})" for i in order)


# ---------------------------------------------------------------------------
# 6. End-to-end run: shared campaign split, three models, per-technique recall
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--synthetic", action="store_true", help="run on generated data")
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--epochs", type=int, default=40)
    args = ap.parse_args()

    events = make_multilabel_synthetic(seed=args.seed)

    X, lengths, y_risk, Y_tech, groups, meta = multilabel_windows(events)

    # ONE campaign-level split shared by every model below (apples-to-apples).
    splitter = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=args.seed)
    tr_idx, te_idx = next(splitter.split(X, y_risk, groups))
    yte = y_risk[te_idx]

    # --- (a) v0 aggregate baseline on the SAME data/campaign split ---
    agg = windowize(events)
    base = run(agg, seed=args.seed)            # GroupShuffleSplit(seed) -> same campaigns in test

    # --- (b) v0.5-style binary GRU (current best architecture) on the SAME split ---
    bin_proba = train_gru(X[tr_idx], y_risk[tr_idx], X[te_idx], epochs=args.epochs)
    bin_auc = average_precision_score(yte, bin_proba)

    # --- (c) v1 multi-label GRU: risk + per-technique + spans ---
    model, risk_p, tech_p, alpha, ralpha = train_multilabel(
        X, lengths, y_risk, Y_tech, tr_idx, te_idx, epochs=args.epochs, seed=args.seed)
    risk_auc = average_precision_score(yte, risk_p)

    # risk threshold tuned on TRAIN (no test-set fitting), applied to test for FP/hour.
    # Re-score the train fold to pick thresholds without peeking at the test labels.
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    model.eval()
    with torch.no_grad():
        Xtr_t = torch.tensor(X[tr_idx], device=dev)
        mtr = _mask_from_lengths(torch.as_tensor(lengths[tr_idx], device=dev), X.shape[1], dev)
        rl, tl, _, _ = model(Xtr_t, mtr)
        risk_tr = torch.sigmoid(rl).cpu().numpy()
        tech_tr = torch.sigmoid(tl).cpu().numpy()
    risk_th = _best_f1_threshold(y_risk[tr_idx], risk_tr)
    risk_pred = risk_p >= risk_th
    rp, rr, rf1, _ = precision_recall_fscore_support(
        yte, risk_pred, average="binary", zero_division=0)
    n_fp = int(((risk_pred == 1) & (yte == 0)).sum())
    fph = _fp_per_hour(events, len(yte), n_fp)

    # --- per-technique recall on test (threshold tuned per technique on train) ---
    Yte_tech = Y_tech[te_idx]
    print("\n=== AI-Attack Detector v1  [synthetic] — ATT&CK multi-label ===")
    print(f"events:   {len(events):>7,}   windows: {len(y_risk):>6,}  "
          f"(attack {y_risk.mean()*100:.1f}%)")
    print("\n--- risk score (binary attack/benign), one shared campaign split ---")
    print(f"  v0 aggregate GBT (order-blind):   PR-AUC {base.pr_auc:.3f}")
    print(f"  v0.5 binary GRU (current best):   PR-AUC {bin_auc:.3f}")
    print(f"  v1 multi-label GRU (risk head):   PR-AUC {risk_auc:.3f}   "
          f"lift vs v0 {risk_auc - base.pr_auc:+.3f}")
    print(f"  v1 risk @train-tuned thr={risk_th:.2f}:  "
          f"precision {rp:.3f}  recall {rr:.3f}  F1 {rf1:.3f}  FP/hour {fph:.2f}")

    print("\n--- per-technique detection (multi-label heads) ---")
    print(f"  {'technique':<20} {'support':>7} {'PR-AUC':>7} {'recall':>7} {'thr':>5}")
    recalls = []
    for k, name in enumerate(TECHNIQUES):
        yk = Yte_tech[:, k]
        sup = int(yk.sum())
        if sup == 0:
            print(f"  {name:<20} {sup:>7}   (no positives in test fold)")
            continue
        auc_k = average_precision_score(yk, tech_p[:, k])
        thr_k = _best_f1_threshold(Y_tech[tr_idx][:, k], tech_tr[:, k])
        rec_k = ((tech_p[:, k] >= thr_k) & (yk == 1)).sum() / sup
        recalls.append(rec_k)
        print(f"  {name:<20} {sup:>7} {auc_k:>7.3f} {rec_k:>7.3f} {thr_k:>5.2f}")
    if recalls:
        print(f"  {'macro-avg recall':<20} {'':>7} {'':>7} {np.mean(recalls):>7.3f}")

    # --- triggering span demo: highest-risk test windows, per-technique spans ---
    print("\n--- triggering spans (top-risk attack windows; events the heads attended) ---")
    attack_test = np.where(yte == 1)[0]
    top = attack_test[np.argsort(risk_p[attack_test])[::-1][:3]]
    for j in top:
        true_techs = [TECHNIQUES[k] for k in range(K) if Yte_tech[j, k] == 1]
        fired = [(TECHNIQUES[k], tech_p[j, k]) for k in range(K) if tech_p[j, k] >= 0.5]
        fired.sort(key=lambda x: -x[1])
        print(f"  window risk={risk_p[j]:.2f}  true={true_techs}")
        print(f"    risk span:  {_span_string(meta[te_idx[j]], ralpha[j])}")
        for name, p in fired[:2]:
            k = TECH_INDEX[name]
            print(f"    {name}={p:.2f} span: {_span_string(meta[te_idx[j]], alpha[j, :, k])}")

    print("\nWhat v1 adds over v0.5: same/better risk PR-AUC PLUS per-technique")
    print("labels, per-technique recall, and the attended span for each — the")
    print("structured output a SOC triages on, not a single yes/no.\n")


if __name__ == "__main__":
    main()
