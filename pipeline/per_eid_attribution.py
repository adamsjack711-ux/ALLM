"""Per-EID FP attribution at window granularity (phase-host-5).

The `pipeline.alert_fatigue` arithmetic gives you total normal-workload
FP/hour at a fitted threshold τ. `pipeline.calibrate_eventrate` tells
you which EIDs dominate event volume. Combining the two has been an
approximation (`COLLECTOR_TUNING.md §4`):

    fp_per_hour_X ≈ share_X × p_w(normal) × W_total

This phase replaces that with two real measurements:

  1. **Dropout attribution** — for each EID in the normal-workload
     campaign, filter its events out, re-windowize, re-score with the
     same trained classifier at the same τ, measure the *delta* in
     per-window FP rate:
         contribution_X = FP_rate(all) − FP_rate(all \ {X})
     A positive contribution means EID X is responsible for that many
     percentage points of the realized FP rate. Negative contributions
     are possible (rare — filtering an EID can occasionally make
     detection worse by removing context); we keep them in the output
     rather than clamp so the operator sees the real number.

  2. **Per-window EID composition** — for every scored window, record
     the dominant EID + the EID-share vector. Bucket windows by
     dominant EID and compute FP rate per bucket. Surfaces "windows
     where EID 10 is the majority fire at X% FP rate" as a concrete
     signal independent of the dropout view.

The two views are complementary: dropout is marginal-effect, composition
is descriptive. An operator typically ranks EIDs by dropout (which
filter to invest in first) and validates the rank against composition
(do the high-dropout EIDs also have high-FP buckets?).

Inputs:
  - `data/host/manifest.jsonl` — produced by `pipeline.score_campaign`.
    Must contain ≥1 attack + ≥1 normal campaign so the classifier has
    both classes.
  - `data/host/<workload_campaign_id>/sysmon.jsonl` — the campaign to
    attribute. Typically a `class=normal` workload capture.

Output: `data/host/per_eid_attribution.json` carrying:
  - `target_campaign_id` + the threshold + the classifier seed
  - `full_fp_rate` + `n_windows` baseline
  - `per_eid` — one row per distinct EID in the target campaign
    (eid, n_events, share_events, n_windows_dropout, fp_rate_dropout,
    contribution_to_fp_rate)
  - `per_window_composition` — bucketed view (dominant_eid → n_windows
    + fp_rate)

NEVER reports accuracy.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Optional

import numpy as np
import pandas as pd

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pipeline import alert_fatigue as af  # noqa: E402
from pipeline import ingest_sysmon, provenance_host, score_campaign  # noqa: E402
from adapter_winlogs import EVENTID_FIELDS  # noqa: E402


# ----------------------------------------------------------------------
# EID column helpers
# ----------------------------------------------------------------------


def _pick_col(df: pd.DataFrame, candidates: list[str]) -> Optional[str]:
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _attach_eid_to_normalized(
    raw_sysmon_df: pd.DataFrame, norm_df: pd.DataFrame,
) -> pd.DataFrame:
    """Join the raw EID column onto the normalized DataFrame by row
    index. `ingest_sysmon.normalize` preserves the source index, so
    a `reindex(norm_df.index)` recovers each row's EID.

    Rows whose EID can't be coerced to int (NaN / non-numeric) get
    `EventID = -1` so the dropout loop's `df.EventID != X` filter
    still includes them under every X (they don't belong to any
    bucket)."""
    eid_col = _pick_col(raw_sysmon_df, EVENTID_FIELDS)
    if eid_col is None:
        raise SystemExit(
            f"[per_eid_attribution] could not find EventID column in "
            f"sysmon dump; expected one of {EVENTID_FIELDS}"
        )
    out = norm_df.copy()
    eids = pd.to_numeric(
        raw_sysmon_df[eid_col].reindex(norm_df.index), errors="coerce",
    ).fillna(-1).astype(int)
    out["EventID"] = eids.values
    return out


# ----------------------------------------------------------------------
# Train classifier on the manifest's train partition
# ----------------------------------------------------------------------


def _train_classifier_from_manifest(
    data_root: pathlib.Path,
    seed: int,
    fp_per_hour_budget: float,
    train_frac: float,
) -> dict:
    """Replicates `alert_fatigue.run`'s train-side: load every
    campaign in the manifest, normalize + windowize, stratified split,
    train HistGradientBoostingClassifier, pick τ at the FP budget.

    Returns a dict with the trained classifier + feature columns + τ +
    benign_dt_median for the rate-conversion.
    """
    manifest = provenance_host.load(data_root / "manifest.jsonl")
    if not manifest:
        raise SystemExit(
            f"[per_eid_attribution] manifest empty at {data_root}/manifest.jsonl"
        )
    windows_by_cid: dict[str, pd.DataFrame] = {}
    meta_by_cid: dict[str, dict] = {r["campaign_id"]: r for r in manifest}
    for row in manifest:
        cid = row["campaign_id"]
        norm = af._campaign_normalized(cid, data_root)
        if norm is None or norm.empty:
            continue
        norm = norm.copy()
        norm["label"] = norm.groupby("campaign_id")["label"].transform("max")
        windows = af._windowize_with_tactic(norm)
        if not windows.empty:
            windows_by_cid[cid] = windows
    if not windows_by_cid:
        raise SystemExit("[per_eid_attribution] no windows from any campaign")

    rng = np.random.default_rng(seed)
    cid_list = sorted(windows_by_cid)
    by_bucket: dict[tuple, list[str]] = {}
    for cid in cid_list:
        m = meta_by_cid[cid]
        bucket = (m.get("class"), m.get("framework"), m.get("benign_subtype", ""))
        by_bucket.setdefault(bucket, []).append(cid)
    train_cids: list[str] = []
    eval_cids: list[str] = []
    for bucket, cids in by_bucket.items():
        cids = list(cids)
        rng.shuffle(cids)
        if len(cids) == 1:
            train_cids.append(cids[0])
            continue
        cut = max(1, int(train_frac * len(cids)))
        cut = min(cut, len(cids) - 1)
        train_cids.extend(cids[:cut])
        eval_cids.extend(cids[cut:])
    if not eval_cids:
        eval_cids = list(train_cids)

    train_windows = pd.concat(
        [windows_by_cid[c] for c in train_cids], ignore_index=True,
    )
    eval_windows = pd.concat(
        [windows_by_cid[c] for c in eval_cids], ignore_index=True,
    )

    feat_cols = [c for c in train_windows.columns
                 if c not in ("campaign_id", "label", "tactic")]
    Xtr = train_windows[feat_cols].to_numpy()
    ytr = train_windows["label"].to_numpy()
    Xev = eval_windows[feat_cols].to_numpy()
    yev = eval_windows["label"].to_numpy()
    if ytr.sum() == 0 or (ytr == 0).sum() == 0:
        raise SystemExit(
            "[per_eid_attribution] train set is single-class — manifest "
            "needs ≥1 attack + ≥1 benign campaign in the TRAIN partition")
    from sklearn.ensemble import HistGradientBoostingClassifier
    pos = ytr.mean()
    sample_w = np.where(ytr == 1, (1 - pos) / pos, 1.0) if 0 < pos < 1 else None
    clf = HistGradientBoostingClassifier(
        max_iter=300, learning_rate=0.06, max_depth=6,
        l2_regularization=1.0, random_state=seed,
    )
    clf.fit(Xtr, ytr, sample_weight=sample_w)

    benign_dt_median = float(
        train_windows.loc[train_windows.label == 0, "dt_median"].median() or 1.0
    )
    eval_scores = clf.predict_proba(Xev)[:, 1]
    benign_eval_count = int((yev == 0).sum())
    tau = af._pick_tau_for_fp_budget(
        eval_scores, yev, benign_eval_count, benign_dt_median, fp_per_hour_budget,
    )
    return {
        "classifier": clf,
        "feat_cols": feat_cols,
        "tau": tau,
        "benign_dt_median": benign_dt_median,
        "train_cids": train_cids,
        "eval_cids": eval_cids,
    }


# ----------------------------------------------------------------------
# Dropout attribution
# ----------------------------------------------------------------------


def _score_windows(windows: pd.DataFrame, clf, feat_cols: list[str]) -> np.ndarray:
    if windows.empty:
        return np.array([], dtype=float)
    X = windows[feat_cols].to_numpy()
    return clf.predict_proba(X)[:, 1]


def compute_per_eid_dropout(
    campaign_id: str, data_root: pathlib.Path,
    trained: dict,
) -> dict:
    """For each EID in `campaign_id`'s sysmon dump, drop those events,
    re-windowize + re-score, measure the FP-rate delta vs the full
    campaign at the trained τ. Returns the structured per-EID block."""
    sysmon_path = data_root / campaign_id / "sysmon.jsonl"
    if not sysmon_path.exists():
        raise SystemExit(f"[per_eid_attribution] missing {sysmon_path}")

    raw = ingest_sysmon.load_sysmon(sysmon_path)
    eid_col = _pick_col(raw, EVENTID_FIELDS)
    if eid_col is None:
        raise SystemExit(
            f"[per_eid_attribution] no EID column in {sysmon_path}")

    # Baseline (full campaign) score
    norm_full = ingest_sysmon.normalize(raw, campaign_id=campaign_id)
    norm_full = norm_full.copy()
    norm_full["label"] = 0  # workload campaign — all benign
    windows_full = af._windowize_with_tactic(norm_full)
    if windows_full.empty:
        raise SystemExit(
            f"[per_eid_attribution] {campaign_id} produced 0 windows — "
            f"campaign is too small for per-EID attribution")
    scores_full = _score_windows(
        windows_full, trained["classifier"], trained["feat_cols"],
    )
    fp_rate_full = float((scores_full >= trained["tau"]).mean())
    total_events = int(len(raw))

    eids = pd.to_numeric(raw[eid_col], errors="coerce").dropna().astype(int)
    distinct = sorted(eids.unique().tolist())

    per_eid: list[dict] = []
    for eid in distinct:
        mask_keep = pd.to_numeric(raw[eid_col], errors="coerce") != eid
        # Keep rows where EID is NaN too (they don't belong to any
        # specific EID bucket, so they survive every dropout).
        mask_keep = mask_keep | pd.to_numeric(
            raw[eid_col], errors="coerce").isna()
        dropout_raw = raw[mask_keep]
        n_dropped = total_events - len(dropout_raw)
        if dropout_raw.empty:
            per_eid.append({
                "eid": int(eid),
                "n_events_dropped": int(n_dropped),
                "share_events": float(n_dropped / max(total_events, 1)),
                "n_windows_dropout": 0,
                "fp_rate_dropout": None,
                "contribution_to_fp_rate": None,
                "note": "campaign empty after dropout",
            })
            continue
        norm_drop = ingest_sysmon.normalize(dropout_raw, campaign_id=campaign_id)
        norm_drop = norm_drop.copy()
        norm_drop["label"] = 0
        windows_drop = af._windowize_with_tactic(norm_drop)
        if windows_drop.empty:
            per_eid.append({
                "eid": int(eid),
                "n_events_dropped": int(n_dropped),
                "share_events": float(n_dropped / max(total_events, 1)),
                "n_windows_dropout": 0,
                "fp_rate_dropout": None,
                "contribution_to_fp_rate": None,
                "note": "no windows after dropout",
            })
            continue
        scores_drop = _score_windows(
            windows_drop, trained["classifier"], trained["feat_cols"],
        )
        fp_rate_drop = float((scores_drop >= trained["tau"]).mean())
        per_eid.append({
            "eid": int(eid),
            "n_events_dropped": int(n_dropped),
            "share_events": float(n_dropped / max(total_events, 1)),
            "n_windows_dropout": int(len(windows_drop)),
            "fp_rate_dropout": fp_rate_drop,
            "contribution_to_fp_rate": float(fp_rate_full - fp_rate_drop),
        })

    return {
        "target_campaign_id": campaign_id,
        "total_events": total_events,
        "n_distinct_eids": len(distinct),
        "n_windows_full": int(len(windows_full)),
        "fp_rate_full": fp_rate_full,
        "per_eid": per_eid,
    }


# ----------------------------------------------------------------------
# Per-window EID composition
# ----------------------------------------------------------------------


def compute_window_eid_composition(
    campaign_id: str, data_root: pathlib.Path,
    trained: dict,
) -> dict:
    """For each window in the target campaign, compute the dominant EID
    + EID-share vector. Bucket windows by dominant EID and compute FP
    rate per bucket.

    Reuses the same windowization step as detector_v0 (and therefore
    the same windows alert_fatigue scores), then walks the source
    events independently to attach EID composition. The dominant-EID
    bucket is the window's plurality EID; ties are broken by lowest
    numeric EID for determinism.
    """
    from detector_v0 import WINDOW_EVENTS, WINDOW_STRIDE

    sysmon_path = data_root / campaign_id / "sysmon.jsonl"
    raw = ingest_sysmon.load_sysmon(sysmon_path)
    norm = ingest_sysmon.normalize(raw, campaign_id=campaign_id)
    norm = _attach_eid_to_normalized(raw, norm)
    norm = norm.copy()
    norm["label"] = 0

    # Same windowization order: groupby(campaign_id) over sorted ts.
    windows = af._windowize_with_tactic(norm)
    if windows.empty:
        return {
            "target_campaign_id": campaign_id,
            "n_windows": 0,
            "by_dominant_eid": {},
        }
    scores = _score_windows(windows, trained["classifier"], trained["feat_cols"])
    flagged = scores >= trained["tau"]

    # Walk the source events with the same slicing logic to capture
    # per-window EID composition. detector_v0.windowize() filters out
    # tail windows with < WINDOW_EVENTS // 2 events — we mirror that
    # here so window indices align with `windows`.
    composition_rows: list[dict] = []
    norm_sorted = norm.sort_values("ts")
    for cid, g in norm_sorted.groupby("campaign_id", sort=False):
        g = g.reset_index(drop=True)
        for start in range(0, max(1, len(g) - WINDOW_EVENTS + 1), WINDOW_STRIDE):
            w = g.iloc[start:start + WINDOW_EVENTS]
            if len(w) < WINDOW_EVENTS // 2:
                continue
            eids = w["EventID"].astype(int)
            counts = eids.value_counts().to_dict()
            # Tie-break: pick the lowest EID with the max count.
            max_count = max(counts.values()) if counts else 0
            dominant = min(int(e) for e, c in counts.items() if c == max_count) \
                if max_count else -1
            composition_rows.append({
                "dominant_eid": dominant,
                "share_dominant": float(max_count / len(w)),
                "n_distinct_eids_in_window": len({int(e) for e in counts if e != -1}),
            })

    if len(composition_rows) != len(windows):
        # Defensive: the loops should produce the same number of
        # windows. If they don't, surface the mismatch in the JSON
        # so the operator can debug, but don't crash the report.
        return {
            "target_campaign_id": campaign_id,
            "n_windows": int(len(windows)),
            "n_composition_rows": len(composition_rows),
            "by_dominant_eid": {},
            "error": "window-count mismatch between scored windows + "
                     "composition walk; investigate",
        }

    by_eid: dict[int, dict] = {}
    for i, row in enumerate(composition_rows):
        eid = row["dominant_eid"]
        cell = by_eid.setdefault(eid, {
            "n_windows": 0,
            "n_flagged": 0,
            "mean_share_dominant": 0.0,
        })
        cell["n_windows"] += 1
        cell["n_flagged"] += int(flagged[i])
        cell["mean_share_dominant"] += row["share_dominant"]

    out_by_eid: dict[str, dict] = {}
    for eid, cell in by_eid.items():
        n = cell["n_windows"]
        out_by_eid[str(eid)] = {
            "n_windows": n,
            "n_flagged": cell["n_flagged"],
            "fp_rate": float(cell["n_flagged"] / n) if n else 0.0,
            "mean_share_dominant": float(cell["mean_share_dominant"] / n)
                                   if n else 0.0,
        }
    return {
        "target_campaign_id": campaign_id,
        "n_windows": int(len(windows)),
        "by_dominant_eid": out_by_eid,
    }


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------


def run(
    data_root: pathlib.Path, campaign_id: str,
    *, fp_per_hour_budget: float, seed: int, train_frac: float = 0.75,
) -> dict:
    trained = _train_classifier_from_manifest(
        data_root, seed=seed,
        fp_per_hour_budget=fp_per_hour_budget,
        train_frac=train_frac,
    )
    dropout = compute_per_eid_dropout(campaign_id, data_root, trained)
    composition = compute_window_eid_composition(campaign_id, data_root, trained)
    return {
        "target_campaign_id": campaign_id,
        "fp_per_hour_budget": fp_per_hour_budget,
        "threshold": float(trained["tau"]),
        "seed": seed,
        "train_campaigns": trained["train_cids"],
        "eval_campaigns": trained["eval_cids"],
        "dropout_attribution": dropout,
        "window_composition": composition,
    }


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-root", type=pathlib.Path,
                    default=pathlib.Path("data/host"))
    ap.add_argument("--campaign", required=True,
                    help="campaign_id of the normal-workload capture to attribute")
    ap.add_argument("--fp-budget", type=float, default=1.0)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--train-frac", type=float, default=0.75)
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host/per_eid_attribution.json"))
    args = ap.parse_args(argv)

    report = run(
        args.data_root, args.campaign,
        fp_per_hour_budget=args.fp_budget,
        seed=args.seed, train_frac=args.train_frac,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2))

    drop = report["dropout_attribution"]
    print(f"\n[per_eid_attribution] wrote {args.out}")
    print(f"  campaign        = {args.campaign}")
    print(f"  threshold τ     = {report['threshold']:.3f}")
    print(f"  full FP rate    = {drop['fp_rate_full']:.4f} "
          f"({drop['n_windows_full']} windows)")
    print(f"  distinct EIDs   = {drop['n_distinct_eids']}")
    print()
    print("  per-EID dropout (sorted by |contribution| desc):")
    rows = sorted(
        drop["per_eid"],
        key=lambda r: abs(r.get("contribution_to_fp_rate") or 0),
        reverse=True,
    )
    for r in rows:
        contrib = r.get("contribution_to_fp_rate")
        contrib_s = f"{contrib:+.4f}" if contrib is not None else "n/a"
        share = r.get("share_events", 0.0)
        print(f"    EID {r['eid']:>4}  share={share*100:5.1f}%  "
              f"fp_drop={r.get('fp_rate_dropout', None)}  "
              f"contribution={contrib_s}")
    comp = report["window_composition"]
    by_dom = comp.get("by_dominant_eid") or {}
    if by_dom:
        print()
        print("  per-dominant-EID window buckets:")
        for eid in sorted(by_dom, key=lambda k: -by_dom[k]["n_windows"])[:6]:
            cell = by_dom[eid]
            print(f"    dom EID {eid:>4}  n_windows={cell['n_windows']:<4} "
                  f"fp_rate={cell['fp_rate']:.3f}  "
                  f"mean_share={cell['mean_share_dominant']:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
