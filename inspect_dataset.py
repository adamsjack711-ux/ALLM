"""
AI-Attack Detector — dataset adapter helper
===========================================
Profiles a real dataset and suggests how to map its columns onto the detector's
normalized schema, so filling in `adapt_real_dataframe()` in detector_v0.py
becomes a fill-in-the-blanks job instead of guesswork.

What it does:
  1. loads a HuggingFace dataset id OR a local file (.csv/.parquet/.json/.jsonl)
  2. profiles every column: dtype, cardinality, sample values
  3. heuristically guesses which column maps to each normalized field
  4. prints a ready-to-paste `rename` dict for adapt_real_dataframe()

Usage:
    python inspect_dataset.py --data <hf_id_or_path>
    python inspect_dataset.py --demo        # runs on a generated foreign-schema file

The guesses are SUGGESTIONS. Always eyeball the sample values before trusting them.

Dependencies: pandas, numpy  (datasets only for HuggingFace ids)
"""

from __future__ import annotations
import argparse
import re
import numpy as np
import pandas as pd

# normalized fields the detector needs. (required?, name-regex hints)
FIELDS = {
    "campaign_id": (True,  r"campaign|trace|session|run|episode|incident|group|conversation|.*_id$|^id$"),
    "ts":          (True,  r"time|timestamp|^ts$|date|epoch|start|when"),
    "action":      (True,  r"action|event|span|operation|^op$|method|verb|activity|tool|call|kind"),
    "target":      (True,  r"target|host|resource|endpoint|dst|destination|url|path|asset|object"),
    "label":       (True,  r"label|malicious|attack|threat|^y$|class|benign|is_?bad|ground_?truth"),
    "depth":       (False, r"depth|pivot|hop|level|tier|stage"),
    "artifact_ai": (False, r"ai|artifact|generated|llm|synthetic|gen_?score|model_?score"),
}


# ---------------------------------------------------------------------------
# loading
# ---------------------------------------------------------------------------
def load_any(path_or_id: str) -> pd.DataFrame:
    low = path_or_id.lower()
    if low.endswith(".csv"):
        return pd.read_csv(path_or_id)
    if low.endswith(".parquet"):
        return pd.read_parquet(path_or_id)
    if low.endswith((".json", ".jsonl")):
        return pd.read_json(path_or_id, lines=low.endswith(".jsonl"))
    # otherwise assume a HuggingFace dataset id
    try:
        from datasets import load_dataset
    except ImportError as e:
        raise SystemExit(
            "Install the HF loader (pip install datasets --break-system-packages) "
            "or point --data at a local .csv/.parquet/.json file."
        ) from e
    ds = load_dataset(path_or_id, split="train")
    return ds.to_pandas()


# ---------------------------------------------------------------------------
# profiling
# ---------------------------------------------------------------------------
def profile(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    n = len(df)
    for c in df.columns:
        s = df[c]
        nun = s.nunique(dropna=True)
        sample = ", ".join(map(lambda x: str(x)[:22], s.dropna().unique()[:3]))
        rows.append(dict(
            column=c,
            dtype=str(s.dtype),
            cardinality=nun,
            card_ratio=round(nun / max(1, n), 3),
            n_missing=int(s.isna().sum()),
            sample=sample,
        ))
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# heuristic mapping  (name match + light value signals)
# ---------------------------------------------------------------------------
def _value_signal(field: str, s: pd.Series, n: int) -> float:
    """Small bonus from a column's values matching what a field should look like."""
    try:
        nun = s.nunique(dropna=True)
        if field == "label":
            vals = set(pd.unique(s.dropna()))
            if nun == 2:                                   # binary-ish
                return 1.5 if vals <= {0, 1, True, False, "0", "1"} else 0.8
            return -1.0
        if field == "ts":
            return 1.0 if pd.api.types.is_numeric_dtype(s) and s.max() > 1e6 else 0.0
        if field == "campaign_id":
            return 0.8 if 0.0 < nun / n < 0.5 else 0.0     # repeats -> groupable
        if field == "action":
            return 0.6 if 2 <= nun <= 50 and pd.api.types.is_string_dtype(s) else 0.0
        if field == "target":
            return 0.5 if nun > 10 and pd.api.types.is_string_dtype(s) else 0.0
        if field == "depth":
            return 0.6 if pd.api.types.is_integer_dtype(s) and s.max() < 50 else 0.0
        if field == "artifact_ai":
            return 0.6 if pd.api.types.is_float_dtype(s) and 0 <= s.min() and s.max() <= 1 else 0.0
    except Exception:
        return 0.0
    return 0.0


def suggest_mapping(df: pd.DataFrame):
    n = len(df)
    used = set()
    suggestions = {}
    for field, (required, hint) in FIELDS.items():
        best, best_score = None, 0.0
        for c in df.columns:
            if c in used:
                continue
            name_score = 2.0 if re.search(hint, c, re.I) else 0.0
            score = name_score + _value_signal(field, df[c], n)
            if score > best_score:
                best, best_score = c, score
        if best is not None and best_score > 0:
            suggestions[field] = (best, round(best_score, 2))
            used.add(best)
        else:
            suggestions[field] = (None, 0.0)
    return suggestions


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
def report(df: pd.DataFrame):
    print(f"\nrows: {len(df):,}   columns: {len(df.columns)}\n")
    print("--- column profile ---")
    with pd.option_context("display.max_colwidth", 26, "display.width", 120):
        print(profile(df).to_string(index=False))

    sugg = suggest_mapping(df)
    print("\n--- suggested field mapping (confidence) ---")
    for field, (col, score) in sugg.items():
        req = "required" if FIELDS[field][0] else "optional"
        flag = "" if col else "  <-- NOT FOUND, set manually" if FIELDS[field][0] else "  (optional, skip if absent)"
        conf = "high" if score >= 2.5 else "low " if score > 0 else "none"
        print(f"  {field:<12} [{req:<8}] <- {str(col):<22} ({conf}){flag}")

    print("\n--- paste into adapt_real_dataframe() ---")
    print("    rename = {")
    for field, (col, _) in sugg.items():
        if col:
            print(f'        {col!r:<24}: {field!r},')
    print("    }")
    missing = [f for f, (c, _) in sugg.items() if c is None and FIELDS[f][0]]
    if missing:
        print(f"\n  WARNING: required field(s) unmatched -> {missing}. "
              f"Inspect the profile above and add them by hand.")
    print()


# ---------------------------------------------------------------------------
# demo: fabricate a "real" dataset with FOREIGN column names to prove it works
# ---------------------------------------------------------------------------
def make_demo_file(path="demo_foreign.csv", seed=0):
    rng = np.random.default_rng(seed)
    n = 4000
    df = pd.DataFrame({
        "trace_uuid":  rng.choice([f"sess-{i}" for i in range(120)], n),
        "event_epoch": np.sort(rng.uniform(1.7e9, 1.7e9 + 5e5, n)),
        "span_name":   rng.choice(["recon", "auth", "lateral", "exfil", "noop"], n),
        "dst_host":    rng.choice([f"10.0.0.{i}" for i in range(60)], n),
        "pivot_level": rng.integers(0, 6, n),
        "llm_score":   rng.random(n).round(3),
        "is_malicious": rng.integers(0, 2, n),
        "notes":       rng.choice(["", "auto", "manual"], n),   # decoy column
    })
    df.to_csv(path, index=False)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=str, help="HF dataset id or local file path")
    ap.add_argument("--demo", action="store_true", help="run on a fabricated foreign-schema file")
    args = ap.parse_args()

    if args.demo:
        path = make_demo_file()
        print(f"[demo] wrote {path} with deliberately foreign column names")
        df = load_any(path)
    elif args.data:
        df = load_any(args.data)
    else:
        ap.error("pass --data <id_or_path> or --demo")
    report(df)


if __name__ == "__main__":
    main()
