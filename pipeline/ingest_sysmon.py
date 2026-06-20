"""Load a Sysmon dump (JSONL preferred) and adapt to the v0/v1 schema.

We accept three layouts seen in the wild:
  - JSONL: one event per line, fields per Sysmon XML or OTRF normalized.
  - CSV / Parquet: tabular dumps (typically OTRF Security-Datasets).
  - JSON array: list of events.

Whatever the input shape, the output is the same normalized DataFrame
that `adapter_winlogs.adapt_winlog_dataframe` produces, so downstream
windowization and detector code see one schema.
"""

from __future__ import annotations

import json
import pathlib
from typing import Optional

import pandas as pd


def load_sysmon(path: pathlib.Path) -> pd.DataFrame:
    suffix = path.suffix.lower()
    if suffix in (".jsonl", ".ndjson"):
        rows: list[dict] = []
        with path.open() as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return pd.DataFrame(rows)
    if suffix == ".json":
        data = json.loads(path.read_text())
        if isinstance(data, dict) and "events" in data:
            data = data["events"]
        return pd.DataFrame(data)
    if suffix == ".csv":
        return pd.read_csv(path)
    if suffix in (".parquet", ".pq"):
        return pd.read_parquet(path)
    raise ValueError(f"unsupported sysmon dump extension: {suffix!r}")


def normalize(
    sysmon_df: pd.DataFrame,
    malicious_guids: Optional[set] = None,
    *,
    campaign_id: Optional[str] = None,
) -> pd.DataFrame:
    """Sysmon DataFrame -> v0 normalized schema.

    If `campaign_id` is given, every row's `campaign_id` is overridden
    to that value. This is the right behavior when scoring a single
    operation (you know which campaign it belongs to; the adapter's
    default of "use the host name" would split it across hosts).
    """
    from adapter_winlogs import adapt_winlog_dataframe

    out = adapt_winlog_dataframe(sysmon_df, malicious_guids=malicious_guids)
    if campaign_id is not None:
        out["campaign_id"] = str(campaign_id)
    return out
