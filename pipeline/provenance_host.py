"""Per-campaign provenance manifest for the host pipeline.

One row per campaign in data/host/manifest.jsonl. Mirrors the
web-harness/data/sessions.jsonl design (same idea: write the labels
once when the campaign is registered, never depend on tail-end joins
to recover what the generator was). The host pipeline's group key is
`campaign_id`, not `session_id`.

Schema:
  ts                     : unix seconds when the row was written
  campaign_id            : group key
  ts_start, ts_end       : earliest / latest event in this campaign
  class                  : attack | normal | hard_negative
  generator              : caldera | atomic | scripted | manual
  generator_version      : "" or a known version string / git sha
  caldera_adversary      : adversary profile name (empty for atomic/normal)
  caldera_op_id          : CALDERA operation id (empty otherwise)
  abilities              : list of ability ids run (empty for normal)
  tactic_coverage        : list[str] of tactics this campaign covered
  host_list              : list[str] of hosts participating
  config_sha             : 8-hex hash of the campaign config
  sysmon_config_sha      : 8-hex hash of the Sysmon config XML, if known
  source_path            : relative path under data/host/ where the
                           raw inputs live
  notes                  : free-form
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import pathlib
import time
from typing import Optional


MANIFEST = pathlib.Path("data/host/manifest.jsonl")


def config_sha(cfg: dict) -> str:
    blob = json.dumps(cfg, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.blake2b(blob, digest_size=4).hexdigest()


@dataclasses.dataclass
class CampaignManifest:
    campaign_id: str
    klass: str  # "attack" | "normal" | "hard_negative"
    generator: str  # "caldera" | "atomic" | "scripted" | "manual"
    ts_start: float
    ts_end: float
    generator_version: str = ""
    caldera_adversary: str = ""
    caldera_op_id: str = ""
    abilities: tuple[str, ...] = ()
    tactic_coverage: tuple[str, ...] = ()
    host_list: tuple[str, ...] = ()
    sysmon_config_sha: str = ""
    source_path: str = ""
    notes: str = ""
    extra: dict = dataclasses.field(default_factory=dict)

    def to_row(self) -> dict:
        cfg = {
            "generator": self.generator,
            "version": self.generator_version,
            "adversary": self.caldera_adversary,
            "abilities": list(self.abilities),
            "sysmon_config_sha": self.sysmon_config_sha,
        }
        return {
            "ts": time.time(),
            "campaign_id": self.campaign_id,
            "ts_start": self.ts_start,
            "ts_end": self.ts_end,
            "class": self.klass,
            "generator": self.generator,
            "generator_version": self.generator_version,
            "caldera_adversary": self.caldera_adversary,
            "caldera_op_id": self.caldera_op_id,
            "abilities": list(self.abilities),
            "tactic_coverage": list(self.tactic_coverage),
            "host_list": list(self.host_list),
            "config_sha": config_sha(cfg),
            "sysmon_config_sha": self.sysmon_config_sha,
            "source_path": self.source_path,
            "notes": self.notes,
            "extra": self.extra,
        }


def append(manifest: CampaignManifest, path: Optional[pathlib.Path] = None) -> None:
    p = path or MANIFEST
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps(manifest.to_row(), separators=(",", ":")) + "\n")


def load(path: Optional[pathlib.Path] = None) -> list[dict]:
    p = path or MANIFEST
    if not p.exists():
        return []
    out: list[dict] = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
