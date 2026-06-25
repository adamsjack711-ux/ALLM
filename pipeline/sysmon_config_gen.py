"""Generate a Sysmon exclusion-stanza XML from `alert_fatigue.json`.

Phase-host-5 + phase-host-6 produce per-EID rankings. This module turns
the top-N EIDs into a deployable Sysmon `<EventFiltering>` block. The
operator still has to deploy it via GPO / config management, but the
"which EIDs to filter" decision is now mechanical.

Ranking source priority:
  1. `deployment_estimates[0].per_eid_cost_benefit` (phase-host-6).
     Sorted by `ranking_score` desc — best trade-off first. Always
     preferred when present.
  2. `deployment_estimates[0].per_eid_contributions` (phase-host-5).
     Sorted by `fp_per_hour` desc — biggest FP-saver first.
  3. Error out with a useful message.

EID → Sysmon RuleGroup tag is a fixed map; only the well-known EIDs
have entries (EID 10 → ProcessAccess, EID 13 → RegistryEvent, etc.).
Unknown EIDs are skipped with a warning so the output is always valid
config XML.

Each EID's exclusion rule body is a small catalog of conservative
defaults adapted from COLLECTOR_TUNING.md §3. The operator should
read the generated file before deploying — these are filter
*candidates*, not final policy.

Output: `data/host/sysmon_cernis_exclusions.xml`. Carries an inline
`<!-- ... -->` comment per rule explaining the EID's ranking score
+ source (cost-benefit vs FP-only) so the operator can audit and
match against the alert_fatigue.json ranking.

NEVER reports accuracy.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Optional


# Map EID → (RuleGroup tag, default exclusion bodies).
# Sourced from COLLECTOR_TUNING.md §3 — these are the conservative
# "drop the noisy default actors" filters, not aggressive policy.
_RULE_CATALOG: dict[int, tuple[str, list[tuple[str, str, str]]]] = {
    # EID 10: ProcessAccess — trusted security tools
    10: ("ProcessAccess", [
        ("TargetImage", "end with", "\\MsMpEng.exe"),
        ("TargetImage", "end with", "\\WmiPrvSE.exe"),
        ("SourceImage", "end with", "\\SearchProtocolHost.exe"),
        ("GrantedAccess", "is", "0x1000"),
        ("GrantedAccess", "is", "0x1400"),
    ]),
    # EID 12 / 13 / 14: RegistryEvent (Object/Value/Rename) — Office +
    # Explorer + Office click-to-run noise
    12: ("RegistryEvent", [
        ("TargetObject", "contains", "\\Software\\Microsoft\\Office\\"),
        ("TargetObject", "contains",
         "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"),
        ("Image", "end with", "\\OfficeClickToRun.exe"),
    ]),
    13: ("RegistryEvent", [
        ("TargetObject", "contains", "\\Software\\Microsoft\\Office\\"),
        ("TargetObject", "contains",
         "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\"),
        ("TargetObject", "end with", "\\MRUListEx"),
        ("Image", "end with", "\\OfficeClickToRun.exe"),
    ]),
    14: ("RegistryEvent", [
        ("TargetObject", "contains", "\\Software\\Microsoft\\Office\\"),
    ]),
    # EID 22: DnsQuery — browser tab spam
    22: ("DnsQuery", [
        ("Image", "end with", "\\chrome.exe"),
        ("Image", "end with", "\\msedge.exe"),
        ("Image", "end with", "\\firefox.exe"),
    ]),
    # EID 23: FileDelete — build-host temp churn
    23: ("FileDelete", [
        ("TargetFilename", "contains", "\\AppData\\Local\\Temp\\"),
    ]),
    # EID 5: ProcessTerminate — usually redundant with EID 1
    5: ("ProcessTerminate", []),  # empty body → drop all
}


_HEADER = (
    "<!--\n"
    "  Cernis-generated Sysmon exclusion stanza.\n"
    "  Source: {source_path}\n"
    "  Ranking source: {ranking_source}\n"
    "  Deployment: {deployment}\n"
    "\n"
    "  This is a STARTING POINT, not final policy. Review every rule\n"
    "  body against the operator's specific environment before deploy.\n"
    "  See pipeline/COLLECTOR_TUNING.md §3 for the rationale behind\n"
    "  the default exclusion bodies.\n"
    "\n"
    "  Generated {top_n} rule groups out of {n_eids_ranked} ranked EIDs.\n"
    "  Skipped EIDs (no rule template): {skipped_eids}\n"
    "-->"
)


def _format_rule_field(field: str, condition: str, value: str) -> str:
    """One Sysmon rule line: `<Field condition="X">VALUE</Field>`."""
    # Escape XML entities in value. Sysmon config is XML so the usual
    # five entities apply.
    escaped = (
        value.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;")
             .replace("'", "&apos;")
    )
    return f'        <{field} condition="{condition}">{escaped}</{field}>'


def _format_rule_group(
    eid: int, ranking_note: str,
) -> Optional[str]:
    """One <RuleGroup>...</RuleGroup> stanza for the given EID. Returns
    None when the EID isn't in `_RULE_CATALOG`."""
    if eid not in _RULE_CATALOG:
        return None
    tag, bodies = _RULE_CATALOG[eid]
    lines = [
        f"    <!-- EID {eid} — {ranking_note} -->",
        f'    <RuleGroup name="cernis-eid-{eid}" groupRelation="or">',
        f'      <{tag} onmatch="exclude">',
    ]
    for field, cond, value in bodies:
        lines.append(_format_rule_field(field, cond, value))
    lines.append(f"      </{tag}>")
    lines.append("    </RuleGroup>")
    return "\n".join(lines)


def _extract_ranking(
    alert_fatigue: dict, deployment_name: Optional[str],
) -> tuple[list[dict], str, dict]:
    """Returns (ranked_rows, ranking_source, deployment_dict). The rows
    each have at least an `eid` key. `ranking_source` is one of
    'cost_benefit' or 'contributions' so the operator can audit which
    table fed the XML."""
    deployments = alert_fatigue.get("deployment_estimates") or []
    if not deployments:
        raise SystemExit(
            "[sysmon_config_gen] alert_fatigue.json has no "
            "deployment_estimates; run pipeline.alert_fatigue first")
    if deployment_name is not None:
        match = [d for d in deployments if d.get("deployment") == deployment_name]
        if not match:
            raise SystemExit(
                f"[sysmon_config_gen] deployment {deployment_name!r} not in "
                f"alert_fatigue.json; available: "
                f"{[d.get('deployment') for d in deployments]}")
        dep = match[0]
    else:
        dep = deployments[0]

    cb = dep.get("per_eid_cost_benefit")
    if cb:
        return list(cb), "cost_benefit", dep
    contribs = dep.get("per_eid_contributions")
    if contribs:
        return list(contribs), "contributions", dep
    raise SystemExit(
        "[sysmon_config_gen] alert_fatigue.json deployment has neither "
        "per_eid_cost_benefit (phase-host-6) nor per_eid_contributions "
        "(phase-host-5). Run pipeline.per_eid_attribution to populate.")


def generate(
    alert_fatigue_path: pathlib.Path, *,
    top_n: int = 5,
    deployment: Optional[str] = None,
) -> str:
    """Read alert_fatigue.json, pick top-N EIDs by ranking, return the
    Sysmon XML stanza as a string.

    `deployment` lets the operator pick which deployment's ranking
    feeds the generation. Different deployments have different
    windows_per_hour, so the cost side of the ranking differs.
    Defaults to the first deployment in the file.
    """
    alert_fatigue = json.loads(alert_fatigue_path.read_text())
    ranked, source, dep = _extract_ranking(alert_fatigue, deployment)

    # Filter to positive ranking only — never recommend filtering
    # an EID with a negative trade-off (filtering would hurt detection
    # more than it helps FPs).
    score_key = (
        "ranking_score" if source == "cost_benefit" else "fp_per_hour"
    )
    positive = [r for r in ranked if (r.get(score_key) or 0) > 0]
    top = positive[:top_n]

    skipped = []
    rule_groups: list[str] = []
    for row in top:
        eid = int(row["eid"])
        if eid not in _RULE_CATALOG:
            skipped.append(eid)
            continue
        if source == "cost_benefit":
            note = (
                f"ranking_score={row.get('ranking_score', 0):+.2f}, "
                f"fp_saved={row.get('fp_per_hour_saved', 0):+.2f}/h, "
                f"recall_lost={row.get('recall_lost', 0):+.4f}"
            )
        else:
            note = (
                f"contribution_to_fp_rate="
                f"{row.get('contribution_to_fp_rate', 0):+.4f}, "
                f"fp_per_hour={row.get('fp_per_hour', 0):+.2f}/h"
            )
        rule_xml = _format_rule_group(eid, note)
        if rule_xml is None:
            skipped.append(eid)
            continue
        rule_groups.append(rule_xml)

    header = _HEADER.format(
        source_path=alert_fatigue_path,
        ranking_source=source,
        deployment=dep.get("deployment", "?"),
        top_n=len(rule_groups),
        n_eids_ranked=len(ranked),
        skipped_eids=skipped or "none",
    )
    # XML comments forbid `--` inside the comment body; phrase the
    # placeholder so the option flag uses single-dash hyphenation
    # ("top_n") rather than the command-line form ("- - top - n").
    body = "\n".join(rule_groups) if rule_groups else (
        "    <!-- No rule groups generated. Either no positive-score "
        "EIDs landed in the top_n, or every top_n EID lacked a rule "
        "template. Tune top_n or check the EID list. -->"
    )
    return (
        f"{header}\n"
        f"<Sysmon schemaversion=\"4.90\">\n"
        f"  <EventFiltering>\n"
        f"{body}\n"
        f"  </EventFiltering>\n"
        f"</Sysmon>\n"
    )


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-fatigue", type=pathlib.Path,
                    default=pathlib.Path("data/host/alert_fatigue.json"))
    ap.add_argument("--top-n", type=int, default=5,
                    help="how many EIDs to include in the output (default 5)")
    ap.add_argument("--deployment", default=None,
                    help="pick a specific deployment's ranking; defaults to "
                         "the first in alert_fatigue.json")
    ap.add_argument("--out", type=pathlib.Path,
                    default=pathlib.Path("data/host/sysmon_cernis_exclusions.xml"))
    args = ap.parse_args(argv)

    xml = generate(
        args.alert_fatigue, top_n=args.top_n, deployment=args.deployment,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(xml)

    n_rule_groups = xml.count("<RuleGroup")
    print(f"\n[sysmon_config_gen] wrote {args.out}")
    print(f"  source           = {args.alert_fatigue}")
    print(f"  deployment       = {args.deployment or '(first)'}")
    print(f"  rule groups      = {n_rule_groups} (of top-{args.top_n} candidates)")
    print()
    print("  Review every rule body before deploying. See "
          "pipeline/COLLECTOR_TUNING.md §3 for the rationale.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
