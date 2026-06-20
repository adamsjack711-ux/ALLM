"""Phase-6 verification gate: benign_bot generators + provenance manifest.

Brings up the `benign` profile (5 services share one image) on top of
phase 1's base stack (db + dvwa + capture), waits for each family to
finish at least one session, and verifies:

  - data/sessions.jsonl contains one provenance row per benign family
    with the expected label-schema fields populated.
  - data/requests.jsonl rows from benign sessions carry the new
    label-schema columns (class, family, target_app, security_level,
    stealth).
  - googlebot tripped /robots.txt (the precision-relevant benign
    interaction with the honeypot system).
  - Only 127.0.0.1:8090 is published to the host (no benign service
    leaked a port; loopback-only invariant intact).

The test does NOT exercise the existing phase 1-5 detector — phase 6
adds the negative class plumbing only. Detector-side eval that uses the
new schema lands in phase 7.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
REQ = DATA / "requests.jsonl"
SESS = DATA / "sessions.jsonl"
HON = DATA / "honeypots.jsonl"

EXPECTED_FAMILIES = {
    "googlebot",
    "uptime_monitor",
    "rss_reader",
    "link_unfurler",
    "ci_health_check",
}
SCHEMA_FIELDS = (
    "class", "family", "target_app", "security_level", "stealth",
    "generator", "generator_version", "generator_config_sha",
)
WAIT_BUDGET_S = int(os.environ.get("ALLM_PHASE6_WAIT_S", "180"))


def run(cmd: list[str], check: bool = False) -> int:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=ROOT)
    if check and cp.returncode != 0:
        raise SystemExit(f"failed rc={cp.returncode}: {cmd}")
    return cp.returncode


def _load(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _families_in_sessions() -> set[str]:
    return {r.get("family") for r in _load(SESS) if r.get("family")}


def _published_ports() -> list[str]:
    """Anything published to the host by the compose project.

    Uses `docker compose ps` JSON output and parses the Publishers list.
    """
    cp = subprocess.run(
        ["docker", "compose", "ps", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if cp.returncode != 0:
        # No compose project up — nothing published by us. Smoke shouldn't
        # be the test that decides whether the user remembered to start
        # compose; fall back to lsof on common offending ports.
        return []
    out: list[str] = []
    for line in cp.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        pubs = row.get("Publishers") or []
        for p in pubs:
            host_ip = p.get("URL") or p.get("HostIp") or ""
            host_port = p.get("PublishedPort")
            if host_port:
                out.append(f"{host_ip}:{host_port}")
    return out


def main() -> None:
    t0 = time.time()
    run(["docker", "compose", "--profile", "benign", "up", "-d", "--build"], check=True)

    print(f"[phase6] waiting up to {WAIT_BUDGET_S}s for all 5 families…", flush=True)
    deadline = time.time() + WAIT_BUDGET_S
    seen: set[str] = set()
    while time.time() < deadline:
        seen = _families_in_sessions()
        if EXPECTED_FAMILIES.issubset(seen):
            break
        time.sleep(2)
    missing = EXPECTED_FAMILIES - seen
    assert not missing, (
        f"[phase6] families never registered provenance: {sorted(missing)} "
        f"(saw {sorted(seen)})"
    )

    # sessions.jsonl row shape per family
    sess_rows = _load(SESS)
    by_family: dict[str, dict] = {}
    for r in sess_rows:
        fam = r.get("family")
        if fam in EXPECTED_FAMILIES:
            by_family.setdefault(fam, r)
    for fam, row in by_family.items():
        for f in SCHEMA_FIELDS:
            assert f in row, f"[phase6] {fam} provenance row missing field {f!r}"
        assert row["class"] == "benign_bot", (
            f"[phase6] {fam} class={row['class']!r}, expected 'benign_bot'"
        )
        assert row["target_app"] == "dvwa", (
            f"[phase6] {fam} target_app={row['target_app']!r}, expected 'dvwa'"
        )
        assert re.fullmatch(r"[0-9a-f]{8}", row["generator_config_sha"]), (
            f"[phase6] {fam} generator_config_sha looks wrong: "
            f"{row['generator_config_sha']!r}"
        )

    # requests.jsonl: at least one row per family carrying the schema columns
    req_rows = _load(REQ)
    seen_in_req: set[str] = set()
    for r in req_rows:
        fam = r.get("family")
        if fam not in EXPECTED_FAMILIES:
            continue
        for f in ("class", "family", "target_app", "security_level", "stealth"):
            assert f in r, (
                f"[phase6] requests.jsonl row for {fam} missing schema field {f!r}"
            )
        assert r["class"] == "benign_bot", (
            f"[phase6] requests row for {fam} class={r['class']!r}"
        )
        seen_in_req.add(fam)
    req_missing = EXPECTED_FAMILIES - seen_in_req
    assert not req_missing, (
        f"[phase6] families absent from requests.jsonl: {sorted(req_missing)}"
    )

    # googlebot must have tripped robots_read
    hp_rows = _load(HON)
    robots_tripped_by = {
        r.get("src_label") for r in hp_rows if r.get("honeypot") == "robots_read"
    }
    assert "googlebot" in robots_tripped_by, (
        f"[phase6] googlebot never read /robots.txt — got src_labels "
        f"{sorted(robots_tripped_by)}"
    )

    # loopback invariant: only 127.0.0.1:8090 is published
    published = _published_ports()
    if published:
        bad = [p for p in published if not p.startswith("127.0.0.1:")]
        assert not bad, (
            f"[phase6] published ports leaked beyond loopback: {bad} "
            f"(all published: {published})"
        )
        port_only = {p.rsplit(":", 1)[-1] for p in published}
        assert port_only.issubset({"8090"}), (
            f"[phase6] unexpected published ports: {sorted(port_only)}; "
            f"only 8090 should publish (the human-capture port)"
        )

    print()
    print(f"PHASE 6 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")
    print(f"  benign sessions  : {len(by_family)} families × ≥1 session")
    print(f"  request rows     : {sum(1 for r in req_rows if r.get('class') == 'benign_bot')}")
    print(f"  robots trippers  : {sorted(robots_tripped_by)}")
    print(f"  published ports  : {published or '(none — compose down?)'}")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
