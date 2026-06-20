"""Phase-7 verification gate: multi-target + 3 new attack generators.

Brings up `multitarget` + `attack-extended` profiles on top of phases
1+6 base stack, waits for the 3 new agent families to register
provenance, and verifies:

  - data/sessions.jsonl now contains rows for sqlmap, selenium_bot,
    puppeteer_bot with class=agent.
  - At least one of the 3 generators ran against a non-DVWA target
    when pointed at one (we sweep configs across DVWA / juice_shop /
    vampi).
  - data/requests.jsonl rows from new agents carry their expected
    family + target_app values.
  - Only 127.0.0.1:8090 is published to the host (the DVWA-capture
    human port). No multi-target capture leaked a port.

The smoke does NOT assert detector PR-AUC — the eval-side rollup that
slices by family / target_app / agent-vs-benign_bot lands in phase 8.
This gate is structural: provenance + label-schema spread + the
loopback invariant.

Wall-clock: building 3 new images (selenium incl chromium, puppeteer
incl chromium, sqlmap incl git-cloned sqlmap repo) plus 3 vulnerable
target containers (Juice Shop / WebGoat / VAmPI) takes a while on a
cold cache. Crank `ALLM_PHASE7_WAIT_S` if your machine is slow.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
REQ = DATA / "requests.jsonl"
SESS = DATA / "sessions.jsonl"

EXPECTED_AGENT_FAMILIES = {"sqlmap", "selenium_bot", "puppeteer_bot"}
SCHEMA_FIELDS = (
    "class", "family", "target_app", "security_level", "stealth",
    "generator", "generator_version", "generator_config_sha",
)
WAIT_BUDGET_S = int(os.environ.get("ALLM_PHASE7_WAIT_S", "600"))

# Targets each generator runs against this sweep. Generators read
# ALLM_TARGET / ALLM_TARGET_APP at container start; we mutate compose
# env per family by passing them via `up`-time overrides.
SWEEP = [
    # (compose_service, ALLM_TARGET, ALLM_TARGET_APP)
    ("sqlmap_bot",    "http://capture:8080",       "dvwa"),
    ("selenium_bot",  "http://capture:8080",       "dvwa"),
    ("puppeteer_bot", "http://capture:8080",       "dvwa"),
    # second pass: one agent at a non-DVWA target so target_app spreads
    ("sqlmap_bot",    "http://capture_vampi:8080", "vampi"),
]


def run(cmd: list[str], check: bool = False, env_extra: dict | None = None) -> int:
    print(f"$ {' '.join(cmd)}", flush=True)
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    cp = subprocess.run(cmd, cwd=ROOT, env=env)
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


def _published_ports() -> list[str]:
    cp = subprocess.run(
        ["docker", "compose", "ps", "--format", "json"],
        cwd=ROOT, capture_output=True, text=True,
    )
    if cp.returncode != 0:
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
        for p in (row.get("Publishers") or []):
            host_port = p.get("PublishedPort")
            host_ip = p.get("URL") or p.get("HostIp") or ""
            if host_port:
                out.append(f"{host_ip}:{host_port}")
    return out


def main() -> None:
    t0 = time.time()

    # bring up vulnerable targets + their captures (build is heavy here)
    run(["docker", "compose", "--profile", "multitarget", "up", "-d", "--build"], check=True)

    # then sweep the new agents. Each `run --rm` invocation runs the
    # generator container with the env override and tears it down.
    for service, target, target_app in SWEEP:
        run(
            ["docker", "compose", "run", "--rm",
             "-e", f"ALLM_TARGET={target}",
             "-e", f"ALLM_TARGET_APP={target_app}",
             "--profile", "attack-extended", service],
            check=False,  # sqlmap exits non-zero on no-injection, fine
        )

    print(f"[phase7] waiting up to {WAIT_BUDGET_S}s for provenance to settle…", flush=True)
    deadline = time.time() + WAIT_BUDGET_S
    seen_fams: set[str] = set()
    while time.time() < deadline:
        sess_rows = _load(SESS)
        seen_fams = {r.get("family") for r in sess_rows if r.get("class") == "agent"}
        if EXPECTED_AGENT_FAMILIES.issubset(seen_fams):
            break
        time.sleep(2)

    missing = EXPECTED_AGENT_FAMILIES - seen_fams
    assert not missing, (
        f"[phase7] agent families never registered provenance: {sorted(missing)} "
        f"(saw {sorted(seen_fams)})"
    )

    sess_rows = _load(SESS)
    by_family: dict[str, dict] = {}
    for r in sess_rows:
        fam = r.get("family")
        if fam in EXPECTED_AGENT_FAMILIES:
            by_family.setdefault(fam, r)
    for fam, row in by_family.items():
        for f in SCHEMA_FIELDS:
            assert f in row, f"[phase7] {fam} provenance row missing field {f!r}"
        assert row["class"] == "agent", f"[phase7] {fam} class={row['class']!r}, expected 'agent'"

    # target_app spread: at least one row with target_app != "dvwa" exists
    req_rows = _load(REQ)
    target_apps_seen = {r.get("target_app") for r in req_rows if r.get("family") in EXPECTED_AGENT_FAMILIES}
    assert "dvwa" in target_apps_seen, f"[phase7] no DVWA-target rows for new agents: {target_apps_seen}"
    non_dvwa = target_apps_seen - {"dvwa", None}
    assert non_dvwa, (
        f"[phase7] no non-DVWA target_app rows from new agents — multi-target sweep didn't reach "
        f"juice_shop/webgoat/vampi. saw: {target_apps_seen}"
    )

    # requests.jsonl rows carry the new schema for each agent family
    seen_in_req: set[str] = set()
    for r in req_rows:
        fam = r.get("family")
        if fam not in EXPECTED_AGENT_FAMILIES:
            continue
        for f in ("class", "family", "target_app", "security_level", "stealth"):
            assert f in r, f"[phase7] requests.jsonl row for {fam} missing schema field {f!r}"
        assert r["class"] == "agent", f"[phase7] requests row for {fam} class={r['class']!r}"
        seen_in_req.add(fam)
    req_missing = EXPECTED_AGENT_FAMILIES - seen_in_req
    assert not req_missing, (
        f"[phase7] new agent families absent from requests.jsonl: {sorted(req_missing)}"
    )

    # loopback invariant
    published = _published_ports()
    if published:
        bad = [p for p in published if not p.startswith("127.0.0.1:")]
        assert not bad, f"[phase7] published ports leaked beyond loopback: {bad}"
        port_only = {p.rsplit(":", 1)[-1] for p in published}
        assert port_only.issubset({"8090"}), (
            f"[phase7] unexpected published ports: {sorted(port_only)}; "
            "only 8090 (DVWA human-capture) should publish"
        )

    print()
    print(f"PHASE 7 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")
    print(f"  new agent families: {sorted(seen_fams & EXPECTED_AGENT_FAMILIES)}")
    print(f"  target_app spread : {sorted(target_apps_seen)}")
    print(f"  published ports   : {published or '(none — compose down?)'}")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
