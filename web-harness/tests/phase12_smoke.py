"""Phase 12 verification gate: crAPI as fourth target.

Structural check (no docker — crAPI's 7 backing services are too heavy
to bring up just for an in-process smoke). Asserts:

  1. docker-compose.yml declares the 7 crAPI services + capture_crapi
     under `profiles: ["crapi"]` and none of them publish ports to the
     host. The loopback-only invariant has to hold for the new target
     too.
  2. target_guard.ALLOWED_HOSTS includes `capture_crapi` and the guard
     accepts http://capture_crapi:8080/.
  3. orchestrator/sweep.py default_config() now produces cells for
     `target_app=crapi` covering both browser and non-browser families
     (crAPI has a React SPA + a JSON API, so BOTH classes are useful).
  4. The sweep's per_cell_census joins correctly when given a synth
     plan that includes crapi cells.

Runs in <1s, no docker, no real generator execution.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile
import time

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

EXPECTED_CRAPI_SERVICES = {
    "crapi", "crapi_identity", "crapi_community", "crapi_workshop",
    "crapi_mongodb", "crapi_postgresdb", "crapi_rabbitmq", "crapi_mailhog",
    "capture_crapi",
}


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _check_compose() -> dict:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    services = compose.get("services") or {}
    for name in EXPECTED_CRAPI_SERVICES:
        _assert(name in services,
                f"[phase12] docker-compose.yml missing service {name!r}")
        svc = services[name]
        _assert("crapi" in (svc.get("profiles") or []),
                f"[phase12] {name} not under profiles:[crapi]: "
                f"{svc.get('profiles')!r}")
        _assert("ports" not in svc,
                f"[phase12] {name} publishes ports — loopback invariant "
                f"broken: {svc.get('ports')!r}")
        nets = svc.get("networks") or []
        _assert("cernis_lab" in nets,
                f"[phase12] {name} not on cernis_lab network: {nets!r}")
    return services


def _check_target_guard() -> None:
    sys.path.insert(0, str(ROOT / "generators" / "shared"))
    from target_guard import ALLOWED_HOSTS, assert_loopback_target  # type: ignore
    _assert("capture_crapi" in ALLOWED_HOSTS,
            f"[phase12] target_guard missing capture_crapi: {sorted(ALLOWED_HOSTS)}")
    url = assert_loopback_target("http://capture_crapi:8080/")
    _assert(url == "http://capture_crapi:8080",
            f"[phase12] target_guard returned {url!r}")
    # An obviously-external host must still be rejected — make sure the
    # crAPI addition didn't accidentally open the allowlist.
    try:
        assert_loopback_target("http://example.com/")
        raise AssertionError("[phase12] target_guard let external host through!")
    except SystemExit:
        pass


def _check_sweep_config() -> None:
    sys.path.insert(0, str(ROOT))
    from orchestrator.sweep import (  # type: ignore
        SweepCell, build_sweep_plan, default_config, per_cell_census,
    )
    plan = build_sweep_plan(default_config())
    targets = {c.target_app for c in plan}
    _assert("crapi" in targets,
            f"[phase12] sweep config missing crapi target: {sorted(targets)}")
    crapi_cells = [c for c in plan if c.target_app == "crapi"]
    _assert(len(crapi_cells) >= 16,
            f"[phase12] expected >=16 crapi cells, got {len(crapi_cells)}")
    families_at_crapi = {c.family for c in crapi_cells}
    # crAPI has both a SPA and a JSON API surface, so browser AND
    # non-browser families should be represented.
    for fam in ("playwright_bot", "sqlmap", "raw_httpx", "ffuf"):
        _assert(fam in families_at_crapi,
                f"[phase12] crapi cells missing family {fam!r}: "
                f"{sorted(families_at_crapi)}")
    # both stealth values
    stealth_vals = {c.stealth for c in crapi_cells}
    _assert(stealth_vals == {True, False},
            f"[phase12] crapi cells missing stealth values: {stealth_vals}")

    # per_cell_census on a synth sessions file
    with tempfile.TemporaryDirectory() as td:
        sess = pathlib.Path(td) / "sessions.jsonl"
        import json
        rows = [
            {"session_id": "s1", "class": "agent", "family": "sqlmap",
             "target_app": "crapi", "security_level": "na", "stealth": False},
            {"session_id": "s2", "class": "agent", "family": "ffuf",
             "target_app": "crapi", "security_level": "na", "stealth": True},
        ]
        with sess.open("w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        synth_plan = [
            SweepCell(target_app="crapi", family="sqlmap",
                      security_level="na", stealth=False,
                      sessions=1, service="sqlmap_bot"),
            SweepCell(target_app="crapi", family="ffuf",
                      security_level="na", stealth=True,
                      sessions=1, service="ffuf_bot"),
            SweepCell(target_app="crapi", family="nonexistent",
                      security_level="na", stealth=False,
                      sessions=1, service="missing"),
        ]
        census = per_cell_census(synth_plan, sess)
        observed = sum(1 for c in census if c["any_provenance_seen"])
        _assert(observed == 2,
                f"[phase12] per_cell_census on crapi: expected 2 matches, "
                f"got {observed}: {census}")


def main() -> None:
    t0 = time.time()
    services = _check_compose()
    print(f"[phase12] docker-compose.yml has all {len(EXPECTED_CRAPI_SERVICES)} "
          f"crapi services under profiles:[crapi], no published ports",
          flush=True)
    _check_target_guard()
    print("[phase12] target_guard accepts capture_crapi, rejects external "
          "hosts as before", flush=True)
    _check_sweep_config()
    print("[phase12] sweep config produces crapi cells across browser + "
          "non-browser families, both stealth values; per_cell_census "
          "joins correctly", flush=True)
    print()
    print(f"PHASE 12 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
