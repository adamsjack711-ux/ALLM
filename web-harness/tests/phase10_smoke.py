"""Phase 10 verification gate.

Two additions to assert:
  1. detector/heldout.py grows `per_family_stealth_holdout` — for each
     agent family with both stealth=true AND stealth=false sessions,
     train without the stealth=true sessions, eval recall on them,
     compare to in-distribution stealth=false recall on the same family.
  2. orchestrator/sweep.py composes the plan + report builders. Smoke
     can't run the docker iteration, but it can:
       a. Verify default_config() produces a non-empty plan that covers
          multiple target_apps × families × stealth values.
       b. Synth-feed the data + a hand-crafted plan that matches it,
          then assert per_cell_census joins correctly and
          build_sweep_report writes the expected blocks.

Runs in a tmpdir, no docker. ~10s wall-clock (train + eval + heldout
on a small synth dataset).
"""

from __future__ import annotations

import json
import pathlib
import random
import subprocess
import sys
import tempfile
import time

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
DETECTOR_DIR = ROOT / "detector"


# Family / stealth matrix. Phase 9's synth shape — adapted so every
# agent family has BOTH stealth values present, which is what
# per_family_stealth_holdout requires.
FAMILIES = [
    # (family, klass, target_app, stealth, n_sessions)
    ("playwright_bot", "agent",      "dvwa",       False, 9),
    ("playwright_bot", "agent",      "dvwa",       True,  6),
    ("sqlmap",         "agent",      "dvwa",       False, 6),
    ("sqlmap",         "agent",      "dvwa",       True,  5),
    ("selenium_bot",   "agent",      "juice_shop", False, 5),
    ("googlebot",      "benign_bot", "dvwa",       False, 6),
    ("uptime_monitor", "benign_bot", "dvwa",       False, 5),
    ("rss_reader",     "benign_bot", "dvwa",       False, 5),
    ("human_sim",      "human",      "dvwa",       False, 7),
]


def _synthesize(out_dir: pathlib.Path, seed: int = 0) -> dict:
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    req_lines: list[dict] = []
    sess_lines: list[dict] = []
    hp_lines: list[dict] = []
    beacon_lines: list[dict] = []
    t_base = time.time() - 7200
    sid_counter = 1

    for family, klass, target_app, stealth, n_sessions in FAMILIES:
        is_agent = klass == "agent"
        for idx in range(n_sessions):
            sid = f"sid-{sid_counter:04d}-{family[:4]}-{'st' if stealth else 'fa'}"
            sid_counter += 1
            if stealth:
                base_delta_ms = rng.uniform(800, 1800)
                n_req = rng.randint(8, 30)
            elif is_agent:
                base_delta_ms = rng.uniform(40, 200)
                n_req = rng.randint(20, 60)
            elif klass == "benign_bot":
                base_delta_ms = rng.uniform(800, 1800)
                n_req = rng.randint(5, 25)
            else:
                base_delta_ms = rng.uniform(1500, 3500)
                n_req = rng.randint(6, 18)
            ts = t_base + idx * 30
            prev = None
            for i in range(n_req):
                delta = (None if prev is None
                         else int(max(1, np_rng.normal(base_delta_ms, base_delta_ms * 0.3))))
                ts = ts + (delta or 0) / 1000.0
                status = (
                    rng.choices([200, 302, 404, 500],
                                weights=[0.55, 0.2, 0.20, 0.05])[0]
                    if is_agent and not stealth else
                    rng.choices([200, 302, 404], weights=[0.85, 0.1, 0.05])[0]
                )
                method = "POST" if is_agent and rng.random() < 0.35 else "GET"
                req_lines.append({
                    "ts": ts, "session_id": sid,
                    "src_ip": "172.18.0.99", "src_label": family,
                    "method": method,
                    "path": rng.choice(["/", "/login.php",
                                        "/vulnerabilities/sqli/",
                                        "/vulnerabilities/xss_r/",
                                        "/about.php", "/instructions.php"]),
                    "qs_len": rng.randint(0, 60) if is_agent else rng.randint(0, 10),
                    "status": status,
                    "req_bytes": rng.randint(100, 800),
                    "resp_bytes": rng.randint(500, 5000),
                    "ua": "Mozilla/5.0 (compatible; testbot/1.0)",
                    "header_hash": f"{rng.randint(0, 0xfffffff):08x}",
                    "header_count": rng.randint(6, 12),
                    "delta_ms": delta,
                    "is_new_session": i == 0,
                    "has_auth_header": False,
                    "has_cookie_header": i > 0,
                    "content_type": "text/html",
                    "elapsed_ms": rng.randint(2, 60),
                    "class": klass, "family": family,
                    "target_app": target_app, "security_level": "low",
                    "stealth": stealth,
                })
                prev = delta
            sess_lines.append({
                "ts": ts, "session_id": sid, "src_label": family,
                "class": klass, "family": family,
                "target_app": target_app, "security_level": "low",
                "stealth": stealth,
                "generator": family, "generator_version": "0.2.0",
                "generator_config_sha": f"{rng.randint(0, 0xffffffff):08x}",
                "extra": {},
            })
            if family == "googlebot":
                hp_lines.append({
                    "ts": ts, "session_id": sid, "src_label": family,
                    "honeypot": "robots_read", "evidence": {"ua": "Googlebot"},
                })
            if is_agent and not stealth and rng.random() < 0.55:
                hp_lines.append({
                    "ts": ts + 1.0, "session_id": sid, "src_label": family,
                    "honeypot": "canary",
                    "evidence": {"qs": "ack=1", "ref": ""},
                })
            if family in ("playwright_bot", "selenium_bot", "human_sim", "googlebot"):
                beacon_lines.append({
                    "ts": ts + 0.1, "session_id": sid,
                    "src_ip": "172.18.0.99", "src_label": family,
                    "ua": "Mozilla/5.0",
                    "event": {"type": "ready", "t": 100.0},
                })

    def _dump(p: pathlib.Path, rows: list[dict]) -> None:
        with p.open("w") as f:
            for row in rows:
                f.write(json.dumps(row, separators=(",", ":")) + "\n")

    _dump(out_dir / "requests.jsonl",  req_lines)
    _dump(out_dir / "sessions.jsonl",  sess_lines)
    _dump(out_dir / "honeypots.jsonl", hp_lines)
    _dump(out_dir / "beacons.jsonl",   beacon_lines)
    return {
        "n_sessions": len(sess_lines),
        "n_requests": len(req_lines),
    }


def _run(cmd: list[str], cwd: pathlib.Path) -> subprocess.CompletedProcess:
    print(f"$ {' '.join(cmd)}", flush=True)
    cp = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if cp.returncode != 0:
        print(f"  stdout:\n{cp.stdout}\n  stderr:\n{cp.stderr}", flush=True)
    return cp


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    t0 = time.time()

    # 1. default_config() shape check (pure Python, no synth needed)
    sys.path.insert(0, str(ROOT))
    from orchestrator.sweep import (  # type: ignore
        SweepCell, build_sweep_plan, build_sweep_report,
        default_config, per_cell_census,
    )
    config = default_config()
    plan = build_sweep_plan(config)
    _assert(len(plan) > 10,
            f"[phase10] default sweep plan too small: {len(plan)} cells")
    targets = {c.target_app for c in plan}
    _assert({"dvwa", "juice_shop", "vampi"} <= targets,
            f"[phase10] default plan missing targets: {targets}")
    stealth_vals = {c.stealth for c in plan}
    _assert({True, False} == stealth_vals,
            f"[phase10] default plan missing stealth values: {stealth_vals}")
    families = {c.family for c in plan}
    _assert(len(families) >= 4,
            f"[phase10] default plan too few families: {families}")
    # vampi should be sqlmap-only (no DOM)
    vampi_families = {c.family for c in plan if c.target_app == "vampi"}
    _assert(vampi_families == {"sqlmap"},
            f"[phase10] vampi cells should be sqlmap-only, got {vampi_families}")
    print(f"[phase10] default_config: {len(plan)} cells, targets={sorted(targets)}, "
          f"families={sorted(families)}", flush=True)

    with tempfile.TemporaryDirectory() as td:
        data_dir = pathlib.Path(td) / "data"
        meta = _synthesize(data_dir)
        print(f"[phase10] synthesized: {meta}", flush=True)

        # 2. heldout per_family_stealth_holdout
        sys.path.insert(0, str(DETECTOR_DIR))
        from features import build_sessions  # type: ignore
        sessions = build_sessions(data_dir, min_requests=3)

        # train first (heldout reuses the training pipeline)
        models_dir = data_dir / "models"
        cp = _run([sys.executable, str(DETECTOR_DIR / "train.py"),
                   "--data", str(data_dir),
                   "--out", str(models_dir),
                   "--epochs", "60", "--patience", "8"], cwd=ROOT)
        _assert(cp.returncode == 0, "[phase10] train.py failed")

        heldout_out = data_dir / "reports" / "heldout.json"
        cp = _run([sys.executable, str(DETECTOR_DIR / "heldout.py"),
                   "--data", str(data_dir),
                   "--out", str(heldout_out),
                   "--fp-per-hour-budget", "1.0"], cwd=ROOT)
        _assert(cp.returncode == 0, "[phase10] heldout.py failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[phase10] heldout stdout mentions accuracy")

        heldout = json.loads(heldout_out.read_text())
        _assert("per_family_stealth_holdout" in heldout,
                "[phase10] heldout missing per_family_stealth_holdout")
        psh = heldout["per_family_stealth_holdout"]
        _assert(psh, "[phase10] per_family_stealth_holdout empty")

        # at least one family with both stealth values must have run
        ran = [(f, v) for f, v in psh.items() if "skipped" not in v]
        _assert(ran,
                f"[phase10] no per_family_stealth_holdout entries ran: {psh}")
        for fam, v in ran:
            for key in ("in_dist_nonstealth_recall", "heldout_stealth_recall",
                        "heldout_ratio", "stealth_evades_detector",
                        "n_train_sessions", "n_holdout_sessions"):
                _assert(key in v,
                        f"[phase10] {fam} per_family_stealth_holdout missing {key!r}")
        _assert("accuracy" not in json.dumps(heldout).lower(),
                "[phase10] heldout JSON mentions accuracy")

        # 3. per_cell_census joins correctly on the synth plan
        synth_plan = [
            SweepCell(target_app="dvwa", family="playwright_bot",
                      security_level="low", stealth=False,
                      sessions=2, service="playwright_bot"),
            SweepCell(target_app="dvwa", family="playwright_bot",
                      security_level="low", stealth=True,
                      sessions=2, service="playwright_bot_stealth"),
            SweepCell(target_app="dvwa", family="sqlmap",
                      security_level="low", stealth=False,
                      sessions=2, service="sqlmap_bot"),
            SweepCell(target_app="juice_shop", family="selenium_bot",
                      security_level="low", stealth=False,
                      sessions=2, service="selenium_bot"),
            SweepCell(target_app="dvwa", family="nonexistent_bot",
                      security_level="low", stealth=False,
                      sessions=2, service="nonexistent"),
        ]
        census = per_cell_census(synth_plan, data_dir / "sessions.jsonl")
        _assert(len(census) == len(synth_plan),
                f"[phase10] census length mismatch: {len(census)}")
        # the four cells matching our synth should all have data;
        # the nonexistent one should not
        matched_count = sum(1 for c in census if c["any_provenance_seen"])
        _assert(matched_count == 4,
                f"[phase10] expected 4 matched census cells, got {matched_count}: "
                f"{[(c['family'], c['stealth'], c['sessions_observed']) for c in census]}")

        # 4. build_sweep_report end-to-end on synth data (no docker)
        report = build_sweep_report(
            data_dir, synth_plan,
            fp_per_hour_budget=1.0,
            detector_dir=DETECTOR_DIR,
        )
        for key in ("summary", "per_cell_census", "eval", "heldout"):
            _assert(key in report, f"[phase10] sweep report missing {key!r}")
        _assert("per_family_stealth_holdout" in report["heldout"],
                "[phase10] sweep report heldout missing per_family_stealth_holdout")
        _assert("per_stealth" in report["eval"]["with_hp"],
                "[phase10] sweep report eval missing per_stealth")
        _assert("accuracy" not in json.dumps(report).lower(),
                "[phase10] sweep report JSON mentions accuracy")

    print()
    print(f"PHASE 10 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
