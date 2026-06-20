"""Phase 9 verification gate: detector eval surfaces the stealth axis.

Synthesizes a multi-family JSONL dataset that INCLUDES stealth=true
twins of the agent families, runs train + eval, and asserts:

  - features.build_sessions resolves stealth from the sessions.jsonl
    provenance row.
  - eval JSON contains, on both with_hp and ml_only heads:
      * per_stealth with at least one of {"true", "false"} present
      * per_family_stealth with cells keyed family::stealth=true
        and family::stealth=false for at least one agent family
  - "accuracy" never appears in any output.

Runs in a tmpdir, no docker. Builds on the phase 8 synth shape.
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


FAMILIES = [
    # (family, klass, target_app, stealth, n_sessions)
    ("playwright_bot", "agent",      "dvwa",       False, 8),
    ("playwright_bot", "agent",      "dvwa",       True,  5),  # stealth twin
    ("sqlmap",         "agent",      "dvwa",       False, 5),
    ("sqlmap",         "agent",      "dvwa",       True,  4),  # stealth twin
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
    next_sid = [1]

    def write_session(family: str, klass: str, target_app: str,
                      stealth: bool, sid: str, idx: int) -> None:
        is_agent = klass == "agent"
        # Stealth shifts the cadence distribution toward humanlike: slower
        # deltas, lower 4xx rate, sparser requests. The detector should
        # still be able to learn this isn't human (other features carry
        # signal) but stealth shouldn't be free.
        if stealth:
            base_delta_ms = rng.uniform(800, 1800)
            n_req = rng.randint(8, 30)
        elif is_agent:
            base_delta_ms = rng.uniform(40, 200)
            n_req = rng.randint(20, 60)
        elif klass == "benign_bot":
            base_delta_ms = rng.uniform(800, 1800)
            n_req = rng.randint(5, 25)
        else:  # human
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
                            weights=([0.55, 0.2, 0.20, 0.05] if not stealth
                                     else [0.7, 0.18, 0.10, 0.02]))[0]
                if is_agent else
                rng.choices([200, 302, 404], weights=[0.85, 0.1, 0.05])[0]
            )
            method = "POST" if is_agent and rng.random() < 0.35 else "GET"
            path_suffix = rng.choice([
                "/", "/login.php", "/vulnerabilities/sqli/",
                "/vulnerabilities/xss_r/", "/about.php",
                "/instructions.php", "/feed", "/robots.txt", "/security.php",
            ])
            req_lines.append({
                "ts": ts, "session_id": sid,
                "src_ip": "172.18.0.99",
                "src_label": family,
                "method": method, "path": path_suffix,
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
        # honeypot trips — stealth bots avoid these by design, so they
        # don't trip canary even though their non-stealth twins do.
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
        # one beacon per browser session
        if family in ("playwright_bot", "selenium_bot", "human_sim", "googlebot"):
            beacon_lines.append({
                "ts": ts + 0.1, "session_id": sid,
                "src_ip": "172.18.0.99", "src_label": family,
                "ua": "Mozilla/5.0",
                "event": {"type": "ready", "t": 100.0},
            })

    for fam, klass, target_app, stealth, n_sessions in FAMILIES:
        for i in range(n_sessions):
            sid = f"sid-{next_sid[0]:04d}-{fam[:4]}-{'st' if stealth else 'fa'}"
            next_sid[0] += 1
            write_session(fam, klass, target_app, stealth, sid, i)

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
        "families_with_stealth": sorted(
            {f"{r['family']}::stealth={r['stealth']}" for r in sess_lines}
        ),
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
    with tempfile.TemporaryDirectory() as td:
        data_dir = pathlib.Path(td) / "data"
        models_dir = data_dir / "models"
        reports_dir = data_dir / "reports"
        meta = _synthesize(data_dir)
        print(f"[phase9] synthesized: {meta}", flush=True)

        # check Session.stealth resolves correctly
        sys.path.insert(0, str(DETECTOR_DIR))
        from features import build_sessions  # type: ignore
        sessions = build_sessions(data_dir, min_requests=3)
        _assert(any(s.stealth for s in sessions),
                "[phase9] no Session.stealth=True after build")
        _assert(any(not s.stealth for s in sessions),
                "[phase9] no Session.stealth=False after build")
        agent_families_with_stealth_pair = {
            f for f in {s.family for s in sessions if s.klass == "agent"}
            if any(s.family == f and s.stealth for s in sessions)
            and any(s.family == f and not s.stealth for s in sessions)
        }
        _assert(agent_families_with_stealth_pair,
                "[phase9] no agent family has both stealth-true and "
                "stealth-false sessions in build")

        cp = _run([sys.executable, str(DETECTOR_DIR / "train.py"),
                   "--data", str(data_dir),
                   "--out", str(models_dir),
                   "--epochs", "60", "--patience", "8"], cwd=ROOT)
        _assert(cp.returncode == 0, f"[phase9] train.py failed rc={cp.returncode}")

        eval_out = reports_dir / "phase9_eval.json"
        cp = _run([sys.executable, str(DETECTOR_DIR / "eval.py"),
                   "--data", str(data_dir),
                   "--models", str(models_dir),
                   "--out", str(eval_out),
                   "--fp-per-hour-budget", "1.0"], cwd=ROOT)
        _assert(cp.returncode == 0, "[phase9] eval.py failed")
        _assert("accuracy" not in cp.stdout.lower(),
                "[phase9] eval stdout mentions accuracy")

        report = json.loads(eval_out.read_text())
        for head in ("with_hp", "ml_only"):
            _assert(head in report, f"[phase9] eval missing head {head!r}")
            block = report[head]
            for key in ("per_stealth", "per_family_stealth"):
                _assert(key in block,
                        f"[phase9] eval[{head}] missing {key!r}")
            _assert(block["per_stealth"],
                    f"[phase9] eval[{head}].per_stealth empty")
            _assert(block["per_family_stealth"],
                    f"[phase9] eval[{head}].per_family_stealth empty")
            keys = set(block["per_family_stealth"])
            # at least one agent family must have both stealth=true AND
            # stealth=false cells present
            has_pair = False
            for fam in {s.family for s in sessions if s.klass == "agent"}:
                k_true = f"{fam}::stealth=true"
                k_false = f"{fam}::stealth=false"
                if k_true in keys and k_false in keys:
                    has_pair = True
                    break
            _assert(has_pair,
                    f"[phase9] eval[{head}].per_family_stealth has no "
                    f"agent family with both stealth values: {sorted(keys)}")
        _assert("accuracy" not in json.dumps(report).lower(),
                "[phase9] eval JSON mentions accuracy")

    print()
    print(f"PHASE 9 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
