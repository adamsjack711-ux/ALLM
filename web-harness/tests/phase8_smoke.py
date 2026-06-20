"""Phase 8 verification gate: detector eval consumes the new label schema.

Synthesizes a multi-family JSONL dataset (requests / sessions /
honeypots) in a tmpdir, runs train + eval + heldout, and asserts:

  - features.build_sessions resolves class / family / target_app from
    the sessions.jsonl provenance rows.
  - eval.json contains:
      * per_family (with `kind` ∈ {agent, benign_bot, human})
      * per_target_app
      * agent_vs_benign_bot.confusion + benign_bot_fp_rate
  - heldout.json contains:
      * per_attacker AND per_benign_family (both must be non-empty)
      * each entry has the new ratio / flag fields
  - "accuracy" never appears in either JSON output.

Runs in a tmpdir, no docker, no real targets. Wall-clock ~30-90s
depending on torch CPU speed (trains 2 heads + ≥3 held-out heads).
"""

from __future__ import annotations

import json
import os
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
    # (family, klass, target_app, n_sessions, agent_signal_strength)
    ("playwright_bot", "agent",      "dvwa",       8, 0.9),
    ("sqlmap",         "agent",      "dvwa",       6, 0.8),
    ("selenium_bot",   "agent",      "juice_shop", 5, 0.85),
    ("googlebot",      "benign_bot", "dvwa",       6, 0.1),
    ("uptime_monitor", "benign_bot", "dvwa",       5, 0.05),
    ("rss_reader",     "benign_bot", "dvwa",       5, 0.1),
    ("human_sim",      "human",      "dvwa",       7, 0.15),
]


def _synthesize_sessions(out_dir: pathlib.Path, seed: int = 0) -> dict:
    """Write requests / honeypots / sessions JSONL to out_dir.

    Per-session feature shape varies by family so the GRU+MLP detector
    has signal to learn from. Agents tend to fire requests fast with
    higher 4xx rate and more distinct paths; benign bots have
    structured slower cadence; humans are slowest with low query churn.
    Honeypot trips: googlebot reads /robots.txt; ~half of agents trip
    the canary (mimics the pentesterpro hidden-DOM pattern).
    """
    rng = random.Random(seed)
    np_rng = np.random.default_rng(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    requests_path = out_dir / "requests.jsonl"
    sessions_path = out_dir / "sessions.jsonl"
    honeypots_path = out_dir / "honeypots.jsonl"
    beacons_path = out_dir / "beacons.jsonl"

    req_lines: list[dict] = []
    sess_lines: list[dict] = []
    hp_lines: list[dict] = []
    beacon_lines: list[dict] = []

    t0 = time.time() - 7200  # 2h ago start

    def write_session(family: str, klass: str, target_app: str,
                      session_idx: int, signal: float, sid: str) -> None:
        nonlocal t0
        is_agent = klass == "agent"
        # Cadence: agents fast, bots medium, humans slow
        base_delta_ms = (
            rng.uniform(40, 200) if is_agent else
            rng.uniform(800, 1800) if klass == "benign_bot" else
            rng.uniform(1500, 3500)
        )
        # Number of requests
        n_req = (
            rng.randint(20, 60) if is_agent else
            rng.randint(5, 25) if klass == "benign_bot" else
            rng.randint(6, 18)
        )
        ts = t0 + session_idx * 30
        prev = None
        for i in range(n_req):
            delta = None if prev is None else int(max(1, np_rng.normal(base_delta_ms, base_delta_ms * 0.3)))
            ts = ts + (delta or 0) / 1000.0
            status = (
                rng.choices([200, 302, 404, 500], weights=[0.5, 0.2, 0.25, 0.05])[0]
                if is_agent else
                rng.choices([200, 302, 404], weights=[0.85, 0.1, 0.05])[0]
            )
            method = "POST" if is_agent and rng.random() < 0.35 else "GET"
            path_suffix = rng.choice([
                "/", "/login.php", "/vulnerabilities/sqli/", "/vulnerabilities/xss_r/",
                "/about.php", "/instructions.php", "/feed", "/robots.txt",
                "/security.php",
            ])
            req_lines.append({
                "ts": ts,
                "session_id": sid,
                "src_ip": "172.18.0.99",
                "src_label": family,
                "method": method,
                "path": path_suffix,
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
                "class": klass,
                "family": family,
                "target_app": target_app,
                "security_level": "low",
                "stealth": False,
            })
            prev = delta

        sess_lines.append({
            "ts": ts,
            "session_id": sid,
            "src_label": family,
            "class": klass,
            "family": family,
            "target_app": target_app,
            "security_level": "low",
            "stealth": False,
            "generator": family,
            "generator_version": "0.1.0",
            "generator_config_sha": f"{rng.randint(0, 0xffffffff):08x}",
            "extra": {},
        })

        # honeypot trips
        if family == "googlebot":
            hp_lines.append({
                "ts": ts, "session_id": sid, "src_label": family,
                "honeypot": "robots_read", "evidence": {"ua": "Googlebot"},
            })
        if is_agent and rng.random() < 0.55:
            hp_lines.append({
                "ts": ts + 1.0, "session_id": sid, "src_label": family,
                "honeypot": "canary", "evidence": {"qs": "ack=1", "ref": ""},
            })

        # one beacon per browser-engine session so js_ran fires
        if family in ("playwright_bot", "selenium_bot", "human_sim", "googlebot"):
            beacon_lines.append({
                "ts": ts + 0.1, "session_id": sid, "src_ip": "172.18.0.99",
                "src_label": family, "ua": "Mozilla/5.0",
                "event": {"type": "ready", "t": 100.0},
            })

    next_sid = [1]
    for fam, klass, target_app, n_sessions, signal in FAMILIES:
        for i in range(n_sessions):
            sid = f"sid-{next_sid[0]:04d}-{fam[:4]}"
            next_sid[0] += 1
            write_session(fam, klass, target_app, i, signal, sid)

    def _dump(path: pathlib.Path, rows: list[dict]) -> None:
        with path.open("w") as f:
            for row in rows:
                f.write(json.dumps(row, separators=(",", ":")) + "\n")

    _dump(requests_path, req_lines)
    _dump(sessions_path, sess_lines)
    _dump(honeypots_path, hp_lines)
    _dump(beacons_path, beacon_lines)

    return {
        "n_sessions": len(sess_lines),
        "n_requests": len(req_lines),
        "n_honeypot_trips": len(hp_lines),
        "n_beacons": len(beacon_lines),
        "families": sorted({r["family"] for r in sess_lines}),
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

        meta = _synthesize_sessions(data_dir)
        print(f"[phase8] synthesized: {meta}", flush=True)

        # Direct features.build_sessions check: new fields resolved
        sys.path.insert(0, str(DETECTOR_DIR))
        from features import build_sessions  # type: ignore
        sessions = build_sessions(data_dir, min_requests=3)
        _assert(len(sessions) > 0, "[phase8] build_sessions returned 0 sessions")
        for s in sessions[:3]:
            _assert(s.klass in ("agent", "benign_bot", "human", "unknown"),
                    f"[phase8] resolved klass invalid: {s.klass}")
            _assert(s.family != "", "[phase8] family empty after resolve")
            _assert(s.target_app != "", "[phase8] target_app empty after resolve")
        klasses = {s.klass for s in sessions}
        _assert({"agent", "benign_bot", "human"} <= klasses,
                f"[phase8] expected 3 classes, got {klasses}")

        # train
        cp = _run([sys.executable, str(DETECTOR_DIR / "train.py"),
                   "--data", str(data_dir),
                   "--out", str(models_dir),
                   "--epochs", "60", "--patience", "8"], cwd=ROOT)
        _assert(cp.returncode == 0, f"[phase8] train.py failed rc={cp.returncode}")
        _assert((models_dir / "with_hp.pt").exists(), "[phase8] with_hp.pt missing")
        _assert((models_dir / "ml_only.pt").exists(), "[phase8] ml_only.pt missing")

        # eval
        eval_out = reports_dir / "phase8_eval.json"
        cp = _run([sys.executable, str(DETECTOR_DIR / "eval.py"),
                   "--data", str(data_dir),
                   "--models", str(models_dir),
                   "--out", str(eval_out),
                   "--fp-per-hour-budget", "1.0"], cwd=ROOT)
        _assert(cp.returncode == 0, f"[phase8] eval.py failed rc={cp.returncode}")
        _assert("accuracy" not in cp.stdout.lower(),
                "[phase8] eval stdout mentions accuracy")

        eval_report = json.loads(eval_out.read_text())
        for head in ("with_hp", "ml_only"):
            _assert(head in eval_report, f"[phase8] eval missing head {head!r}")
            block = eval_report[head]
            for key in ("per_family", "per_target_app", "agent_vs_benign_bot"):
                _assert(key in block, f"[phase8] eval[{head}] missing {key!r}")
            _assert(block["per_family"], f"[phase8] eval[{head}].per_family is empty")
            _assert(block["per_target_app"], f"[phase8] eval[{head}].per_target_app is empty")
            avb = block["agent_vs_benign_bot"]
            _assert("confusion" in avb, "[phase8] agent_vs_benign_bot.confusion missing")
            _assert("benign_bot_fp_rate" in avb, "[phase8] benign_bot_fp_rate missing")
            _assert("per_benign_family_fp" in avb, "[phase8] per_benign_family_fp missing")
            # at least one agent family present in per_family
            kinds = {v.get("kind") for v in block["per_family"].values()}
            _assert("agent" in kinds, f"[phase8] no agent kind in per_family: {kinds}")
            _assert("benign_bot" in kinds, f"[phase8] no benign_bot kind in per_family: {kinds}")
        _assert("accuracy" not in json.dumps(eval_report).lower(),
                "[phase8] eval JSON mentions accuracy")

        # heldout
        heldout_out = reports_dir / "phase8_heldout.json"
        cp = _run([sys.executable, str(DETECTOR_DIR / "heldout.py"),
                   "--data", str(data_dir),
                   "--out", str(heldout_out),
                   "--fp-per-hour-budget", "1.0"], cwd=ROOT)
        _assert(cp.returncode == 0, f"[phase8] heldout.py failed rc={cp.returncode}")

        heldout_report = json.loads(heldout_out.read_text())
        _assert("skipped" not in heldout_report,
                f"[phase8] heldout skipped: {heldout_report.get('skipped')}")
        for key in ("per_attacker", "per_benign_family",
                    "agent_families", "benign_families"):
            _assert(key in heldout_report, f"[phase8] heldout missing {key!r}")
        _assert(heldout_report["per_attacker"], "[phase8] per_attacker empty")
        _assert(heldout_report["per_benign_family"],
                "[phase8] per_benign_family empty")
        # at least one non-skipped entry per side
        agent_runs = [v for v in heldout_report["per_attacker"].values() if "skipped" not in v]
        benign_runs = [v for v in heldout_report["per_benign_family"].values() if "skipped" not in v]
        _assert(len(agent_runs) >= 1, "[phase8] no agent heldout runs completed")
        _assert(len(benign_runs) >= 1, "[phase8] no benign heldout runs completed")
        for v in agent_runs:
            for key in ("in_dist_recall", "heldout_recall", "heldout_ratio",
                        "overfits_attacker", "n_train_sessions", "n_holdout_sessions"):
                _assert(key in v, f"[phase8] per_attacker entry missing {key!r}: {v}")
        for v in benign_runs:
            for key in ("in_dist_fp_rate", "heldout_fp_rate", "heldout_ratio",
                        "fp_generalization_fail", "n_train_sessions",
                        "n_holdout_sessions"):
                _assert(key in v, f"[phase8] per_benign_family entry missing {key!r}: {v}")
        _assert("accuracy" not in json.dumps(heldout_report).lower(),
                "[phase8] heldout JSON mentions accuracy")

    print()
    print(f"PHASE 8 SMOKE PASSED ✅  elapsed={time.time() - t0:.1f}s")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
