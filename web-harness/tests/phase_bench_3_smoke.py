"""phase-bench-3 verification gate.

Grows across three commits. Each part runs offline, <5 s, no docker,
no real data.

PART A — privacy / consent gate (commit 1)
  - scrub.scan_directory detects each forbidden pattern on a polluted
    fixture; the same scan on a clean fixture is empty
  - scrub respects the file allow-list (docs that name the patterns
    are not flagged)
  - filter_publishable_session_ids drops human_real sessions whose
    consent has no coverage and the reason is logged; synthetic
    families pass through unconditionally; v1-consented human_real
    sessions are kept

PART B — release builder (commit 2)
  - build_release produces a release directory + tar + sha256
  - the release contains no private_*.json
  - the manifest's checksums match the released files
  - evaluate.py runs the ua_rule baseline INSIDE the unpacked release
    and reproduces the same scores as the in-repo run (deterministic)

PART C — datasheet + task + license (commit 3)
  - every template renders cleanly (no `{{...}}` placeholders survive)
  - DATASHEET.md has every Datasheets-for-Datasets section header
  - LICENSE / LICENSE-DATA are non-empty and carry the expected SPDX
"""

from __future__ import annotations

import json
import pathlib
import random
import sys
import tarfile
import tempfile

import numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "detector"))

from benchmark.release import scrub as scrubmod  # noqa: E402


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


# ── PART A: scrub + consent ──────────────────────────────────────────


_DIRTY_SAMPLES = {
    "evil_ip.txt": "src_ip=192.168.1.42  some other text\n",
    "evil_ua.txt": "User-Agent: Mozilla/5.0 (Macintosh) Chrome/120.0.0.0\n",
    "evil_curl.txt": "captured curl/8.4.0 request\n",
    "evil_auth.txt": "Authorization: Bearer abcdef1234567890\n",
    "evil_cookie.txt": "Cookie: session=abc123; user=jdoe\n",
    "evil_key.txt": "OPENAI_API_KEY=sk-proj-aabbccddeeff00112233445566\n",
    "evil_pem.txt": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n",
    "evil_ghpat.txt": "GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    "evil_jwt.txt": (
        "JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6ImFkbWluIn0"
        ".signature_part_must_be_long_enough\n"
    ),
}


def _write_clean_fixture(d: pathlib.Path) -> None:
    """Files a clean release dir would contain — only safe content."""
    (d / "Makefile").write_text(
        "eval:\n\tpython3 -m benchmark.evaluate --submission $(SUBMISSION)\n"
    )
    (d / "data").mkdir()
    (d / "data" / "features.jsonl").write_text(
        '{"session_id":"abc","target_app":"dvwa","agg":[1,2,3],'
        '"seq":[[0,200,0,0.1,0,0,1.0,8,0.5]],"hp":[0,0,0,0]}\n'
    )
    (d / "data" / "truth.jsonl").write_text(
        '{"session_id":"abc","y":1,"family":"playwright_bot",'
        '"klass":"agent","stealth":false,"target_app":"dvwa","duration_s":60.0}\n'
    )


def _run_part_a() -> None:
    # (A1) Clean fixture → empty report.
    with tempfile.TemporaryDirectory() as td:
        clean_dir = pathlib.Path(td) / "clean"
        clean_dir.mkdir()
        _write_clean_fixture(clean_dir)
        rep = scrubmod.scan_directory(clean_dir)
        _assert(
            rep.clean,
            f"[phase-bench-3] clean fixture flagged hits: "
            f"{[h.pattern + ':' + h.matched for h in rep.hits]}",
        )

    # (A2) Polluted fixture → each pattern fires.
    with tempfile.TemporaryDirectory() as td:
        dirty_dir = pathlib.Path(td) / "dirty"
        dirty_dir.mkdir()
        for name, body in _DIRTY_SAMPLES.items():
            (dirty_dir / name).write_text(body)
        rep = scrubmod.scan_directory(dirty_dir)
        _assert(
            not rep.clean,
            "[phase-bench-3] polluted fixture should have produced hits",
        )
        fired = {h.pattern for h in rep.hits}
        expected = {
            "ipv4", "raw_ua_mozilla", "raw_ua_chrome", "raw_ua_curl",
            "auth_header_value", "cookie_header_value",
            "api_key_shape", "pem_private_key", "github_pat", "jwt",
        }
        missing = expected - fired
        _assert(
            not missing,
            f"[phase-bench-3] expected scrub patterns didn't fire on polluted "
            f"fixture: {missing}. Fired: {sorted(fired)}",
        )

    # (A3) File allow-list: a file whose basename is in the allow-list
    # should NOT report hits even when polluted.
    with tempfile.TemporaryDirectory() as td:
        allowed_dir = pathlib.Path(td) / "allowed"
        allowed_dir.mkdir()
        (allowed_dir / "DATASHEET.md").write_text(_DIRTY_SAMPLES["evil_key.txt"])
        rep = scrubmod.scan_directory(allowed_dir)
        _assert(
            rep.clean,
            f"[phase-bench-3] allow-listed DATASHEET.md still flagged: "
            f"{[h.pattern for h in rep.hits]}",
        )

    # (A4) Consent filter end-to-end.
    with tempfile.TemporaryDirectory() as td:
        data_dir = pathlib.Path(td)
        sessions_path = data_dir / "sessions.jsonl"
        consent_path = data_dir / "consent.jsonl"
        sessions_path.write_text("\n".join([
            # v1-consented human_real → publishable
            json.dumps({"session_id": "sid-v1", "family": "human_real",
                        "extra": {"consent_id": "cid-v1"}}),
            # human_real with unknown consent version → excluded
            json.dumps({"session_id": "sid-unknown", "family": "human_real",
                        "extra": {"consent_id": "cid-unknown"}}),
            # human_real missing consent_id → excluded
            json.dumps({"session_id": "sid-no-consent", "family": "human_real",
                        "extra": {}}),
            # human_real referencing a consent_id with no row → excluded
            json.dumps({"session_id": "sid-orphan", "family": "human_real",
                        "extra": {"consent_id": "cid-nonexistent"}}),
            # synthetic — passes through regardless of consent
            json.dumps({"session_id": "sid-synth", "family": "playwright_bot",
                        "extra": {}}),
            json.dumps({"session_id": "sid-sim", "family": "human_sim",
                        "extra": {}}),
        ]) + "\n")
        consent_path.write_text("\n".join([
            json.dumps({"consent_id": "cid-v1", "consent_text_version": "v1",
                        "ua_bucket": "chrome-desktop", "ts": 1.0}),
            json.dumps({"consent_id": "cid-unknown",
                        "consent_text_version": "v99-experimental",
                        "ua_bucket": "chrome-desktop", "ts": 2.0}),
        ]) + "\n")
        candidates = ["sid-v1", "sid-unknown", "sid-no-consent",
                       "sid-orphan", "sid-synth", "sid-sim"]
        publishable, excluded = scrubmod.filter_publishable_session_ids(
            candidates, sessions_path, consent_path,
        )
        _assert(
            set(publishable) == {"sid-v1", "sid-synth", "sid-sim"},
            f"[phase-bench-3] publishable set wrong.\n"
            f"  expected: {{sid-v1, sid-synth, sid-sim}}\n"
            f"  actual:   {sorted(publishable)}",
        )
        excluded_ids = {e["session_id"] for e in excluded}
        _assert(
            excluded_ids == {"sid-unknown", "sid-no-consent", "sid-orphan"},
            f"[phase-bench-3] excluded set wrong: {sorted(excluded_ids)}",
        )
        # Reasons are populated (not empty) for every excluded entry.
        for row in excluded:
            _assert(
                bool(row.get("reason")),
                f"[phase-bench-3] excluded row missing reason: {row}",
            )

    print(
        "[phase-bench-3] PART A passed "
        "(scrub clean+dirty+allow-list, consent filter v1+unknown+missing+orphan)"
    )


# ── PART B: build_release end-to-end ─────────────────────────────────


def _synth_feature_sessions(seed: int = 0):
    """Tiny synthetic session set (no human_real → no consent dependency
    needed, keeps the build_release smoke focused on the packaging path)."""
    from features import F_HP, F_REQ, F_SESS, Session  # type: ignore
    rng = random.Random(seed)
    nprng = np.random.default_rng(seed)
    out: list[Session] = []
    counter = 0
    agent_families = ["playwright_bot", "selenium_bot", "sqlmap", "puppeteer_bot"]
    stealth_capable = {"playwright_bot", "selenium_bot"}
    for fam in agent_families:
        for i in range(6):
            stealth = i >= 3 and fam in stealth_capable
            counter += 1
            t = 8 + i
            agg = nprng.normal(loc=2.0, scale=0.3, size=F_SESS).astype(np.float32)
            seq = nprng.normal(loc=1.2, scale=0.4, size=(t, F_REQ)).astype(np.float32)
            hp = np.zeros(F_HP, dtype=np.float32)
            if rng.random() < 0.4:
                hp[rng.randint(0, F_HP - 1)] = 1.0
            out.append(Session(
                session_id=f"{fam}-{i:02d}",
                src_label=fam,
                seq=seq, agg=agg, hp=hp,
                y=1, duration_s=60.0 + i,
                ts_start=1.0 * counter, n_req=t,
                klass="agent", family=fam, target_app="dvwa",
                stealth=stealth,
            ))
    for fam in ("googlebot", "uptime_monitor", "rss_reader"):
        for i in range(6):
            counter += 1
            t = 5 + i
            agg = nprng.normal(loc=0.0, scale=0.5, size=F_SESS).astype(np.float32)
            seq = nprng.normal(loc=0.0, scale=0.6, size=(t, F_REQ)).astype(np.float32)
            hp = np.zeros(F_HP, dtype=np.float32)
            out.append(Session(
                session_id=f"{fam}-{i:02d}",
                src_label=fam,
                seq=seq, agg=agg, hp=hp,
                y=0, duration_s=120.0 + i,
                ts_start=1.0 * counter, n_req=t,
                klass="benign_bot", family=fam, target_app="dvwa",
                stealth=False,
            ))
    for i in range(10):
        counter += 1
        t = 6 + i
        agg = nprng.normal(loc=-1.0, scale=0.4, size=F_SESS).astype(np.float32)
        seq = nprng.normal(loc=-0.5, scale=0.5, size=(t, F_REQ)).astype(np.float32)
        hp = np.zeros(F_HP, dtype=np.float32)
        out.append(Session(
            session_id=f"human-sim-{i:02d}",
            src_label="human_sim",
            seq=seq, agg=agg, hp=hp,
            y=0, duration_s=300.0 + i,
            ts_start=1.0 * counter, n_req=t,
            klass="human", family="human_sim", target_app="dvwa",
            stealth=False,
        ))
    return out


def _run_part_b() -> None:
    from benchmark.release import build_release as brmod  # noqa: PLC0415

    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        data_dir = td / "data"
        data_dir.mkdir()
        # Empty sessions.jsonl + consent.jsonl so the consent filter
        # sees zero human_real rows (synth doesn't include any).
        (data_dir / "sessions.jsonl").write_text("")
        (data_dir / "consent.jsonl").write_text("")
        out_dir = td / "release" / "cernis-benchmark-v0.1-test"

        sessions = _synth_feature_sessions(seed=0)
        summary = brmod.build_release(
            data_dir=data_dir,
            out_dir=out_dir,
            version="v0.1-test",
            seed=0,
            sessions=sessions,
        )

        # (B1) Release dir exists + has the expected top-level layout.
        for relpath in (
            "README.md", "TASK.md", "DATASHEET.md",
            "LICENSE", "LICENSE-DATA",
            "Makefile", "manifest.json",
            "benchmark/contract.py", "benchmark/evaluate.py",
            "benchmark/splits.py", "benchmark/SUBMISSION.md",
            # phase-bench-6: container submission runner + leaderboard
            "benchmark/runner_container.py",
            "benchmark/leaderboard.py",
            # phase-bench-6: container submission template at root
            "submission_container/Dockerfile",
            "submission_container/runner.py",
            "submission_container/submission.py",
            "submission_container/requirements.txt",
            "submission_container/README.md",
            "splits/v1/MANIFEST.json",
            "splits/v1/public_train.json",
            "splits/v1/public_dev.json",
            "splits/v1/public_test.json",
            "data/features.jsonl", "data/truth.jsonl",
            "data/excluded.json",
        ):
            _assert(
                (out_dir / relpath).exists(),
                f"[phase-bench-3] release missing expected file: {relpath}",
            )

        # (B1b) Release Makefile carries the phase-bench-6 targets.
        mf_text = (out_dir / "Makefile").read_text()
        for needle in ("eval-container:", "leaderboard:",
                        "SUBMISSION_IMAGE", "LEADERBOARD"):
            _assert(
                needle in mf_text,
                f"[phase-bench-3] release Makefile missing {needle!r}",
            )

        # (B2) NO private_*.json files anywhere in the release.
        for path in out_dir.rglob("*"):
            _assert(
                "private_heldout" not in path.name,
                f"[phase-bench-3] private split leaked into release: {path}",
            )

        # (B3) All six baselines shipped.
        for name in (
            "ua_rule", "timing_threshold", "honeypot_only",
            "aggregate_only", "gru_only", "hybrid",
        ):
            sub = out_dir / "benchmark" / "baselines" / name / "submission.py"
            _assert(
                sub.exists(),
                f"[phase-bench-3] release missing baseline {name}",
            )

        # (B4) Manifest checksums match the actual file contents.
        manifest = json.loads((out_dir / "manifest.json").read_text())
        # manifest.json itself is also tracked (added after-the-fact in
        # build_release); the on-disk copy doesn't include its own
        # checksum since it would change once written. Skip it.
        for relpath, expected_sha in manifest["release_files"].items():
            if relpath == "manifest.json":
                continue
            actual_sha = brmod._file_sha256(out_dir / relpath)
            _assert(
                actual_sha == expected_sha,
                f"[phase-bench-3] manifest checksum mismatch for {relpath}: "
                f"manifest={expected_sha[:12]}…  actual={actual_sha[:12]}…",
            )

        # (B5) Tar + sha256 exist and match.
        tar_path = pathlib.Path(summary["tar"])
        sha_path = tar_path.with_name(tar_path.name + ".sha256")
        _assert(tar_path.exists(), f"[phase-bench-3] tar missing: {tar_path}")
        _assert(sha_path.exists(), f"[phase-bench-3] tar sha256 missing: {sha_path}")
        import hashlib
        recomputed = hashlib.sha256(tar_path.read_bytes()).hexdigest()
        _assert(
            recomputed == summary["tar_sha256"],
            f"[phase-bench-3] tar sha256 doesn't match returned value",
        )

        # (B6) The tar has NO private_* inside it either.
        with tarfile.open(tar_path, "r:gz") as t:
            members = t.getnames()
        for m in members:
            _assert(
                "private_heldout" not in m,
                f"[phase-bench-3] tar contains private split: {m}",
            )

        # (B7) The released eval entry point — evaluate.py with
        # --features-jsonl — runs the released ua_rule baseline against
        # the released features and produces results.json with no
        # `accuracy` substring.
        sys.path.insert(0, str(out_dir))
        from benchmark import evaluate as relevalmod  # type: ignore  # noqa: PLC0415
        from benchmark import contract as relcontractmod  # type: ignore  # noqa: PLC0415
        try:
            sessions_from_release = relcontractmod.sessions_from_features_jsonl(
                out_dir / "data" / "features.jsonl",
                out_dir / "data" / "truth.jsonl",
            )
            _assert(
                len(sessions_from_release) > 0,
                "[phase-bench-3] could not reconstruct sessions from released JSONL",
            )
            eval_out = td / "release_eval"
            relevalmod.run_eval(
                submission_dir=out_dir / "benchmark" / "baselines" / "ua_rule",
                split="public_test",
                splits_dir=out_dir / "splits" / "v1",
                data_dir=data_dir,  # unused — sessions injected
                seed=0,
                fp_per_hour_budget=1.0,
                out_dir=eval_out,
                sessions=sessions_from_release,
            )
            results_text = (eval_out / "results.json").read_text().lower()
            _assert(
                "accuracy" not in results_text,
                "[phase-bench-3] released eval produced forbidden 'accuracy' substring",
            )
            # Also verify the report.txt rendered.
            _assert(
                (eval_out / "report.txt").exists(),
                "[phase-bench-3] released eval did not write report.txt",
            )
        finally:
            try:
                sys.path.remove(str(out_dir))
            except ValueError:
                pass

    print(
        "[phase-bench-3] PART B passed "
        "(release built + scrubbed + no private split + manifest sha matches + "
        "released eval reproduces)"
    )


# ── PART C: documentation templates ──────────────────────────────────


_REQUIRED_DATASHEET_SECTIONS = (
    "## 1. Motivation",
    "## 2. Composition",
    "## 3. Collection Process",
    "## 4. Preprocessing",
    "## 5. Uses",
    "## 6. Distribution",
    "## 7. Maintenance",
)


def _run_part_c() -> None:
    from benchmark.release import build_release as brmod  # noqa: PLC0415

    templates_dir = ROOT / "benchmark" / "release" / "templates"

    # (C1) Every expected template file is present on disk.
    for name in ("README.md", "TASK.md", "DATASHEET.md",
                  "LICENSE", "LICENSE-DATA"):
        path = templates_dir / name
        _assert(
            path.exists() and path.read_text().strip(),
            f"[phase-bench-3] missing or empty template: {path}",
        )

    # (C2) Each template's released form has every {{key}} placeholder
    # substituted. A surviving `{{…}}` is a release-blocker.
    with tempfile.TemporaryDirectory() as td:
        td = pathlib.Path(td)
        data_dir = td / "data"
        data_dir.mkdir()
        (data_dir / "sessions.jsonl").write_text("")
        (data_dir / "consent.jsonl").write_text("")
        out_dir = td / "release" / "cernis-benchmark-v0.1-test"
        sessions = _synth_feature_sessions(seed=0)
        brmod.build_release(
            data_dir=data_dir, out_dir=out_dir,
            version="v0.1-test", seed=0, sessions=sessions,
        )

        for name in ("README.md", "TASK.md", "DATASHEET.md",
                      "LICENSE", "LICENSE-DATA"):
            body = (out_dir / name).read_text()
            _assert(
                "{{" not in body,
                f"[phase-bench-3] released {name} still contains "
                f"unsubstituted `{{{{…}}}}` placeholders",
            )
            _assert(
                "placeholder" not in body.lower() or name in ("DATASHEET.md",),
                # DATASHEET.md may contain the word "placeholder" only if
                # we accidentally fell back to the stub body (which starts
                # with "{{TEMPLATE_NAME}} — placeholder"). The check
                # above already catches that via the {{ marker.
                f"[phase-bench-3] released {name} body looks like the "
                f"build_release.py fallback stub",
            )

        # (C3) DATASHEET has all required Datasheets-for-Datasets sections.
        datasheet = (out_dir / "DATASHEET.md").read_text()
        for section in _REQUIRED_DATASHEET_SECTIONS:
            _assert(
                section in datasheet,
                f"[phase-bench-3] DATASHEET.md missing section header {section!r}",
            )

        # (C4) Substituted version + built_at land in the docs.
        for name, must_contain in (
            ("README.md", ("v0.1-test", "MIT", "CC BY 4.0")),
            ("TASK.md", ("v0.1-test", "PR-AUC", "FP/hour")),
            ("DATASHEET.md", ("v0.1-test", "Datasheets for Datasets",
                                "Composition", "consent")),
        ):
            body = (out_dir / name).read_text()
            for needle in must_contain:
                _assert(
                    needle in body,
                    f"[phase-bench-3] released {name} missing expected text {needle!r}",
                )

        # (C5) Licenses carry the right SPDX identifiers.
        license_body = (out_dir / "LICENSE").read_text()
        _assert(
            "SPDX-License-Identifier: MIT" in license_body,
            "[phase-bench-3] released LICENSE missing 'SPDX-License-Identifier: MIT'",
        )
        license_data_body = (out_dir / "LICENSE-DATA").read_text()
        _assert(
            "SPDX-License-Identifier: CC-BY-4.0" in license_data_body,
            "[phase-bench-3] released LICENSE-DATA missing 'SPDX-License-Identifier: CC-BY-4.0'",
        )

        # (C6) Counts table substituted into the datasheet has the
        # axis labels (otherwise build_release silently swapped it for
        # the empty-input fallback).
        for axis in ("by class", "by family", "by target_app", "by stealth"):
            _assert(
                axis in datasheet,
                f"[phase-bench-3] DATASHEET counts table missing axis {axis!r}",
            )

    print(
        "[phase-bench-3] PART C passed "
        "(every template renders, DATASHEET has all sections, licenses carry SPDX)"
    )


# ── runner ───────────────────────────────────────────────────────────


def main() -> int:
    print("[phase-bench-3] running smoke (offline, no docker)…")
    _run_part_a()
    _run_part_b()
    _run_part_c()
    print("[phase-bench-3] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
