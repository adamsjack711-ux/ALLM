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
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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


# ── runner ───────────────────────────────────────────────────────────


def main() -> int:
    print("[phase-bench-3] running smoke (offline, no docker)…")
    _run_part_a()
    # PARTS B + C land in commits 2 + 3.
    print("[phase-bench-3] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
