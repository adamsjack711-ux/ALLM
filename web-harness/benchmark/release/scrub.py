"""Privacy + consent gate for the Cernis public release.

Two responsibilities, run as a pipeline (consent → scrub):

  1. `filter_publishable_session_ids` — for every `human_real` session,
     look up its consent_id in `data/consent.jsonl`, check the
     `consent_text_version` against the `CONSENT_COVERAGE` map. Sessions
     whose consent doesn't cover public release are dropped + logged.
     Sessions with `class=human` but `family != human_real` (e.g. the
     `human_sim` simulator) bypass the consent check — they are
     synthetic and have no human-subject to consent. Agent / benign_bot
     classes likewise bypass.

  2. `scan_directory` / `scan_paths` — regex sweep for forbidden
     patterns in every file about to be packaged. Any hit on a
     non-allowlisted file aborts the release.

The allow-list (`_FILE_ALLOWLIST`) names a handful of files that
LEGITIMATELY contain these substrings (docs / smoke tests / this
file itself). Documentation can reference "Authorization:" by name;
it just cannot ship an actual auth-header value attached to a session
row.

These gates are NOT a substitute for the in-redaction-at-write-time
guarantees from phase-bench-1. They are belt-and-suspenders: even if
a future change accidentally lets a raw IP into the data, the release
build will fail before publishing.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from typing import Iterable


# ── Consent coverage map ─────────────────────────────────────────────


# Each entry says whether sessions tagged with that consent text version
# may be redistributed as part of a public release. Adding a new
# consent text version means adding it here AFTER reviewing the wording.
CONSENT_COVERAGE: dict[str, dict] = {
    "v1": {
        "publish": True,
        "summary": (
            "v1 consent text (capture/consent.html) explicitly states "
            "'The benchmark may be released publicly.'"
        ),
    },
}


def _read_jsonl(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def filter_publishable_session_ids(
    candidate_ids: Iterable[str],
    sessions_jsonl: pathlib.Path,
    consent_jsonl: pathlib.Path,
) -> tuple[list[str], list[dict]]:
    """Drop human_real sessions whose consent doesn't cover publication.

    Returns:
      publishable_ids:  candidates that survive the consent check
      excluded:         one row per dropped session — {session_id,
                         family, reason}. Useful for the release
                         manifest's excluded-sessions audit trail.

    A session is publishable when:
      - it is NOT `family=human_real` (synthetic data — no consent
        dependency), OR
      - it is `family=human_real`, has a `consent_id` in its
        provenance row, the consent.jsonl row for that id exists,
        and `CONSENT_COVERAGE[consent_text_version].publish is True`.

    Any other combination → excluded with a logged reason.
    """
    candidates = set(candidate_ids)
    sess_rows = {
        r["session_id"]: r
        for r in _read_jsonl(sessions_jsonl)
        if r.get("session_id")
    }
    consent_rows = {
        r["consent_id"]: r
        for r in _read_jsonl(consent_jsonl)
        if r.get("consent_id")
    }

    publishable: list[str] = []
    excluded: list[dict] = []
    for sid in sorted(candidates):
        sess = sess_rows.get(sid)
        family = (sess or {}).get("family", "?")
        if family != "human_real":
            # Synthetic / generator-produced session — no consent needed.
            publishable.append(sid)
            continue

        consent_id = ((sess or {}).get("extra") or {}).get("consent_id")
        if not consent_id:
            excluded.append({
                "session_id": sid, "family": family,
                "reason": "human_real session missing consent_id in provenance",
            })
            continue
        consent_row = consent_rows.get(consent_id)
        if consent_row is None:
            excluded.append({
                "session_id": sid, "family": family,
                "reason": f"consent_id {consent_id!r} not found in consent.jsonl",
            })
            continue
        version = consent_row.get("consent_text_version") or ""
        coverage = CONSENT_COVERAGE.get(version)
        if coverage is None:
            excluded.append({
                "session_id": sid, "family": family,
                "reason": f"unknown consent_text_version {version!r} "
                          f"(not in CONSENT_COVERAGE; add an entry after "
                          f"reviewing the wording)",
            })
            continue
        if not coverage.get("publish"):
            excluded.append({
                "session_id": sid, "family": family,
                "reason": f"consent version {version!r} has publish=False",
            })
            continue
        publishable.append(sid)

    return publishable, excluded


# ── PII / secret scrub ───────────────────────────────────────────────


@dataclasses.dataclass
class ScrubHit:
    path: str
    line: int
    pattern: str
    matched: str  # truncated for the report


@dataclasses.dataclass
class ScrubReport:
    hits: list[ScrubHit]
    files_scanned: int

    @property
    def clean(self) -> bool:
        return not self.hits

    def as_dict(self) -> dict:
        return {
            "clean": self.clean,
            "files_scanned": self.files_scanned,
            "n_hits": len(self.hits),
            "hits": [dataclasses.asdict(h) for h in self.hits],
        }


# Each pattern is (name, compiled_regex). Names go into the report so
# whoever investigates an abort knows WHICH rule fired.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    # IP addresses — docker-internal IPs (172.x, 10.x) shouldn't ship
    # either. The redaction in phase-bench-1 set src_ip to None for the
    # human channel; other channels' src_ip is a docker network address.
    ("ipv4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("ipv6", re.compile(
        r"\b(?:[0-9a-fA-F]{1,4}:){4,7}[0-9a-fA-F]{1,4}\b"
    )),
    # Raw User-Agent fragments — the bucketed strings (chrome-desktop,
    # firefox-mobile) are fine; the raw "Chrome/120.0.0.0" / "Mozilla/5.0"
    # tokens are not.
    ("raw_ua_mozilla", re.compile(r"Mozilla/\d+\.\d+")),
    ("raw_ua_chrome", re.compile(r"Chrome/\d+\.\d+")),
    ("raw_ua_firefox", re.compile(r"Firefox/\d+\.\d+")),
    ("raw_ua_safari", re.compile(r"Safari/\d+\.\d+")),
    ("raw_ua_curl", re.compile(r"\bcurl/\d+\.\d+")),
    ("raw_ua_python", re.compile(r"python-requests/\d+\.\d+")),
    ("raw_ua_wget", re.compile(r"\bWget/\d+\.\d+")),
    # Header VALUES (not the booleans the proxy stores).
    ("auth_header_value", re.compile(
        r"\bAuthorization:\s*(?:Bearer|Basic|Digest|Token)\s+\S{4,}",
        re.IGNORECASE,
    )),
    ("cookie_header_value", re.compile(
        r"\bCookie:\s*[A-Za-z_][A-Za-z0-9_-]*=\S",
        re.IGNORECASE,
    )),
    ("set_cookie_value", re.compile(
        r"\bSet-Cookie:\s*[A-Za-z_][A-Za-z0-9_-]*=\S",
        re.IGNORECASE,
    )),
    # API-key shapes — length-gated to avoid false-positives on `sk-*`
    # prefix mentions in docs. Same regex as phase-bench-1.
    ("api_key_shape", re.compile(
        r"sk-(?:live|ant|proj|test|or)-[A-Za-z0-9_]{16,}"
    )),
    # Common secret shapes worth catching even if not API keys.
    ("pem_private_key", re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----")),
    ("github_pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("jwt", re.compile(
        r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}"
        r"\.[A-Za-z0-9_-]{20,}"
    )),
)

# Files whose basename matches one of these are EXEMPT from the scan.
# They legitimately contain these substrings (this file names every
# regex; docs reference the rules; smoke tests use synthetic fixtures
# with deliberately polluted content to verify the scanner works).
_FILE_ALLOWLIST: frozenset[str] = frozenset({
    "scrub.py",
    "phase_bench_1_smoke.py",
    "phase_bench_2_smoke.py",
    "phase_bench_3_smoke.py",
    "DATASHEET.md",
    "SUBMISSION.md",
    "TASK.md",
    "README.md",
})

# File extensions / suffixes that are always skipped (binary or
# generated). Cuts scan time + avoids junk hits.
_SKIP_SUFFIXES: frozenset[str] = frozenset({
    ".pyc", ".pyo", ".pyd",
    ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".pdf", ".gz", ".tgz", ".tar", ".zip", ".whl",
    ".pt", ".bin", ".onnx", ".npz", ".npy",
})


def _file_is_skippable(path: pathlib.Path) -> bool:
    if path.suffix.lower() in _SKIP_SUFFIXES:
        return True
    for part in path.parts:
        if part in ("__pycache__", ".git", "node_modules", ".venv", "venv"):
            return True
    return False


def scan_paths(paths: Iterable[pathlib.Path]) -> ScrubReport:
    """Scan an explicit list of files. Files whose basename is in
    `_FILE_ALLOWLIST` are recorded as scanned but no hits are emitted
    for them.
    """
    hits: list[ScrubHit] = []
    scanned = 0
    for path in paths:
        if not path.is_file():
            continue
        if _file_is_skippable(path):
            continue
        scanned += 1
        if path.name in _FILE_ALLOWLIST:
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        # Line-by-line so the report can cite line numbers.
        for lineno, line in enumerate(text.splitlines(), start=1):
            for name, pat in _PATTERNS:
                m = pat.search(line)
                if m:
                    matched = m.group(0)
                    if len(matched) > 80:
                        matched = matched[:77] + "..."
                    hits.append(ScrubHit(
                        path=str(path), line=lineno,
                        pattern=name, matched=matched,
                    ))
    return ScrubReport(hits=hits, files_scanned=scanned)


def scan_directory(root: pathlib.Path) -> ScrubReport:
    """Walk a directory tree and scan every regular file in it."""
    return scan_paths(p for p in root.rglob("*") if p.is_file())
