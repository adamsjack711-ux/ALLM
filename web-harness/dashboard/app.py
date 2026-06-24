"""Cernis live dashboard — a single-page operator view of the lab.

Read-only. Tails the JSONL artifacts the rest of the lab already
writes and renders them as three panels:

  - **Live sweep** — counts and req/s rates per (family, target_app,
    stealth) from `data/sessions.jsonl` + `data/requests.jsonl`. Shows
    what's hitting which target right now while a sweep runs.

  - **Leaderboard** — deduped + sorted view of
    `data/reports/leaderboard.jsonl` (the phase-bench-4 append-only
    log). Surfaces PR-AUC / FP-per-hour / wall-time / peak-mem per
    submission so you can compare ranks as new entries land.

  - **Alert-fatigue** — latest `data/host/alert_fatigue.json` from the
    host-side phase-3/phase-4 arithmetic. Threshold τ, per-class FP
    rate, per-deployment FP/hour. Daily distribution when present.

The dashboard NEVER writes to data/, NEVER opens any private split,
NEVER mentions the forbidden word.

Run locally:
    python3 -m dashboard.app --data-dir data --port 8095

Under docker:
    docker compose --profile dashboard up --build dashboard

Both default to host 127.0.0.1 + port 8095. The compose service binds
to 127.0.0.1 only; this is an operator tool, not a public surface.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import time
from typing import Any, Optional


# ── pure data-access helpers (tested directly by the smoke) ─────────


def read_jsonl(path: pathlib.Path, *, max_lines: Optional[int] = None) -> list[dict]:
    """Parse a JSONL file. Bad lines are skipped (the lab's
    generators sometimes truncate the final line during a crash; we
    don't want one bad row to take the dashboard down)."""
    if not path.exists():
        return []
    out: list[dict] = []
    lines = path.read_text().splitlines()
    if max_lines is not None:
        lines = lines[-max_lines:]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def tail_sessions(
    sessions_path: pathlib.Path, n: int = 200,
) -> list[dict]:
    """Return the last `n` provenance rows from sessions.jsonl, newest
    first. Truncates each row's `extra` field to avoid shipping
    multi-KB blobs to the browser, but pulls the phase-14b cost
    fields out as top-level keys so the dashboard can render them."""
    rows = read_jsonl(sessions_path, max_lines=max(n * 4, 1000))[-n:]
    trimmed = []
    for r in reversed(rows):
        extra = r.get("extra") or {}
        trimmed.append({
            "ts": r.get("ts"),
            "session_id": r.get("session_id"),
            "class": r.get("class"),
            "family": r.get("family"),
            "target_app": r.get("target_app"),
            "security_level": r.get("security_level"),
            "stealth": bool(r.get("stealth")),
            "generator": r.get("generator"),
            "extra_keys": sorted(extra.keys()),
            # Phase 14b: surface cost fields when present.
            "tokens_in": extra.get("tokens_in"),
            "tokens_out": extra.get("tokens_out"),
            "estimated_cost_cents": extra.get("estimated_cost_cents"),
        })
    return trimmed


# ── phase 14b: LLM spend rollup ─────────────────────────────────────


def llm_spend_summary(
    sessions_path: pathlib.Path, *, window_s: float = 86400.0,
    now: Optional[float] = None,
) -> dict:
    """Sum `extra.estimated_cost_cents` across `llm_*` family sessions
    in the last `window_s` seconds (default 24h). Returns total +
    per-(backend, model) breakdown + an `unpriced_sessions` count for
    rows whose (backend, model) wasn't in the pricing table.

    Used by the dashboard's header spend-badge and the phase 14b
    smoke."""
    now = now if now is not None else time.time()
    cutoff = now - window_s
    rows = read_jsonl(sessions_path, max_lines=200000)
    total_cents = 0.0
    n_sessions = 0
    unpriced = 0
    by_pair: dict[str, dict] = {}
    for r in rows:
        ts = float(r.get("ts") or 0)
        if ts < cutoff:
            continue
        fam = r.get("family") or ""
        if not fam.startswith("llm_"):
            continue
        extra = r.get("extra") or {}
        backend = extra.get("backend") or "?"
        model = extra.get("model") or "?"
        key = f"{backend}/{model}"
        cell = by_pair.setdefault(key, {
            "backend": backend, "model": model,
            "n_sessions": 0, "tokens_in": 0, "tokens_out": 0,
            "cost_cents": 0.0, "unpriced": False,
        })
        cell["n_sessions"] += 1
        cell["tokens_in"] += int(extra.get("tokens_in") or 0)
        cell["tokens_out"] += int(extra.get("tokens_out") or 0)
        cents = extra.get("estimated_cost_cents")
        if cents is None:
            cell["unpriced"] = True
            unpriced += 1
        else:
            cell["cost_cents"] += float(cents)
            total_cents += float(cents)
        n_sessions += 1
    return {
        "window_s": window_s,
        "n_sessions": n_sessions,
        "unpriced_sessions": unpriced,
        "total_cents": total_cents,
        "total_dollars": total_cents / 100.0,
        "by_backend_model": by_pair,
    }


def sessions_by_family(
    sessions_path: pathlib.Path, *, window_s: float = 300.0,
    now: Optional[float] = None,
) -> dict[str, dict]:
    """Counts of `sessions.jsonl` rows by family within the last
    `window_s` seconds. Returns
    `{family: {n, by_target_app, by_stealth, by_class, last_seen}}`.
    """
    now = now if now is not None else time.time()
    cutoff = now - window_s
    rows = read_jsonl(sessions_path, max_lines=20000)
    by_fam: dict[str, dict] = {}
    for r in rows:
        ts = float(r.get("ts") or 0)
        if ts < cutoff:
            continue
        fam = r.get("family") or "?"
        target_app = r.get("target_app") or "?"
        stealth = "stealth" if r.get("stealth") else "no_stealth"
        klass = r.get("class") or "?"
        cell = by_fam.setdefault(fam, {
            "n": 0,
            "by_target_app": {},
            "by_stealth": {"stealth": 0, "no_stealth": 0},
            "by_class": {},
            "last_seen": 0.0,
        })
        cell["n"] += 1
        cell["by_target_app"][target_app] = (
            cell["by_target_app"].get(target_app, 0) + 1
        )
        cell["by_stealth"][stealth] += 1
        cell["by_class"][klass] = cell["by_class"].get(klass, 0) + 1
        cell["last_seen"] = max(cell["last_seen"], ts)
    return by_fam


def requests_rate(
    requests_path: pathlib.Path, *, window_s: float = 60.0,
    now: Optional[float] = None,
) -> dict[str, dict]:
    """Req/s rate per (src_label / family, target_app) over the
    trailing `window_s` window. The capture proxy writes one row per
    request, so a coarse count / window_s is what an operator wants
    to see for `who's hammering what right now`.
    """
    now = now if now is not None else time.time()
    cutoff = now - window_s
    rows = read_jsonl(requests_path, max_lines=200000)
    by_key: dict[str, dict] = {}
    for r in rows:
        ts = float(r.get("ts") or 0)
        if ts < cutoff:
            continue
        # The capture proxy uses `src_label`; the phase-7 generators
        # carry it forward as `family`. Honor either.
        fam = r.get("src_label") or r.get("family") or "?"
        target_app = r.get("target_app") or "?"
        key = f"{fam}@{target_app}"
        cell = by_key.setdefault(key, {
            "family": fam, "target_app": target_app,
            "n_requests": 0, "last_ts": 0.0,
            "status_2xx": 0, "status_4xx": 0, "status_5xx": 0,
        })
        cell["n_requests"] += 1
        cell["last_ts"] = max(cell["last_ts"], ts)
        status = int(r.get("status") or 0)
        if 200 <= status < 300:
            cell["status_2xx"] += 1
        elif 400 <= status < 500:
            cell["status_4xx"] += 1
        elif 500 <= status < 600:
            cell["status_5xx"] += 1
    for cell in by_key.values():
        cell["req_per_s"] = cell["n_requests"] / max(window_s, 1.0)
    return by_key


# ── leaderboard (inline dedupe so we don't depend on the phase-bench-4 module) ──


def _leaderboard_key(entry: dict) -> tuple:
    return (
        entry.get("submission_hash") or "",
        entry.get("splits_version") or "",
        entry.get("split") or "",
        int(entry.get("seed") or 0),
    )


def dedupe_leaderboard(entries: list[dict]) -> list[dict]:
    """Keep the latest entry per (submission_hash, splits_version,
    split, seed). `latest` is by `submitted_at` (ISO-8601, lex-sortable
    when the suffix is consistent)."""
    by_key: dict[tuple, dict] = {}
    for e in entries:
        if not isinstance(e, dict):
            continue
        k = _leaderboard_key(e)
        prior = by_key.get(k)
        if prior is None or (e.get("submitted_at") or "") >= (prior.get("submitted_at") or ""):
            by_key[k] = e
    return list(by_key.values())


def leaderboard_view(
    leaderboard_path: pathlib.Path, *, sort_by: str = "pr_auc",
) -> dict:
    """Read the leaderboard JSONL, dedupe, group by
    (splits_version, split, seed), sort each group by primary[sort_by]
    desc. Returns a structure the dashboard can render directly."""
    entries = read_jsonl(leaderboard_path)
    deduped = dedupe_leaderboard(entries)
    groups: dict[tuple, list[dict]] = {}
    for e in deduped:
        sv = e.get("splits_version") or ""
        sp = e.get("split") or ""
        seed = int(e.get("seed") or 0)
        groups.setdefault((sv, sp, seed), []).append(e)

    def _sort_key(e: dict) -> float:
        v = (e.get("primary") or {}).get(sort_by)
        try:
            x = float(v)
        except (TypeError, ValueError):
            return float("-inf")
        return float("-inf") if x != x else x  # NaN sinks

    out_groups: list[dict] = []
    for (sv, sp, seed) in sorted(groups):
        rows = sorted(groups[(sv, sp, seed)], key=_sort_key, reverse=True)
        out_groups.append({
            "splits_version": sv,
            "split": sp,
            "seed": seed,
            "n_entries": len(rows),
            "entries": rows,
        })
    return {
        "n_raw": len(entries),
        "n_deduped": len(deduped),
        "sort_by": sort_by,
        "groups": out_groups,
    }


# ── alert-fatigue + sweep loaders ───────────────────────────────────


def read_alert_fatigue(path: pathlib.Path) -> Optional[dict]:
    """Latest `data/host/alert_fatigue.json` contents, or None when
    no host run has happened yet."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def find_latest_sweep(reports_dir: pathlib.Path) -> Optional[pathlib.Path]:
    """Most-recent `sweep_<ts>.json` by filename."""
    if not reports_dir.exists():
        return None
    candidates = sorted(reports_dir.glob("sweep_*.json"))
    return candidates[-1] if candidates else None


def read_latest_sweep(reports_dir: pathlib.Path) -> Optional[dict]:
    path = find_latest_sweep(reports_dir)
    if path is None:
        return None
    try:
        return {"path": str(path), "report": json.loads(path.read_text())}
    except json.JSONDecodeError:
        return None


# ── final-safety scrubber ───────────────────────────────────────────


_ACCURACY_RE = re.compile(r"accuracy", re.IGNORECASE)


def assert_no_accuracy(payload: Any, *, source: str) -> None:
    """Belt + suspenders. The artifacts we read have their own
    `accuracy`-rejection gates, but the dashboard re-checks at render
    time so a future regression elsewhere doesn't leak the forbidden
    word through us."""
    blob = json.dumps(payload, default=str)
    if _ACCURACY_RE.search(blob):
        raise RuntimeError(
            f"[dashboard] refusing to serve {source}: contains 'accuracy'"
        )


# ── HTML template (kept inline so no jinja2 / template dir is needed) ──


_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Cernis live dashboard</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  :root {
    --bg: #0f1115; --panel: #161a21; --border: #242a33;
    --ink: #e7eaee; --ink-dim: #8b94a3; --accent: #8ab4ff;
    --good: #75d175; --warn: #f4c869; --bad: #ef6b6b;
  }
  * { box-sizing: border-box; }
  body { background: var(--bg); color: var(--ink); margin: 0;
         font-family: -apple-system, "SF Mono", ui-monospace, Menlo, monospace;
         font-size: 13px; line-height: 1.45; }
  header { padding: 14px 20px; border-bottom: 1px solid var(--border);
           display: flex; align-items: baseline; gap: 16px; }
  header h1 { font-size: 14px; margin: 0; font-weight: 600; letter-spacing: 0.04em; }
  header .meta { color: var(--ink-dim); font-size: 12px; }
  header .pill { font-size: 11px; color: var(--bg); background: var(--accent);
                 padding: 2px 8px; border-radius: 10px; font-weight: 600; }
  main { padding: 16px; display: grid; gap: 16px;
         grid-template-columns: 1fr 1fr; }
  @media (max-width: 1100px) { main { grid-template-columns: 1fr; } }
  .panel { background: var(--panel); border: 1px solid var(--border);
           border-radius: 8px; padding: 14px 16px; overflow: hidden; }
  .panel h2 { font-size: 12px; font-weight: 600; margin: 0 0 8px 0;
              letter-spacing: 0.05em; color: var(--ink-dim); text-transform: uppercase; }
  .panel.span-2 { grid-column: 1 / -1; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th, td { padding: 5px 8px; border-bottom: 1px solid var(--border);
           text-align: left; vertical-align: top; }
  th { font-weight: 600; color: var(--ink-dim); font-size: 11px;
       text-transform: uppercase; letter-spacing: 0.04em; }
  td.num { text-align: right; font-variant-numeric: tabular-nums; }
  .muted { color: var(--ink-dim); }
  .ok { color: var(--good); } .warn { color: var(--warn); } .bad { color: var(--bad); }
  .empty { color: var(--ink-dim); font-style: italic; padding: 8px 0; }
  .group-head { font-size: 11px; color: var(--ink-dim); margin: 10px 0 4px 0;
                letter-spacing: 0.05em; }
  .footer { padding: 8px 20px 18px; color: var(--ink-dim); font-size: 11px;
            border-top: 1px solid var(--border); }
  code { background: #0b0d12; padding: 1px 5px; border-radius: 3px;
         color: var(--accent); }
  .stale { opacity: 0.5; }
  .panel-rule { display: flex; gap: 12px; flex-wrap: wrap; align-items: baseline;
                margin-bottom: 6px; color: var(--ink-dim); font-size: 11px; }
  .stale-pill { background: var(--warn); color: var(--bg); padding: 0 6px;
                border-radius: 6px; font-size: 10px; }
</style>
</head>
<body>
<header>
  <h1>CERNIS</h1>
  <span class="pill">live</span>
  <span class="meta" id="lastUpdate">starting…</span>
  <span class="meta" id="dataDir"></span>
</header>
<main>

  <section class="panel">
    <h2>Live sweep — sessions by family (5 min)</h2>
    <div class="panel-rule"><span id="sessRule"></span></div>
    <div id="sessByFamily">loading…</div>
  </section>

  <section class="panel">
    <h2>Request rate (60s)</h2>
    <div class="panel-rule"><span id="reqRule"></span></div>
    <div id="reqRate">loading…</div>
  </section>

  <section class="panel span-2">
    <h2>Leaderboard — phase-bench-4</h2>
    <div class="panel-rule"><span id="lbRule"></span></div>
    <div id="leaderboard">loading…</div>
  </section>

  <section class="panel span-2">
    <h2>Alert-fatigue (host) — latest run</h2>
    <div class="panel-rule"><span id="afRule"></span></div>
    <div id="alertFatigue">loading…</div>
  </section>

  <section class="panel span-2">
    <h2>Recent sessions (provenance tail)</h2>
    <div class="panel-rule"><span id="tailRule"></span></div>
    <div id="sessTail">loading…</div>
  </section>

</main>

<div class="footer">
  Cernis dashboard · panels poll independently · sessions+requests
  every 2s · leaderboard every 5s · alert-fatigue every 10s ·
  read-only: no eval is triggered by this view.
</div>

<script>
function fmtAgo(ts) {
  if (!ts) return "n/a";
  const dt = Date.now()/1000 - ts;
  if (dt < 60)   return Math.round(dt) + "s ago";
  if (dt < 3600) return Math.round(dt/60) + "m ago";
  return Math.round(dt/3600) + "h ago";
}
function fmtNum(n, places=2) {
  if (n === null || n === undefined) return "n/a";
  if (typeof n !== "number") return n;
  if (Number.isNaN(n)) return "n/a";
  return n.toFixed(places);
}
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  if (attrs) for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else if (k === "html") e.innerHTML = v;
    else e.setAttribute(k, v);
  }
  for (const kid of kids) {
    if (kid === null || kid === undefined) continue;
    e.appendChild(typeof kid === "string" ? document.createTextNode(kid) : kid);
  }
  return e;
}
function setEmpty(target, msg) {
  target.replaceChildren(el("div", {class: "empty"}, msg));
}

async function poll(url) {
  try {
    const r = await fetch(url);
    if (!r.ok) throw new Error("status " + r.status);
    return await r.json();
  } catch (exc) {
    return {_error: String(exc)};
  }
}

async function pollSessions() {
  const data = await poll("/api/sessions/by_family?window_s=300");
  const tgt = document.getElementById("sessByFamily");
  const rule = document.getElementById("sessRule");
  if (data._error) { setEmpty(tgt, "error: " + data._error); return; }
  const fams = data.by_family || {};
  const keys = Object.keys(fams).sort((a, b) => fams[b].n - fams[a].n);
  rule.textContent = `${keys.length} families · ${data.window_s}s window`;
  if (keys.length === 0) { setEmpty(tgt, "no sessions in window"); return; }
  const table = el("table", null,
    el("thead", null,
      el("tr", null,
        el("th", null, "family"),
        el("th", {class: "num"}, "n"),
        el("th", null, "targets"),
        el("th", {class: "num"}, "stealth"),
        el("th", null, "class"),
        el("th", {class: "num"}, "last seen"),
      )));
  const tbody = el("tbody");
  for (const fam of keys) {
    const cell = fams[fam];
    const targets = Object.entries(cell.by_target_app)
      .map(([k, v]) => `${k}:${v}`).join(" ");
    const klass = Object.keys(cell.by_class)[0] || "?";
    const cls = (klass === "agent") ? "bad" :
                (klass === "benign_bot" || klass === "human") ? "ok" : "warn";
    tbody.appendChild(el("tr", null,
      el("td", null, fam),
      el("td", {class: "num"}, String(cell.n)),
      el("td", {class: "muted"}, targets),
      el("td", {class: "num"}, String(cell.by_stealth.stealth)),
      el("td", {class: cls}, klass),
      el("td", {class: "num muted"}, fmtAgo(cell.last_seen)),
    ));
  }
  table.appendChild(tbody);
  tgt.replaceChildren(table);
}

async function pollRequests() {
  const data = await poll("/api/requests/rate?window_s=60");
  const tgt = document.getElementById("reqRate");
  const rule = document.getElementById("reqRule");
  if (data._error) { setEmpty(tgt, "error: " + data._error); return; }
  const by = data.by_key || {};
  const keys = Object.keys(by).sort((a, b) => by[b].req_per_s - by[a].req_per_s);
  rule.textContent = `${keys.length} (family×target) pairs · ${data.window_s}s window`;
  if (keys.length === 0) { setEmpty(tgt, "no requests in window"); return; }
  const table = el("table", null,
    el("thead", null,
      el("tr", null,
        el("th", null, "family"),
        el("th", null, "target"),
        el("th", {class: "num"}, "req/s"),
        el("th", {class: "num"}, "n"),
        el("th", {class: "num"}, "2xx"),
        el("th", {class: "num"}, "4xx"),
        el("th", {class: "num"}, "5xx"),
      )));
  const tbody = el("tbody");
  for (const k of keys) {
    const c = by[k];
    tbody.appendChild(el("tr", null,
      el("td", null, c.family),
      el("td", {class: "muted"}, c.target_app),
      el("td", {class: "num"}, fmtNum(c.req_per_s, 2)),
      el("td", {class: "num"}, String(c.n_requests)),
      el("td", {class: "num ok"}, String(c.status_2xx)),
      el("td", {class: "num warn"}, String(c.status_4xx)),
      el("td", {class: "num bad"}, String(c.status_5xx)),
    ));
  }
  table.appendChild(tbody);
  tgt.replaceChildren(table);
}

async function pollLeaderboard() {
  const data = await poll("/api/leaderboard");
  const tgt = document.getElementById("leaderboard");
  const rule = document.getElementById("lbRule");
  if (data._error) { setEmpty(tgt, "error: " + data._error); return; }
  rule.textContent = `${data.n_deduped}/${data.n_raw} deduped entries · sort: ${data.sort_by}`;
  if (!data.groups || data.groups.length === 0) {
    setEmpty(tgt, "no leaderboard entries yet — run `make eval LEADERBOARD=...`");
    return;
  }
  const frag = document.createDocumentFragment();
  for (const g of data.groups) {
    frag.appendChild(el("div", {class: "group-head"},
      `splits=${g.splits_version} · split=${g.split} · seed=${g.seed} · n=${g.n_entries}`));
    const table = el("table", null,
      el("thead", null,
        el("tr", null,
          el("th", null, "#"),
          el("th", null, "submission"),
          el("th", {class: "num"}, "PR-AUC"),
          el("th", {class: "num"}, "FP/h"),
          el("th", {class: "num"}, "τ"),
          el("th", {class: "num"}, "wall(s)"),
          el("th", {class: "num"}, "peak MB"),
          el("th", null, "runner"),
          el("th", {class: "muted"}, "submitted"),
        )));
    const tbody = el("tbody");
    g.entries.forEach((e, i) => {
      const p = e.primary || {}, r = e.resource || {};
      tbody.appendChild(el("tr", null,
        el("td", {class: "num"}, String(i+1)),
        el("td", null, e.submission || ""),
        el("td", {class: "num"}, fmtNum(p.pr_auc, 4)),
        el("td", {class: "num"}, fmtNum(p.fp_per_hour, 2)),
        el("td", {class: "num"}, fmtNum(p.threshold, 3)),
        el("td", {class: "num"}, fmtNum(r.wall_time_s, 1)),
        el("td", {class: "num"}, fmtNum(r.peak_mem_mb, 1)),
        el("td", {class: "muted"}, e.runner || "python"),
        el("td", {class: "muted"}, e.submitted_at || ""),
      ));
    });
    table.appendChild(tbody);
    frag.appendChild(table);
  }
  tgt.replaceChildren(frag);
}

async function pollAlertFatigue() {
  const data = await poll("/api/alert_fatigue");
  const tgt = document.getElementById("alertFatigue");
  const rule = document.getElementById("afRule");
  if (data._error) { setEmpty(tgt, "error: " + data._error); return; }
  if (!data.report) {
    setEmpty(tgt, "no alert_fatigue.json found at " + data.path);
    rule.textContent = "";
    return;
  }
  const r = data.report;
  rule.textContent =
    `τ=${fmtNum(r.threshold, 3)} · budget=${fmtNum(r.fp_per_hour_budget, 2)} ` +
    `· window≈${fmtNum(r.window_seconds_estimate, 1)}s`;
  const frag = document.createDocumentFragment();

  // deployment estimates
  const deps = r.deployment_estimates || [];
  if (deps.length) {
    frag.appendChild(el("div", {class: "group-head"},
      `deployment FP/hour estimates (n=${deps.length})`));
    const table = el("table", null,
      el("thead", null,
        el("tr", null,
          el("th", null, "deployment"),
          el("th", {class: "num"}, "hosts"),
          el("th", {class: "num"}, "evt/s/host"),
          el("th", {class: "num"}, "total FP/h"),
          el("th", {class: "num"}, "normal"),
          el("th", {class: "num"}, "hard_neg"),
        )));
    const tbody = el("tbody");
    for (const d of deps) {
      tbody.appendChild(el("tr", null,
        el("td", null, d.deployment || ""),
        el("td", {class: "num"}, String(d.hosts || 0)),
        el("td", {class: "num"}, fmtNum(d.events_per_sec_per_host, 2)),
        el("td", {class: "num"}, fmtNum(d.total_fp_per_hour, 2)),
        el("td", {class: "num muted"}, fmtNum(d.normal_fp_per_hour, 2)),
        el("td", {class: "num muted"}, fmtNum(d.hard_negative_fp_per_hour, 2)),
      ));
    }
    table.appendChild(tbody);
    frag.appendChild(table);
  }

  // MTTD per attack family
  const mttd = r.mttd_by_attack_family || {};
  const mttd_keys = Object.keys(mttd);
  if (mttd_keys.length) {
    frag.appendChild(el("div", {class: "group-head"}, "MTTD per attack family"));
    const table = el("table", null,
      el("thead", null,
        el("tr", null,
          el("th", null, "family"),
          el("th", {class: "num"}, "n campaigns"),
          el("th", {class: "num"}, "detected"),
          el("th", {class: "num"}, "MTTD (s)"),
          el("th", {class: "num"}, "p95 MTTD"),
        )));
    const tbody = el("tbody");
    for (const fam of mttd_keys.sort()) {
      const m = mttd[fam];
      const detected = m.n_detected || 0;
      const total = m.n_campaigns || 0;
      const cls = (total === 0) ? "muted" :
                  (detected === total) ? "ok" :
                  (detected === 0) ? "bad" : "warn";
      tbody.appendChild(el("tr", null,
        el("td", null, fam),
        el("td", {class: "num"}, String(total)),
        el("td", {class: "num " + cls}, `${detected}/${total}`),
        el("td", {class: "num"}, fmtNum(m.mttd_s, 1)),
        el("td", {class: "num muted"}, fmtNum(m.mttd_s_p95, 1)),
      ));
    }
    table.appendChild(tbody);
    frag.appendChild(table);
  }

  // multi-day distribution if present
  if (r.daily && r.daily.deployment_distribution) {
    frag.appendChild(el("div", {class: "group-head"},
      `multi-day distribution · ${(r.daily.days || []).length} days`));
    const dist = r.daily.deployment_distribution;
    const table = el("table", null,
      el("thead", null,
        el("tr", null,
          el("th", null, "deployment"),
          el("th", {class: "num"}, "n days"),
          el("th", {class: "num"}, "median"),
          el("th", {class: "num"}, "p95"),
          el("th", {class: "num"}, "min"),
          el("th", {class: "num"}, "max"),
        )));
    const tbody = el("tbody");
    for (const d of dist) {
      tbody.appendChild(el("tr", null,
        el("td", null, d.deployment || ""),
        el("td", {class: "num"}, String(d.n_days || 0)),
        el("td", {class: "num"}, fmtNum(d.median_total_fp_per_hour, 2)),
        el("td", {class: "num"}, fmtNum(d.p95_total_fp_per_hour, 2)),
        el("td", {class: "num muted"}, fmtNum(d.min_total_fp_per_hour, 2)),
        el("td", {class: "num muted"}, fmtNum(d.max_total_fp_per_hour, 2)),
      ));
    }
    table.appendChild(tbody);
    frag.appendChild(table);
  }

  tgt.replaceChildren(frag);
}

async function pollTail() {
  const data = await poll("/api/sessions/recent?n=30");
  const tgt = document.getElementById("sessTail");
  const rule = document.getElementById("tailRule");
  if (data._error) { setEmpty(tgt, "error: " + data._error); return; }
  const rows = data.rows || [];
  rule.textContent = `${rows.length} latest rows`;
  if (rows.length === 0) {
    setEmpty(tgt, "no sessions yet — start a generator");
    return;
  }
  const table = el("table", null,
    el("thead", null,
      el("tr", null,
        el("th", null, "when"),
        el("th", null, "family"),
        el("th", null, "target"),
        el("th", null, "class"),
        el("th", {class: "num"}, "stealth"),
        el("th", {class: "muted"}, "generator"),
        el("th", {class: "muted"}, "session_id"),
      )));
  const tbody = el("tbody");
  for (const r of rows) {
    const cls = (r.class === "agent") ? "bad" :
                (r.class === "benign_bot" || r.class === "human") ? "ok" : "warn";
    tbody.appendChild(el("tr", null,
      el("td", {class: "muted"}, fmtAgo(r.ts)),
      el("td", null, r.family || ""),
      el("td", {class: "muted"}, r.target_app || ""),
      el("td", {class: cls}, r.class || ""),
      el("td", {class: "num"}, r.stealth ? "yes" : ""),
      el("td", {class: "muted"}, r.generator || ""),
      el("td", {class: "muted"}, (r.session_id || "").slice(0, 12) + "…"),
    ));
  }
  table.appendChild(tbody);
  tgt.replaceChildren(table);
}

async function pollMeta() {
  const r = await fetch("/api/meta");
  if (!r.ok) return;
  const data = await r.json();
  document.getElementById("dataDir").textContent = data.data_dir;
}

async function tick() {
  await Promise.all([pollSessions(), pollRequests(), pollTail()]);
  document.getElementById("lastUpdate").textContent =
    "updated " + new Date().toLocaleTimeString();
}

pollMeta();
tick();
setInterval(tick, 2000);
setInterval(pollLeaderboard, 5000);
setInterval(pollAlertFatigue, 10000);
pollLeaderboard();
pollAlertFatigue();
</script>
</body>
</html>"""


# ── HTTP layer (aiohttp) ────────────────────────────────────────────


def _find_alert_fatigue(data_dir: pathlib.Path, explicit: Optional[pathlib.Path]) -> pathlib.Path:
    """Discover the host-side alert_fatigue.json. Multiple plausible
    layouts exist in the wild:
      - explicit path passed on the CLI (highest priority)
      - `<data_dir>/host/alert_fatigue.json` (web-harness checkout)
      - `<data_dir>/../data/host/alert_fatigue.json` (repo-root layout
        where the host pipeline writes alongside the web-harness data/)
    Returns the FIRST candidate that exists; falls back to the
    web-harness layout so the API can still report
    `report=null` cleanly when the file isn't there yet."""
    if explicit:
        return pathlib.Path(explicit).resolve()
    fallback = data_dir / "host" / "alert_fatigue.json"
    repo_root_path = data_dir.parent / "data" / "host" / "alert_fatigue.json"
    for cand in (fallback, repo_root_path):
        if cand.exists():
            return cand
    return fallback


def make_app(
    data_dir: pathlib.Path,
    *,
    alert_fatigue_path: Optional[pathlib.Path] = None,
):
    """Build the aiohttp web app. `data_dir` is the lab's data/
    directory (where sessions.jsonl + requests.jsonl + reports/ live);
    `alert_fatigue_path` overrides the auto-discovery for the
    host-side report."""
    from aiohttp import web

    data_dir = pathlib.Path(data_dir).resolve()
    sessions_path = data_dir / "sessions.jsonl"
    requests_path = data_dir / "requests.jsonl"
    reports_dir = data_dir / "reports"
    leaderboard_path = reports_dir / "leaderboard.jsonl"
    alert_fatigue_path = _find_alert_fatigue(data_dir, alert_fatigue_path)

    async def index(request):
        return web.Response(text=_HTML, content_type="text/html")

    async def health(request):
        return web.json_response({"ok": True, "ts": time.time()})

    async def meta(request):
        return web.json_response({
            "data_dir": str(data_dir),
            "sessions_path": str(sessions_path),
            "requests_path": str(requests_path),
            "leaderboard_path": str(leaderboard_path),
            "alert_fatigue_path": str(alert_fatigue_path),
        })

    async def api_sessions_recent(request):
        n = int(request.query.get("n", "200"))
        rows = tail_sessions(sessions_path, n=n)
        payload = {"rows": rows}
        assert_no_accuracy(payload, source="sessions/recent")
        return web.json_response(payload)

    async def api_sessions_by_family(request):
        window_s = float(request.query.get("window_s", "300"))
        by_family = sessions_by_family(sessions_path, window_s=window_s)
        payload = {"window_s": window_s, "by_family": by_family}
        assert_no_accuracy(payload, source="sessions/by_family")
        return web.json_response(payload)

    async def api_requests_rate(request):
        window_s = float(request.query.get("window_s", "60"))
        by_key = requests_rate(requests_path, window_s=window_s)
        payload = {"window_s": window_s, "by_key": by_key}
        assert_no_accuracy(payload, source="requests/rate")
        return web.json_response(payload)

    async def api_leaderboard(request):
        sort_by = request.query.get("sort_by", "pr_auc")
        view = leaderboard_view(leaderboard_path, sort_by=sort_by)
        assert_no_accuracy(view, source="leaderboard")
        return web.json_response(view)

    async def api_alert_fatigue(request):
        report = read_alert_fatigue(alert_fatigue_path)
        payload = {"path": str(alert_fatigue_path), "report": report}
        if report is not None:
            assert_no_accuracy(payload, source="alert_fatigue")
        return web.json_response(payload)

    async def api_sweep(request):
        payload = read_latest_sweep(reports_dir) or {"path": None, "report": None}
        if payload.get("report") is not None:
            assert_no_accuracy(payload, source="sweep")
        return web.json_response(payload)

    async def api_llm_spend(request):
        window_s = float(request.query.get("window_s", "86400"))
        payload = llm_spend_summary(sessions_path, window_s=window_s)
        assert_no_accuracy(payload, source="llm_spend")
        return web.json_response(payload)

    app = web.Application()
    app.add_routes([
        web.get("/", index),
        web.get("/api/health", health),
        web.get("/api/meta", meta),
        web.get("/api/sessions/recent", api_sessions_recent),
        web.get("/api/sessions/by_family", api_sessions_by_family),
        web.get("/api/requests/rate", api_requests_rate),
        web.get("/api/leaderboard", api_leaderboard),
        web.get("/api/alert_fatigue", api_alert_fatigue),
        web.get("/api/sweep", api_sweep),
        web.get("/api/llm_spend", api_llm_spend),
    ])
    return app


def main(argv: Optional[list[str]] = None) -> int:
    from aiohttp import web

    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", type=pathlib.Path,
                    default=pathlib.Path("data"))
    ap.add_argument("--alert-fatigue-path", type=pathlib.Path, default=None,
                    help="override the auto-discovery for the host-side "
                         "alert_fatigue.json")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8095)
    args = ap.parse_args(argv)

    app = make_app(args.data_dir, alert_fatigue_path=args.alert_fatigue_path)
    print(f"[dashboard] serving on http://{args.host}:{args.port}  "
          f"data_dir={args.data_dir.resolve()}")
    web.run_app(app, host=args.host, port=args.port, print=None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
