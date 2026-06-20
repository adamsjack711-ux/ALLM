# `ingest/` — production data collection for the web detector

The lab harness (phases 1–12) is a closed-loop: synthetic generators
drive traffic through a reverse-proxy that injects honeypots + a JS
beacon, and the detector trains on the resulting labeled JSONL.

`ingest/` is the **production-safe** counterpart: a passive shipper
that reads a real webserver's access logs and writes the same
`requests.jsonl` schema, so a model trained in the lab can score
live traffic without further plumbing.

## Why not just run the capture proxy in front of production?

The lab capture proxy intentionally has hostile-to-production
behaviors that surface attacker signal: it mints its own `allm_sid`
cookie (would collide with prod session cookies), injects a JS beacon
on every HTML response (changes prod page behavior), and **injects
honeypots** (`/__canary`, hidden form fields, fake `robots.txt`
Disallow paths) that would leak in front of real users.

The shipper does none of that. It reads logs, period.

## What the shipper does NOT do

- **NO** reverse-proxy injection — it sits outside the request path.
- **NO** honeypot injection — those are a lab artifact.
- **NO** JS beacon injection — never modifies response bodies.
- **NO** cookie minting — real users keep their own session cookies, untouched.
- **NO** request-body or sensitive-header capture — it reads the
  access log only.

## Supported log format

Standard nginx / Apache **combined** log format:

```
$remote_addr - $remote_user [$time_local] "$request" $status
$body_bytes_sent "$http_referer" "$http_user_agent"
```

Example line:
```
192.168.1.42 - - [20/Jun/2026:13:55:36 -0700] "GET /search?q=test HTTP/1.1" 200 1842 "-" "Mozilla/5.0 …"
```

Both default nginx (`/var/log/nginx/access.log`) and Apache's
`combined` LogFormat are this shape. Custom formats need a custom
parser; the regex lives at the top of `access_log_shipper.py` if you
need to extend it.

## Session synthesis

Access logs don't carry a `session_id`. The shipper synthesizes one
per `(src_ip, sha1(user_agent)[:8])` tuple with a **30-minute
inactivity timeout**: when a tuple goes quiet for >30 min, the next
request mints a fresh `session_id`. Override the timeout with
`--inactivity-timeout-s` if your traffic shape differs.

This is a heuristic. Deployments with real session cookies (e.g.
already extracted by a log-enrichment step) can pre-compute the
session_id and skip the stitcher — `SessionStitcher` is a class so
it's swappable.

## Fields the access log can't give us

The detector's feature pipeline tolerates missing fields — they get
safe defaults that `_safe_log1p` handles:

| field | source in lab | source from access log |
|---|---|---|
| `req_bytes` | proxy reads request body | `0` (not logged) |
| `header_count` | proxy reads request | `0` (not logged) |
| `content_type` | proxy reads response | `""` (not logged) |
| `has_auth_header` / `has_cookie_header` | proxy reads headers | `False` (not logged) |
| `elapsed_ms` | proxy times the request | `0` (set `$request_time` in nginx if you want this) |
| `delta_ms` | computed by proxy | computed by shipper from session timestamps |
| `header_hash` | proxy hashes header names | shipper hashes UA + referer |

The lab-trained detector still works because (a) cadence /
sequence / path / status features all survive, and (b) the
**ML-only head** (`detector/eval.py --models <dir>` with `ml_only.pt`)
trains without honeypot inputs anyway and was specifically built for
exactly this "less signal, still meaningful" case.

## Usage

### Backfill an existing log file

```sh
python3 -m ingest.access_log_shipper \
    --log /var/log/nginx/access.log \
    --out /opt/allm/data/requests.jsonl \
    --once \
    --target-app prod \
    --family prod_traffic
```

### Continuous tail

```sh
python3 -m ingest.access_log_shipper \
    --log /var/log/nginx/access.log \
    --out /opt/allm/data/requests.jsonl \
    --follow \
    --target-app prod
```

Polls every 1 second by default — increase with `--poll-interval-s`
on quieter sites.

### Scoring the resulting data

The detector's existing tooling reads `data/requests.jsonl` directly.
Once the shipper is populating that file:

```sh
# one-shot scoring against a trained model
python3 detector/eval.py \
    --data /opt/allm/data \
    --models /path/to/lab-trained-models \
    --out /opt/allm/data/reports/prod_eval.json \
    --fp-per-hour-budget 1.0
```

The `per_family` block will show one entry (`prod_traffic`,
`kind=unknown`); the actionable signal is the **per-session alert
rate** vs your FP/hour budget. For real continuous detection you'd
wrap `detector/alerter.py`'s `StreamingAlerter` around the shipper
output — that's deliberately out of phase 13 scope (single
responsibility: the shipper produces data, scoring is downstream).

## Class / family / target_app tagging

By default the shipper writes:
- `class = "unknown"` — we don't know the ground truth on prod
- `family = "prod_traffic"`
- `target_app = "prod"`

Override with `--klass`, `--family`, `--target-app` if you're shipping
a known-benign segment (e.g. ship internal monitoring traffic with
`--klass human --family internal_monitoring`). **Never set `--klass
agent` without a real label** — the eval rollup treats `class=agent`
as ground-truth-positive and that would silently mis-train if the
same JSONL was fed back into a training loop.

## When NOT to use the shipper

- **In front of crAPI / Juice Shop / DVWA / VAmPI / WebGoat.** Those
  targets live in the lab; point the lab capture proxy at them
  instead — it gives you the beacon + honeypot signal too.
- **On a host with rotated/compressed logs.** This shipper expects
  the live log file; gzipped rotations need decompression upstream.
- **For training data.** Production traffic is unlabeled. The shipper
  produces inference inputs, not training inputs.
