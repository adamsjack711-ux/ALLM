"""Per-(backend, model) list-price table for the Cernis real-LLM matrix.

Single source of truth so the bot's per-session cost field, the sweep's
pre-run cost projection, and the dashboard's 24h spend badge all derive
from the same numbers. Prices below are PUBLIC LIST prices in
**cents per million tokens** as of LAST_REVIEWED — they will drift;
treat this as an estimate, not a contract.

Lookups against (backend, model) pairs that aren't in the table return
None (the bot writes `extra.estimated_cost_cents = null` rather than
guess; the dashboard renders it as 'unpriced'). When you add a new
model, add it here so the projection isn't silently wrong.

## Drift detection (phase 14d)

The bot calls `warn_if_stale()` at startup. When the table hasn't been
reviewed in `STALE_DAYS` days, it prints a one-line warning to stderr.
`python -m generators.real_agent.pricing` (the module's CLI) prints the
full table — operators run it as an annual review starting point.

When you update prices:
  1. Verify each row against the provider's current public pricing page.
  2. Bump `LAST_REVIEWED` to today.
  3. Bump `PRICING_TABLE_VERSION` minor for price changes, major for a
     schema change (e.g. adding cached-prompt rates).
"""

from __future__ import annotations

import datetime as dt
import sys
from typing import Optional, TypedDict


# Schema-vs-content versioning. The version string lives in
# `extra.pricing_table_version` on every per-session provenance row so
# downstream consumers (dashboard, sweep cost projection) can join
# spent-cost against the price list that fed the estimate.
PRICING_TABLE_VERSION = "1.1"
LAST_REVIEWED = dt.date(2026, 6, 25)  # phase 14d ships this discipline
STALE_DAYS = 365


class PriceCents(TypedDict):
    """Cents per million tokens. `input` covers prompt + cached prompt;
    `output` covers completion tokens. We deliberately don't separate
    cached vs uncached input rates — browser-use prompts are mostly
    one-shot, the cache hit rate is low, and the simpler table reads
    better at the consumer."""
    input: float
    output: float


PRICING: dict[tuple[str, str], PriceCents] = {
    # OpenAI list prices (per https://openai.com/api/pricing)
    ("openai", "gpt-4o-mini"):   {"input":  15.0, "output":   60.0},
    ("openai", "gpt-4o"):        {"input": 250.0, "output": 1000.0},
    ("openai", "gpt-4-turbo"):   {"input": 1000.0, "output": 3000.0},

    # Anthropic list prices (per https://www.anthropic.com/pricing)
    ("anthropic", "claude-haiku-4-5"): {"input":  80.0, "output":  400.0},
    ("anthropic", "claude-sonnet-4-6"): {"input": 300.0, "output": 1500.0},
    ("anthropic", "claude-opus-4-7"):   {"input": 1500.0, "output": 7500.0},
}


# Per-session token defaults for the PRE-RUN projection (when no actual
# session has been measured yet). Tuned conservatively for browser-use
# DVWA-style tasks: ~15 LLM calls per session × ~600 prompt + ~150
# completion tokens each. Real sessions vary widely; the projection is
# meant as an upper-bound sanity check, not an accountant's invoice.
DEFAULT_TOKENS_PER_SESSION = {"input": 9000, "output": 2250}


def lookup(backend: str, model: str) -> Optional[PriceCents]:
    """Return the price entry for (backend, model), or None if unpriced.

    Lookup is case-sensitive on backend, exact-match on model. Model
    aliases (e.g. provider-side `gpt-4o-mini-2024-07-18`) are not
    resolved — callers should pass the model name they use in their
    LLM constructor.
    """
    return PRICING.get((backend, model))


def estimate_cost_cents(
    backend: str, model: str,
    tokens_in: int, tokens_out: int,
) -> Optional[float]:
    """(tokens_in × input_rate + tokens_out × output_rate) / 1M tokens.

    Returns None for unpriced (backend, model) pairs so the consumer
    can render 'unpriced' rather than a misleading $0.00. Returns 0.0
    for priced pairs with zero token counts."""
    p = lookup(backend, model)
    if p is None:
        return None
    return (tokens_in * p["input"] + tokens_out * p["output"]) / 1_000_000.0


def estimate_session_projection(backend: str, model: str) -> Optional[float]:
    """Pre-run cost estimate (cents) for ONE session against this
    (backend, model), using DEFAULT_TOKENS_PER_SESSION. Used by the
    sweep's pre-run projection block."""
    return estimate_cost_cents(
        backend, model,
        DEFAULT_TOKENS_PER_SESSION["input"],
        DEFAULT_TOKENS_PER_SESSION["output"],
    )


def format_cents(cents: Optional[float]) -> str:
    """`None` → 'unpriced'. Sub-cent values render as $0.00xxx. Cents
    >= 100 render as $X.YY. Used by the bot's startup banner + sweep
    pre-run printout."""
    if cents is None:
        return "unpriced"
    dollars = cents / 100.0
    if dollars < 0.01:
        return f"${dollars:.4f}"
    return f"${dollars:.2f}"


# ── phase 14d: drift detection ──────────────────────────────────────


def staleness_days(now: Optional[dt.date] = None) -> int:
    """Days since LAST_REVIEWED. Used by `warn_if_stale()` and exposed
    to the smoke. `now` lets the smoke spoof time without touching
    `dt.date.today()`."""
    today = now if now is not None else dt.date.today()
    return (today - LAST_REVIEWED).days


def is_stale(now: Optional[dt.date] = None) -> bool:
    return staleness_days(now) > STALE_DAYS


def warn_if_stale(stream=None, now: Optional[dt.date] = None) -> bool:
    """One-line stderr warning when the table hasn't been reviewed in
    STALE_DAYS days. Returns True iff a warning was emitted.

    The bot calls this once at startup. Negative staleness (LAST_REVIEWED
    in the future) is treated as fresh — clock skew on the host
    shouldn't trigger spurious warnings."""
    days = staleness_days(now)
    if days <= STALE_DAYS:
        return False
    out = stream if stream is not None else sys.stderr
    print(
        f"[pricing] table v{PRICING_TABLE_VERSION} last reviewed "
        f"{LAST_REVIEWED.isoformat()} ({days} days ago, > {STALE_DAYS}d "
        f"threshold). Re-verify against provider pricing pages and "
        f"bump LAST_REVIEWED.",
        file=out,
    )
    return True


def print_table(stream=None) -> None:
    """Operator entry point: dump every row + the review metadata.
    `python -m generators.real_agent.pricing` calls this."""
    out = stream if stream is not None else sys.stdout
    days = staleness_days()
    flag = "STALE" if is_stale() else "fresh"
    print(
        f"Cernis pricing table v{PRICING_TABLE_VERSION} · "
        f"last reviewed {LAST_REVIEWED.isoformat()} "
        f"({days} days ago — {flag})",
        file=out,
    )
    print(file=out)
    print(f"{'backend':<12} {'model':<26} {'in ¢/M':>10} {'out ¢/M':>10}",
          file=out)
    print("-" * 62, file=out)
    for (backend, model), p in sorted(PRICING.items()):
        print(
            f"{backend:<12} {model:<26} "
            f"{p['input']:>10.2f} {p['output']:>10.2f}",
            file=out,
        )
    print(file=out)
    print(f"default session envelope: "
          f"{DEFAULT_TOKENS_PER_SESSION['input']} input / "
          f"{DEFAULT_TOKENS_PER_SESSION['output']} output tokens",
          file=out)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI: `python -m generators.real_agent.pricing` prints the table."""
    print_table()
    return 0


if __name__ == "__main__":
    sys.exit(main())
