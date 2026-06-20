"""Slack/Discord-style link unfurler.

When a user pastes a URL into chat, Slack and Discord fetch it once to
extract og: / twitter: meta. We mirror that: one HEAD, one GET, parse
og: tags. The whole session is a handful of requests against a couple
of paths.
"""

from __future__ import annotations

import httpx
from bs4 import BeautifulSoup

from benign_bots._common import loop, start_session

UA = "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
LINKS = ["/", "/login.php", "/about.php"]


def _read_og(html: str) -> int:
    """Parse og:/twitter: tags. Returns count of meta tags read.

    Real unfurlers process the response body in-process; the request
    count to the proxy is what we care about for detection.
    """
    soup = BeautifulSoup(html, "html.parser")
    n = 0
    for tag in soup.find_all("meta"):
        prop = (tag.get("property") or tag.get("name") or "").lower()
        if prop.startswith("og:") or prop.startswith("twitter:"):
            n += 1
    return n


def _unfurl(client: httpx.Client, path: str) -> int:
    n = 0
    try:
        client.head(path)
        n += 1
    except httpx.HTTPError:
        pass
    try:
        r = client.get(path)
        n += 1
        if r.status_code == 200 and "text/html" in r.headers.get("Content-Type", ""):
            _read_og(r.text)
    except httpx.HTTPError:
        pass
    return n


def run_session(target: str) -> int:
    client, _ = start_session(
        target,
        family="link_unfurler",
        user_agent=UA,
        config={"links": LINKS},
    )
    with client:
        return loop(len(LINKS), 0.3, lambda i: _unfurl(client, LINKS[i]))
