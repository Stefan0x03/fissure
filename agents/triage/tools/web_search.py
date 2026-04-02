"""
Web search tool — returns the top result URLs for a query via DuckDuckGo.

No API key required. Returns a list of result dicts so the agent can decide
which URLs to follow with fetch_url rather than receiving a wall of text.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

import httpx

_DDG_URL = "https://html.duckduckgo.com/html/"
_TIMEOUT = 20.0
_MAX_RESULTS = 8


def web_search(query: str) -> list[dict[str, Any]]:
    """
    Search the web for *query* and return up to 8 results.

    Each result dict contains:
    - ``url`` — the result URL
    - ``title`` — the result title (may be empty if not parsed)

    Returns an empty list on HTTP errors rather than raising, so the agent
    can try a different query or fall back gracefully.
    """
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            response = client.get(
                _DDG_URL,
                params={"q": query},
                headers={"User-Agent": "Mozilla/5.0 (compatible; Fissure-triage/1.0)"},
            )
            response.raise_for_status()
    except (httpx.HTTPStatusError, httpx.RequestError):
        return []

    html = response.text

    # Extract destination URLs from DuckDuckGo redirect links (uddg= param).
    raw_links = re.findall(r"uddg=([^&\"]+)", html)
    urls = [urllib.parse.unquote(u) for u in raw_links]

    # Extract titles from result__a anchor text.
    title_matches = re.findall(
        r'class="result__a"[^>]*>([^<]+)</a>', html
    )

    results = []
    seen: set[str] = set()
    for i, url in enumerate(urls):
        if url in seen:
            continue
        seen.add(url)
        title = title_matches[i].strip() if i < len(title_matches) else ""
        results.append({"url": url, "title": title})
        if len(results) >= _MAX_RESULTS:
            break

    return results
