"""
Generic URL fetcher tool — fetches the content at a supplied URL and returns
it as plain text. HTML tags are stripped so the agent receives readable prose
rather than raw markup.

The agent uses this to follow reference links from the issue body — e.g. an
Exploit-DB PoC page to find a vendor homepage, or a vendor page to find a
source tarball URL for the affected version.
"""

from __future__ import annotations

import re

import httpx

_TIMEOUT = 20.0
_MAX_CHARS = 8000


def fetch_url(url: str) -> str:
    """
    Fetch the content at *url* and return it as plain text (up to 8000 chars).

    HTML tags are stripped so the agent sees readable text rather than markup.
    Raises ``httpx.HTTPStatusError`` on non-2xx responses.
    """
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            response = client.get(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; Fissure-triage/1.0)"},
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        return f"[fetch_url] HTTP {exc.response.status_code} for {url} — try a different URL"
    except httpx.RequestError as exc:
        return f"[fetch_url] Connection error for {url}: {exc}"

    text = _strip_html(response.text)
    return text[:_MAX_CHARS]


def _strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
