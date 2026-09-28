"""
Generic URL fetcher tool — fetches the content at a supplied URL and returns
it as plain text. HTML tags are stripped so the agent receives readable prose
rather than raw markup.

The agent uses this to follow reference links from the issue body — e.g. an
Exploit-DB PoC page to find a vendor homepage, or a vendor page to find a
source tarball URL for the affected version.

URLs are chosen by the agent from untrusted content, so the response is read
as a stream with a byte cap and an overall deadline: a huge or slow-drip
response cannot exhaust memory or stall the triage queue.
"""

from __future__ import annotations

import re
import time

import httpx

_TIMEOUT = 20.0          # per-operation (connect / read) timeout
_DEADLINE = 30.0         # overall wall-clock budget for one fetch
_MAX_BYTES = 1_000_000   # stop reading the body after this many bytes
_MAX_CHARS = 8000


def fetch_url(url: str) -> str:
    """
    Fetch the content at *url* and return it as plain text (up to 8000 chars).

    HTML tags are stripped so the agent sees readable text rather than markup.
    Returns an explanatory ``[fetch_url] ...`` string on HTTP, connection, or
    deadline errors rather than raising.
    """
    try:
        body, encoding = _read_capped(url)
    except httpx.HTTPStatusError as exc:
        return f"[fetch_url] HTTP {exc.response.status_code} for {url} — try a different URL"
    except httpx.RequestError as exc:
        return f"[fetch_url] Connection error for {url}: {exc}"
    except TimeoutError:
        return f"[fetch_url] Timed out after {_DEADLINE:.0f}s reading {url} — try a different URL"

    try:
        text = body.decode(encoding or "utf-8", errors="replace")
    except LookupError:  # server declared an unknown charset
        text = body.decode("utf-8", errors="replace")
    return _strip_html(text)[:_MAX_CHARS]


def _read_capped(url: str) -> tuple[bytes, str | None]:
    """Stream *url*, returning at most _MAX_BYTES of body within _DEADLINE seconds."""
    deadline = time.monotonic() + _DEADLINE
    chunks: list[bytes] = []
    received = 0
    with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
        with client.stream(
            "GET",
            url,
            headers={"User-Agent": "Mozilla/5.0 (compatible; Fissure-triage/1.0)"},
        ) as response:
            response.raise_for_status()
            for chunk in response.iter_bytes():
                chunks.append(chunk)
                received += len(chunk)
                if received >= _MAX_BYTES:
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError
            encoding = response.charset_encoding
    return b"".join(chunks)[:_MAX_BYTES], encoding


def _strip_html(html: str) -> str:
    # [^<>] (not [^>]) keeps this linear: with [^>], each unmatched "<" scans
    # to the end of the input, which is quadratic on "<<<<...".
    text = re.sub(r"<[^<>]*>", " ", html)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()
