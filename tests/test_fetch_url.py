"""
Unit tests for agents/triage/tools/fetch_url.py.

HTTP is served by httpx.MockTransport — no live requests.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import httpx

from agents.triage.tools import fetch_url as fetch_url_mod
from agents.triage.tools.fetch_url import _strip_html, fetch_url

_RealClient = httpx.Client


def _patch_transport(handler):
    """Route fetch_url's httpx.Client through a MockTransport calling *handler*."""
    return patch.object(
        fetch_url_mod.httpx,
        "Client",
        side_effect=lambda **kw: _RealClient(transport=httpx.MockTransport(handler), **kw),
    )


class _CountingStream(httpx.SyncByteStream):
    """Yields *chunk* up to *limit* times, recording how many were consumed."""

    def __init__(self, chunk: bytes, limit: int, delay: float = 0.0) -> None:
        self.chunk = chunk
        self.limit = limit
        self.delay = delay
        self.consumed = 0

    def __iter__(self):
        for _ in range(self.limit):
            if self.delay:
                time.sleep(self.delay)
            self.consumed += 1
            yield self.chunk


class TestFetchUrl:
    def test_strips_html_and_returns_text(self):
        html = b"<html><body><h1>libfoo</h1><p>Heap overflow in foo_parse()</p></body></html>"
        with _patch_transport(lambda req: httpx.Response(200, content=html)):
            result = fetch_url("https://example.org/advisory")
        assert "libfoo" in result
        assert "Heap overflow in foo_parse()" in result
        assert "<" not in result

    def test_output_capped_at_max_chars(self):
        with _patch_transport(lambda req: httpx.Response(200, content=b"a" * 50_000)):
            result = fetch_url("https://example.org/big")
        assert len(result) == fetch_url_mod._MAX_CHARS

    def test_http_error_returns_message(self):
        with _patch_transport(lambda req: httpx.Response(404)):
            result = fetch_url("https://example.org/missing")
        assert result.startswith("[fetch_url] HTTP 404")

    def test_connection_error_returns_message(self):
        def handler(req):
            raise httpx.ConnectError("refused", request=req)

        with _patch_transport(handler):
            result = fetch_url("https://example.org/down")
        assert result.startswith("[fetch_url] Connection error")

    def test_stops_reading_body_at_byte_cap(self):
        chunk = b"x" * 65_536
        stream = _CountingStream(chunk, limit=10_000)  # ~650 MB if fully read
        with _patch_transport(lambda req: httpx.Response(200, stream=stream)):
            result = fetch_url("https://example.org/huge")
        assert len(result) == fetch_url_mod._MAX_CHARS
        max_chunks = fetch_url_mod._MAX_BYTES // len(chunk) + 1
        assert stream.consumed <= max_chunks

    def test_slow_drip_response_hits_deadline(self):
        stream = _CountingStream(b"x", limit=1_000, delay=0.01)
        with _patch_transport(lambda req: httpx.Response(200, stream=stream)), \
             patch.object(fetch_url_mod, "_DEADLINE", 0.05):
            result = fetch_url("https://example.org/slow")
        assert result.startswith("[fetch_url] Timed out")
        assert stream.consumed < 1_000

    def test_unknown_charset_falls_back_to_utf8(self):
        with _patch_transport(lambda req: httpx.Response(
            200, content=b"caf\xc3\xa9", headers={"content-type": "text/html; charset=bogus-9"},
        )):
            assert fetch_url("https://example.org/charset") == "café"


class TestStripHtml:
    def test_pathological_angle_brackets_are_linear(self):
        # With the old <[^>]+> pattern this input took ~0.5s at 40 KB and grew
        # quadratically; 1 MB would take minutes.
        start = time.perf_counter()
        _strip_html("<" * 1_000_000)
        assert time.perf_counter() - start < 1.0

    def test_strips_tags_with_attributes(self):
        assert _strip_html('<a href="https://x.org/y">link</a> text') == "link text"
