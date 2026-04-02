"""
Unit tests for agents/triage/tools/poc_search.py.

All HTTP calls are mocked — no live requests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from agents.triage.tools.poc_search import search_poc


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_response(body: dict, status_code: int = 200) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = body
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def _github_item(name: str, full_name: str, html_url: str) -> dict:
    return {
        "name": name,
        "html_url": html_url,
        "repository": {"full_name": full_name},
    }


def _make_client_ctx(response: MagicMock) -> MagicMock:
    """Return a mock httpx.Client context manager that returns *response*."""
    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get.return_value = response
    return mock_client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSearchPocMissingToken:
    def test_raises_when_github_token_absent(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="GITHUB_TOKEN"):
                search_poc("CVE-2023-4863")


class TestSearchPocGitHub:
    def test_github_results_parsed_correctly(self):
        gh_body = {
            "items": [
                _github_item("poc.py", "hacker/CVE-2023-4863", "https://github.com/hacker/CVE-2023-4863/blob/main/poc.py"),
                _github_item("exploit.c", "researcher/libwebp-poc", "https://github.com/researcher/libwebp-poc/blob/main/exploit.c"),
            ]
        }
        edb_body = {"data": []}

        gh_resp = _make_response(gh_body)
        edb_resp = _make_response(edb_body)

        mock_gh_client = _make_client_ctx(gh_resp)
        mock_edb_client = _make_client_ctx(edb_resp)

        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}), \
             patch("agents.triage.tools.poc_search.httpx.Client") as mock_cls:
            mock_cls.side_effect = [mock_gh_client, mock_edb_client]
            result = search_poc("CVE-2023-4863")

        assert len(result["github"]) == 2
        first = result["github"][0]
        assert first["html_url"] == "https://github.com/hacker/CVE-2023-4863/blob/main/poc.py"
        assert first["repository"]["full_name"] == "hacker/CVE-2023-4863"
        assert first["name"] == "poc.py"

    def test_github_results_capped_at_five(self):
        items = [
            _github_item(f"poc{i}.py", f"user/repo{i}", f"https://github.com/user/repo{i}/blob/main/poc{i}.py")
            for i in range(10)
        ]
        gh_body = {"items": items}
        edb_body = {"data": []}

        gh_resp = _make_response(gh_body)
        edb_resp = _make_response(edb_body)

        mock_gh_client = _make_client_ctx(gh_resp)
        mock_edb_client = _make_client_ctx(edb_resp)

        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}), \
             patch("agents.triage.tools.poc_search.httpx.Client") as mock_cls:
            mock_cls.side_effect = [mock_gh_client, mock_edb_client]
            result = search_poc("CVE-2023-4863")

        assert len(result["github"]) <= 5

    def test_github_empty_results(self):
        gh_body = {"items": []}
        edb_body = {"data": []}

        gh_resp = _make_response(gh_body)
        edb_resp = _make_response(edb_body)

        mock_gh_client = _make_client_ctx(gh_resp)
        mock_edb_client = _make_client_ctx(edb_resp)

        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}), \
             patch("agents.triage.tools.poc_search.httpx.Client") as mock_cls:
            mock_cls.side_effect = [mock_gh_client, mock_edb_client]
            result = search_poc("CVE-2023-9999")

        assert result["github"] == []
        assert result["exploitdb"] == []


class TestSearchPocExploitDB:
    def test_exploitdb_results_parsed_correctly(self):
        gh_body = {"items": []}
        edb_body = {
            "data": [
                {"id": "51572", "description": "libwebp 1.3.1 - Heap Buffer Overflow"},
                {"id": "51573", "description": "libwebp - Another PoC"},
            ]
        }

        gh_resp = _make_response(gh_body)
        edb_resp = _make_response(edb_body)

        mock_gh_client = _make_client_ctx(gh_resp)
        mock_edb_client = _make_client_ctx(edb_resp)

        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}), \
             patch("agents.triage.tools.poc_search.httpx.Client") as mock_cls:
            mock_cls.side_effect = [mock_gh_client, mock_edb_client]
            result = search_poc("CVE-2023-4863")

        assert len(result["exploitdb"]) == 2
        first = result["exploitdb"][0]
        assert first["id"] == "51572"
        assert first["description"] == "libwebp 1.3.1 - Heap Buffer Overflow"
        assert first["url"] == "https://www.exploit-db.com/exploits/51572"

    def test_exploitdb_returns_empty_list_on_no_results(self):
        gh_body = {"items": []}
        edb_body = {"data": []}

        gh_resp = _make_response(gh_body)
        edb_resp = _make_response(edb_body)

        mock_gh_client = _make_client_ctx(gh_resp)
        mock_edb_client = _make_client_ctx(edb_resp)

        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}), \
             patch("agents.triage.tools.poc_search.httpx.Client") as mock_cls:
            mock_cls.side_effect = [mock_gh_client, mock_edb_client]
            result = search_poc("CVE-2023-9999")

        assert result["exploitdb"] == []

    def test_exploitdb_returns_empty_list_on_http_error(self):
        gh_body = {"items": []}

        gh_resp = _make_response(gh_body)
        edb_resp = _make_response({}, status_code=503)

        mock_gh_client = _make_client_ctx(gh_resp)
        mock_edb_client = _make_client_ctx(edb_resp)

        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}), \
             patch("agents.triage.tools.poc_search.httpx.Client") as mock_cls:
            mock_cls.side_effect = [mock_gh_client, mock_edb_client]
            result = search_poc("CVE-2023-4863")

        assert result["exploitdb"] == []
        assert "github" in result

    def test_exploitdb_returns_empty_list_on_json_decode_error(self):
        gh_body = {"items": []}

        gh_resp = _make_response(gh_body)
        edb_resp = MagicMock(spec=httpx.Response)
        edb_resp.status_code = 200
        edb_resp.raise_for_status.return_value = None
        edb_resp.json.side_effect = ValueError("No JSON")

        mock_gh_client = _make_client_ctx(gh_resp)
        mock_edb_client = _make_client_ctx(edb_resp)

        with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}), \
             patch("agents.triage.tools.poc_search.httpx.Client") as mock_cls:
            mock_cls.side_effect = [mock_gh_client, mock_edb_client]
            result = search_poc("CVE-2023-4863")

        assert result["exploitdb"] == []
