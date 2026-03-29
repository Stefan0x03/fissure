"""
Unit tests for agents/triage/tools/nvd.py.

All HTTP calls are mocked — no live NVD requests.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest

from agents.triage.tools.nvd import fetch_cves_by_date_range


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_START = datetime(2024, 1, 1, tzinfo=timezone.utc)
_END = datetime(2024, 1, 3, tzinfo=timezone.utc)


def _make_response(
    vulns: list[dict],
    total: int | None = None,
    status_code: int = 200,
) -> MagicMock:
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.json.return_value = {
        "vulnerabilities": vulns,
        "totalResults": total if total is not None else len(vulns),
        "resultsPerPage": len(vulns),
        "startIndex": 0,
    }
    if status_code >= 400:
        resp.raise_for_status.side_effect = httpx.HTTPStatusError(
            "error", request=MagicMock(), response=resp
        )
    else:
        resp.raise_for_status.return_value = None
    return resp


def _vuln(cve_id: str) -> dict:
    return {"cve": {"id": cve_id, "descriptions": [], "weaknesses": []}}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFetchCVEsByDateRange:
    def test_returns_empty_list_when_no_results(self):
        resp = _make_response([], total=0)
        with patch("agents.triage.tools.nvd.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = resp
            mock_client_cls.return_value = mock_client

            result = fetch_cves_by_date_range(_START, _END)

        assert result == []

    def test_returns_single_page_of_results(self):
        vulns = [_vuln("CVE-2024-0001"), _vuln("CVE-2024-0002")]
        resp = _make_response(vulns)
        with patch("agents.triage.tools.nvd.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = resp
            mock_client_cls.return_value = mock_client

            result = fetch_cves_by_date_range(_START, _END)

        assert len(result) == 2
        assert result[0]["cve"]["id"] == "CVE-2024-0001"

    def test_paginates_across_multiple_pages(self):
        page1 = [_vuln(f"CVE-2024-{i:04d}") for i in range(3)]
        page2 = [_vuln(f"CVE-2024-{i:04d}") for i in range(3, 5)]

        resp1 = _make_response(page1, total=5)
        resp2 = _make_response(page2, total=5)

        with patch("agents.triage.tools.nvd.httpx.Client") as mock_client_cls, \
             patch("agents.triage.tools.nvd.time.sleep"):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.side_effect = [resp1, resp2]
            mock_client_cls.return_value = mock_client

            result = fetch_cves_by_date_range(_START, _END)

        assert len(result) == 5
        assert mock_client.get.call_count == 2

    def test_raises_on_http_error(self):
        resp = _make_response([], status_code=403)
        with patch("agents.triage.tools.nvd.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = resp
            mock_client_cls.return_value = mock_client

            with pytest.raises(httpx.HTTPStatusError):
                fetch_cves_by_date_range(_START, _END)

    def test_requires_timezone_aware_datetimes(self):
        naive = datetime(2024, 1, 1)
        with pytest.raises(ValueError, match="timezone-aware"):
            fetch_cves_by_date_range(naive, _END)
        with pytest.raises(ValueError, match="timezone-aware"):
            fetch_cves_by_date_range(_START, naive)

    def test_uses_api_key_header_when_env_set(self):
        resp = _make_response([])
        with patch("agents.triage.tools.nvd.httpx.Client") as mock_client_cls, \
             patch.dict("os.environ", {"NVD_API_KEY": "test-key-123"}):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = resp
            mock_client_cls.return_value = mock_client

            fetch_cves_by_date_range(_START, _END)

        _, kwargs = mock_client.get.call_args
        assert kwargs["headers"]["apiKey"] == "test-key-123"

    def test_no_api_key_header_when_env_absent(self):
        resp = _make_response([])
        with patch("agents.triage.tools.nvd.httpx.Client") as mock_client_cls, \
             patch.dict("os.environ", {}, clear=True):
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = resp
            mock_client_cls.return_value = mock_client

            fetch_cves_by_date_range(_START, _END)

        _, kwargs = mock_client.get.call_args
        assert "apiKey" not in kwargs["headers"]

    def test_passes_correct_date_params(self):
        resp = _make_response([])
        with patch("agents.triage.tools.nvd.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get.return_value = resp
            mock_client_cls.return_value = mock_client

            fetch_cves_by_date_range(_START, _END)

        _, kwargs = mock_client.get.call_args
        params = kwargs["params"]
        assert params["pubStartDate"] == "2024-01-01T00:00:00.000"
        assert params["pubEndDate"] == "2024-01-03T00:00:00.000"
