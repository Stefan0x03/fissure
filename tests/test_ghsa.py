"""
Unit tests for agents/triage/tools/ghsa.py.

All HTTP calls are mocked — no live GitHub API requests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from agents.triage.tools.ghsa import GHSAAdvisory, fetch_ghsa_for_cve


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_response(body: list | dict, status_code: int = 200) -> MagicMock:
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


def _advisory_payload() -> list:
    """Realistic REST /advisories response for CVE-2016-20049."""
    return [
        {
            "ghsa_id": "GHSA-x5f7-xgg8-pr9p",
            "cve_id": "CVE-2016-20049",
            "summary": "JAD stack-based buffer overflow",
            "description": "JAD 1.5.8e-1kali1 and prior contains a stack-based buffer overflow...",
            "type": "unreviewed",
            "severity": "critical",
            "published_at": "2026-03-28T12:30:29Z",
            "updated_at": "2026-03-28T12:30:35Z",
            "cvss": {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
            },
            "cwes": [
                {"cwe_id": "CWE-787", "name": "Out-of-bounds Write"}
            ],
            "references": [
                "https://nvd.nist.gov/vuln/detail/CVE-2016-20049",
                "https://www.exploit-db.com/exploits/42076",
            ],
            "vulnerabilities": [],
        }
    ]


def _reviewed_advisory_payload() -> list:
    """REST response for a reviewed advisory with vulnerabilities."""
    return [
        {
            "ghsa_id": "GHSA-j7hp-h8jx-5ppr",
            "cve_id": "CVE-2023-4863",
            "summary": "Heap buffer overflow in libwebp",
            "description": "A heap buffer overflow exists in libwebp in versions before 1.3.2.",
            "type": "reviewed",
            "severity": "critical",
            "published_at": "2023-09-12T00:00:00Z",
            "updated_at": "2023-09-14T00:00:00Z",
            "cvss": {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "score": 9.8,
            },
            "cwes": [
                {"cwe_id": "CWE-787", "name": "Out-of-bounds Write"}
            ],
            "references": [
                "https://github.com/webmproject/libwebp/security/advisories/GHSA-j7hp-h8jx-5ppr",
            ],
            "vulnerabilities": [
                {
                    "package": {"name": "libwebp", "ecosystem": "OTHER"},
                    "vulnerable_version_range": "< 1.3.2",
                    "first_patched_version": "1.3.2",
                }
            ],
        }
    ]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFetchGHSAForCVE:
    def _mock_get(self, body, status_code: int = 200):
        resp = _make_response(body, status_code)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get.return_value = resp
        return mock_client

    def test_returns_advisory_when_found(self):
        mock_client = self._mock_get(_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2016-20049")

        assert isinstance(result, GHSAAdvisory)
        assert result.ghsa_id == "GHSA-x5f7-xgg8-pr9p"
        assert result.severity == "critical"
        assert result.advisory_type == "unreviewed"
        assert result.cvss_score == 9.8
        assert result.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_returns_none_when_no_advisory(self):
        mock_client = self._mock_get([])
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2099-99999")

        assert result is None

    def test_parses_cwes(self):
        mock_client = self._mock_get(_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2016-20049")

        assert result.cwes == [{"cwe_id": "CWE-787", "name": "Out-of-bounds Write"}]

    def test_parses_references(self):
        mock_client = self._mock_get(_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2016-20049")

        assert len(result.references) == 2
        assert "exploit-db.com" in result.references[1]

    def test_parses_vulnerabilities_for_reviewed_advisory(self):
        mock_client = self._mock_get(_reviewed_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2023-4863")

        assert len(result.vulnerabilities) == 1
        v = result.vulnerabilities[0]
        assert v["package"] == "libwebp"
        assert v["ecosystem"] == "OTHER"
        assert v["vulnerable_range"] == "< 1.3.2"
        assert v["first_patched"] == "1.3.2"

    def test_empty_vulnerabilities_for_unreviewed(self):
        mock_client = self._mock_get(_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2016-20049")

        assert result.vulnerabilities == []

    def test_raises_on_http_error(self):
        mock_client = self._mock_get({}, status_code=401)
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            with pytest.raises(httpx.HTTPStatusError):
                fetch_ghsa_for_cve("CVE-2016-20049")

    def test_raises_without_token(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="token"):
                fetch_ghsa_for_cve("CVE-2016-20049")

    def test_sends_cve_id_as_query_param(self):
        mock_client = self._mock_get([])
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            fetch_ghsa_for_cve("CVE-2016-20049")

        _, kwargs = mock_client.get.call_args
        assert kwargs["params"]["cve_id"] == "CVE-2016-20049"

    def test_handles_null_cvss(self):
        payload = _advisory_payload()
        payload[0]["cvss"] = None
        mock_client = self._mock_get(payload)
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2016-20049")

        assert result.cvss_score is None
        assert result.cvss_vector is None

    def test_handles_null_cwes(self):
        payload = _advisory_payload()
        payload[0]["cwes"] = None
        mock_client = self._mock_get(payload)
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2016-20049")

        assert result.cwes == []
