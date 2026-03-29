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


def _advisory_payload(cve_id: str = "CVE-2023-4863") -> dict:
    """Minimal but realistic GraphQL response for a single advisory."""
    return {
        "data": {
            "securityAdvisories": {
                "nodes": [
                    {
                        "ghsaId": "GHSA-j7hp-h8jx-5ppr",
                        "summary": "Heap buffer overflow in libwebp",
                        "description": "A heap buffer overflow exists in libwebp...",
                        "severity": "CRITICAL",
                        "publishedAt": "2023-09-12T00:00:00Z",
                        "updatedAt": "2023-09-14T00:00:00Z",
                        "cvss": {
                            "score": 9.8,
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                        "cwes": {
                            "nodes": [
                                {"cweId": "CWE-787", "name": "Out-of-bounds Write"}
                            ]
                        },
                        "references": [
                            {"url": "https://github.com/webmproject/libwebp/security/advisories/GHSA-j7hp-h8jx-5ppr"},
                            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-4863"},
                        ],
                        "vulnerabilities": {
                            "nodes": [
                                {
                                    "package": {"name": "libwebp", "ecosystem": "OTHER"},
                                    "vulnerableVersionRange": "< 1.3.2",
                                    "firstPatchedVersion": {"identifier": "1.3.2"},
                                }
                            ]
                        },
                    }
                ]
            }
        }
    }


def _empty_payload() -> dict:
    return {"data": {"securityAdvisories": {"nodes": []}}}


def _error_payload() -> dict:
    return {"errors": [{"message": "Something went wrong"}]}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFetchGHSAForCVE:
    def _mock_post(self, body: dict, status_code: int = 200):
        resp = _make_response(body, status_code)
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.return_value = resp
        return mock_client

    def test_returns_advisory_when_found(self):
        mock_client = self._mock_post(_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2023-4863")

        assert isinstance(result, GHSAAdvisory)
        assert result.ghsa_id == "GHSA-j7hp-h8jx-5ppr"
        assert result.severity == "CRITICAL"
        assert result.cvss_score == 9.8
        assert result.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_returns_none_when_no_advisory(self):
        mock_client = self._mock_post(_empty_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2099-99999")

        assert result is None

    def test_parses_cwes(self):
        mock_client = self._mock_post(_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2023-4863")

        assert result.cwes == [{"cweId": "CWE-787", "name": "Out-of-bounds Write"}]

    def test_parses_references(self):
        mock_client = self._mock_post(_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2023-4863")

        assert len(result.references) == 2
        assert "GHSA-j7hp-h8jx-5ppr" in result.references[0]

    def test_parses_vulnerabilities(self):
        mock_client = self._mock_post(_advisory_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2023-4863")

        assert len(result.vulnerabilities) == 1
        v = result.vulnerabilities[0]
        assert v["package"] == "libwebp"
        assert v["ecosystem"] == "OTHER"
        assert v["vulnerable_range"] == "< 1.3.2"
        assert v["first_patched"] == "1.3.2"

    def test_raises_on_graphql_errors(self):
        mock_client = self._mock_post(_error_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            with pytest.raises(ValueError, match="GraphQL errors"):
                fetch_ghsa_for_cve("CVE-2023-4863")

    def test_raises_on_http_error(self):
        mock_client = self._mock_post({}, status_code=401)
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            with pytest.raises(httpx.HTTPStatusError):
                fetch_ghsa_for_cve("CVE-2023-4863")

    def test_raises_without_token(self):
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(ValueError, match="token"):
                fetch_ghsa_for_cve("CVE-2023-4863")

    def test_sends_cve_id_as_variable(self):
        mock_client = self._mock_post(_empty_payload())
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            fetch_ghsa_for_cve("CVE-2023-4863")

        _, kwargs = mock_client.post.call_args
        assert kwargs["json"]["variables"]["cveId"] == "CVE-2023-4863"

    def test_handles_missing_first_patched_version(self):
        payload = _advisory_payload()
        payload["data"]["securityAdvisories"]["nodes"][0]["vulnerabilities"]["nodes"][0][
            "firstPatchedVersion"
        ] = None
        mock_client = self._mock_post(payload)
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2023-4863")

        assert result.vulnerabilities[0]["first_patched"] is None

    def test_handles_missing_cvss(self):
        payload = _advisory_payload()
        payload["data"]["securityAdvisories"]["nodes"][0]["cvss"] = {}
        mock_client = self._mock_post(payload)
        with patch("agents.triage.tools.ghsa.httpx.Client", return_value=mock_client), \
             patch.dict("os.environ", {"GITHUB_TOKEN": "test-token"}):
            result = fetch_ghsa_for_cve("CVE-2023-4863")

        assert result.cvss_score is None
        assert result.cvss_vector is None
