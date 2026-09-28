"""
Unit tests for scripts/ingest.py deduplication (_fetch_existing_cve_ids).

All HTTP calls are mocked — no live requests.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx

from scripts.ingest import _fetch_existing_cve_ids

_BOT = "github-actions[bot]"


def _issue(title: str, login: str = _BOT, *, pr: bool = False) -> dict:
    issue = {"title": title, "user": {"login": login}}
    if pr:
        issue["pull_request"] = {"url": "https://api.github.com/pulls/1"}
    return issue


def _run(issues: list[dict]) -> tuple[set[str], MagicMock]:
    resp = MagicMock(spec=httpx.Response)
    resp.raise_for_status.return_value = None
    resp.json.return_value = issues

    mock_client = MagicMock()
    mock_client.__enter__ = MagicMock(return_value=mock_client)
    mock_client.__exit__ = MagicMock(return_value=False)
    mock_client.get.return_value = resp

    with patch.dict("os.environ", {"GITHUB_TOKEN": "tok"}), \
         patch("scripts.ingest.httpx.Client", return_value=mock_client):
        result = _fetch_existing_cve_ids("owner/repo")
    return result, mock_client


class TestFetchExistingCveIds:
    def test_bot_candidate_issue_counts(self):
        result, _ = _run([_issue("[Candidate] CVE-2026-12345")])
        assert result == {"CVE-2026-12345"}

    def test_user_issue_with_cve_ids_in_title_ignored(self):
        # A public user listing CVE IDs in a title must not suppress ingestion.
        result, _ = _run([_issue("CVE-2026-1001 CVE-2026-1002 CVE-2026-1003", login="attacker")])
        assert result == set()

    def test_user_issue_with_exact_candidate_title_ignored(self):
        result, _ = _run([_issue("[Candidate] CVE-2026-12345", login="attacker")])
        assert result == set()

    def test_pull_requests_ignored(self):
        result, _ = _run([_issue("[Candidate] CVE-2026-12345", pr=True)])
        assert result == set()

    def test_bot_issue_with_extra_ids_in_title_ignored(self):
        result, _ = _run([_issue("[Candidate] CVE-2026-12345 CVE-2026-99999")])
        assert result == set()

    def test_requests_filter_by_bot_creator(self):
        _, client = _run([])
        assert client.get.call_args.kwargs["params"]["creator"] == _BOT
