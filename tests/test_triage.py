"""
Smoke tests for scripts/triage.py.

Mocks get_issue_body and run_triage to verify the entrypoint wires them
correctly for a given --issue argument.
"""

from __future__ import annotations

from unittest.mock import call, patch

import pytest

from scripts.triage import main


class TestTriageEntrypoint:
    def test_fetches_issue_body_and_calls_run_triage(self):
        with patch("scripts.triage.get_issue_body", return_value="issue body text") as mock_get, \
             patch("scripts.triage.run_triage") as mock_run:
            exit_code = main(["--issue", "42", "--repo", "owner/repo"])

        assert exit_code == 0
        mock_get.assert_called_once_with(42, "owner/repo")
        mock_run.assert_called_once_with(42, "issue body text", "owner/repo")

    def test_uses_github_repository_env_var_when_no_repo_flag(self):
        with patch("scripts.triage.get_issue_body", return_value="body") as mock_get, \
             patch("scripts.triage.run_triage") as mock_run, \
             patch.dict("os.environ", {"GITHUB_REPOSITORY": "envowner/envrepo"}):
            exit_code = main(["--issue", "7"])

        assert exit_code == 0
        mock_get.assert_called_once_with(7, "envowner/envrepo")
        mock_run.assert_called_once_with(7, "body", "envowner/envrepo")

    def test_returns_error_when_repo_absent(self):
        with patch.dict("os.environ", {}, clear=True):
            exit_code = main(["--issue", "1"])

        assert exit_code == 1

    def test_passes_issue_number_as_int(self):
        with patch("scripts.triage.get_issue_body", return_value="body") as mock_get, \
             patch("scripts.triage.run_triage"):
            main(["--issue", "99", "--repo", "owner/repo"])

        issue_arg = mock_get.call_args[0][0]
        assert isinstance(issue_arg, int)
        assert issue_arg == 99
