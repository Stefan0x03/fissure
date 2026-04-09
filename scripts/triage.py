"""
Triage entrypoint — called by cve-triage.yml.

Usage:
    # Triage a single issue:
    python -m scripts.triage --issue <number> --repo <owner/repo>

    # Drain all untriaged candidate issues (queue mode):
    python -m scripts.triage --repo <owner/repo>
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from agents.triage.agent import run_triage
from scripts.issues import get_issue_body, list_untriaged_candidates

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the Fissure triage agent against a GitHub issue."
    )
    parser.add_argument(
        "--issue",
        type=int,
        required=False,
        default=None,
        metavar="NUMBER",
        help="GitHub issue number to triage (omit to drain the full candidate queue)",
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        metavar="OWNER/REPO",
        help="Repository in owner/repo format (default: $GITHUB_REPOSITORY)",
    )
    return parser.parse_args(argv)


def _triage_single(issue_number: int, repo: str) -> None:
    logger.info("Fetching issue body: #%d from %s", issue_number, repo)
    issue_body = get_issue_body(issue_number, repo)
    logger.info("Starting triage agent for issue #%d", issue_number)
    run_triage(issue_number, issue_body, repo)
    logger.info("Triage complete for issue #%d", issue_number)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if not args.repo:
        logger.error(
            "Repository not specified: use --repo or set GITHUB_REPOSITORY env var"
        )
        return 1

    if args.issue is not None:
        _triage_single(args.issue, args.repo)
        return 0

    # Drain mode — process all untriaged candidate issues sequentially.
    queue = list_untriaged_candidates(args.repo)
    logger.info("Triage queue: %d issue(s) to process", len(queue))

    if not queue:
        logger.info("Nothing to triage — exiting cleanly")
        return 0

    errors = 0
    for issue_number in queue:
        try:
            _triage_single(issue_number, args.repo)
        except Exception:
            logger.exception("Triage failed for issue #%d — continuing", issue_number)
            errors += 1

    if errors:
        logger.warning("%d issue(s) failed during drain", errors)
    return 0


if __name__ == "__main__":
    sys.exit(main())
