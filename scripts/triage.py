"""
Triage entrypoint — called by cve-triage.yml.

Usage:
    python -m scripts.triage --issue <number> --repo <owner/repo>
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

from agents.triage.agent import run_triage
from scripts.issues import get_issue_body

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
        required=True,
        metavar="NUMBER",
        help="GitHub issue number to triage",
    )
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        metavar="OWNER/REPO",
        help="Repository in owner/repo format (default: $GITHUB_REPOSITORY)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if not args.repo:
        logger.error(
            "Repository not specified: use --repo or set GITHUB_REPOSITORY env var"
        )
        return 1

    logger.info("Fetching issue body: #%d from %s", args.issue, args.repo)
    issue_body = get_issue_body(args.issue, args.repo)

    logger.info("Starting triage agent for issue #%d", args.issue)
    run_triage(args.issue, issue_body, args.repo)

    logger.info("Triage complete for issue #%d", args.issue)
    return 0


if __name__ == "__main__":
    sys.exit(main())
