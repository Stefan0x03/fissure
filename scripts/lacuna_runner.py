"""
Lacuna runner glue — two subcommands:

  extract       Find the triage comment on an issue and write the first
                ```yaml fenced block to a file (the Lacuna handoff YAML).

  post-results  Read the Lacuna scan output, post a summary comment on the
                issue, and apply the complete or failed label.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from pathlib import Path

import httpx

_GITHUB_API = "https://api.github.com"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


def _headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------


def extract(issue_number: int, repo: str, output: Path, *, token: str) -> None:
    """
    Find the triage comment by github-actions[bot] and write the first
    ```yaml block to *output*.
    """
    comments = _list_comments(issue_number, repo, token=token)

    triage_comment = next(
        (c for c in comments if c.get("user", {}).get("login") == "github-actions[bot]"),
        None,
    )
    if triage_comment is None:
        logger.error("No triage comment by github-actions[bot] on issue #%d", issue_number)
        sys.exit(1)

    body = triage_comment.get("body", "")
    yaml_block = _first_yaml_block(body)
    if yaml_block is None:
        logger.error("No ```yaml block found in triage comment on issue #%d", issue_number)
        sys.exit(1)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(yaml_block)
    logger.info("Handoff YAML written to %s (%d bytes)", output, len(yaml_block))


def _list_comments(issue_number: int, repo: str, *, token: str) -> list[dict]:
    headers = _headers(token)
    comments: list[dict] = []
    page = 1
    with httpx.Client(timeout=15.0) as client:
        while True:
            resp = client.get(
                f"{_GITHUB_API}/repos/{repo}/issues/{issue_number}/comments",
                params={"per_page": 100, "page": page},
                headers=headers,
            )
            resp.raise_for_status()
            batch = resp.json()
            if not batch:
                break
            comments.extend(batch)
            if len(batch) < 100:
                break
            page += 1
    return comments


def _first_yaml_block(text: str) -> str | None:
    """Return the content of the first ```yaml ... ``` block, or None."""
    match = re.search(r"```yaml\n(.*?)```", text, re.DOTALL)
    return match.group(1) if match else None


# ---------------------------------------------------------------------------
# post-results
# ---------------------------------------------------------------------------


def post_results(
    issue_number: int,
    repo: str,
    lacuna_dir: Path,
    scan_outcome: str,
    *,
    token: str,
) -> None:
    """
    Build a summary comment from the Lacuna report and PoC list, post it to
    the issue, then apply the `complete` or `failed` label and remove
    `in-progress`.
    """
    succeeded = scan_outcome == "success"
    label = "complete" if succeeded else "failed"

    report_text, report_name = _find_report(lacuna_dir)

    lines: list[str] = []
    lines.append(f"## Lacuna scan {'complete' if succeeded else 'failed'}")
    lines.append("")

    if report_text:
        lines.append(f"### Report — `{report_name}`")
        lines.append("")
        lines.append("<details><summary>Full report</summary>")
        lines.append("")
        lines.append(report_text.strip())
        lines.append("")
        lines.append("</details>")
    else:
        lines.append("_No report file produced._")

    comment = "\n".join(lines)

    _post_comment(issue_number, repo, comment, token=token)
    _apply_label(issue_number, repo, label, token=token)
    _remove_label(issue_number, repo, "in-progress", token=token)
    logger.info("Posted results and applied label '%s' to issue #%d", label, issue_number)


def _find_report(lacuna_dir: Path) -> tuple[str | None, str | None]:
    reports_dir = lacuna_dir / "reports"
    if not reports_dir.exists():
        return None, None
    candidates = [p for p in reports_dir.iterdir() if p.is_file() and p.suffix == ".md"]
    if not candidates:
        return None, None
    latest = max(candidates, key=lambda p: p.stat().st_mtime)
    return latest.read_text(), latest.name



def _post_comment(issue_number: int, repo: str, body: str, *, token: str) -> None:
    with httpx.Client(timeout=15.0) as client:
        client.post(
            f"{_GITHUB_API}/repos/{repo}/issues/{issue_number}/comments",
            json={"body": body},
            headers=_headers(token),
        ).raise_for_status()


def _apply_label(issue_number: int, repo: str, label: str, *, token: str) -> None:
    with httpx.Client(timeout=15.0) as client:
        client.post(
            f"{_GITHUB_API}/repos/{repo}/issues/{issue_number}/labels",
            json={"labels": [label]},
            headers=_headers(token),
        ).raise_for_status()


def _remove_label(issue_number: int, repo: str, label: str, *, token: str) -> None:
    with httpx.Client(timeout=15.0) as client:
        resp = client.delete(
            f"{_GITHUB_API}/repos/{repo}/issues/{issue_number}/labels/{label}",
            headers=_headers(token),
        )
        # 404 is fine — label wasn't applied (e.g. extract failed before we set it)
        if resp.status_code not in (200, 204, 404):
            resp.raise_for_status()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lacuna runner glue")
    sub = parser.add_subparsers(dest="command", required=True)

    ex = sub.add_parser("extract", help="Extract handoff YAML from triage comment")
    ex.add_argument("--issue", type=int, required=True)
    ex.add_argument("--repo", required=True, metavar="OWNER/REPO")
    ex.add_argument("--output", type=Path, required=True, metavar="PATH")

    pr = sub.add_parser("post-results", help="Post scan results to issue")
    pr.add_argument("--issue", type=int, required=True)
    pr.add_argument("--repo", required=True, metavar="OWNER/REPO")
    pr.add_argument("--lacuna-dir", type=Path, required=True, metavar="PATH")
    pr.add_argument("--scan-outcome", required=True, metavar="success|failure|...")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.error("GITHUB_TOKEN env var is required")
        return 1

    if args.command == "extract":
        extract(args.issue, args.repo, args.output, token=token)
    elif args.command == "post-results":
        post_results(
            args.issue,
            args.repo,
            args.lacuna_dir,
            args.scan_outcome,
            token=token,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
