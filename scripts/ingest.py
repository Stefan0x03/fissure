"""
Ingest entrypoint — called by cve-ingest.yml.

Pipeline:
  1. Fetch CVEs from NVD for the configured lookback window.
  2. Fetch EPSS scores for surviving CVE IDs (bulk where possible).
  3. Run the rule-based pre-filter on each CVE.
  4. Create a GitHub candidate issue for each CVE that passes.

Usage:
  python -m scripts.ingest [--repo owner/name] [--dry-run]
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from agents.triage.prefilter import passes_prefilter
from agents.triage.tools.ghsa import fetch_ghsa_for_cve
from agents.triage.tools.nvd import fetch_cves_by_date_range
from config.settings import EPSS_BASE_URL, NVD_LOOKBACK_DAYS
from scripts.issues import create_candidate_issue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)


def main(repo: str, dry_run: bool = False) -> None:
    now = datetime.now(tz=timezone.utc)
    pub_start = now - timedelta(days=NVD_LOOKBACK_DAYS)
    pub_end = now

    log.info("Fetching CVEs published between %s and %s", pub_start.date(), pub_end.date())
    vulns = fetch_cves_by_date_range(pub_start, pub_end)
    log.info("NVD returned %d CVE records", len(vulns))

    if not vulns:
        log.info("Nothing to process.")
        return

    # Bulk-fetch EPSS scores for all CVE IDs in one request.
    cve_ids = [v.get("cve", {}).get("id", "") for v in vulns if v.get("cve", {}).get("id")]
    epss_map = _fetch_epss_bulk(cve_ids)

    # Prefetch all existing issue titles once so deduplication doesn't rely on
    # the GitHub Search API, which has an indexing lag of several minutes and
    # causes false negatives (and therefore duplicate issues) within the same run.
    existing_cve_ids = _fetch_existing_cve_ids(repo) if not dry_run else set()
    log.info("Found %d existing issues in repo", len(existing_cve_ids))

    passed = 0
    discarded = 0

    for vuln in vulns:
        cve_id: str = vuln.get("cve", {}).get("id", "UNKNOWN")
        epss_score, epss_percentile = epss_map.get(cve_id, (None, None))

        ok, reason = passes_prefilter(vuln, epss_percentile=epss_percentile)
        if not ok:
            log.debug("DISCARD %s — %s", cve_id, reason)
            discarded += 1
            continue

        log.info("PASS %s (EPSS=%.4f, percentile=%.1f%%)", cve_id, epss_score or 0.0, (epss_percentile or 0.0) * 100)
        passed += 1

        if dry_run:
            log.info("  [dry-run] would create issue for %s", cve_id)
            continue

        if cve_id in existing_cve_ids:
            log.info("  SKIP %s — issue already exists", cve_id)
            passed -= 1
            discarded += 1
            continue

        try:
            ghsa = fetch_ghsa_for_cve(cve_id)
            if ghsa:
                log.info("  GHSA %s found for %s", ghsa.ghsa_id, cve_id)
            else:
                log.info("  No GHSA advisory for %s", cve_id)

            issue = create_candidate_issue(
                vuln,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                repo=repo,
                ghsa=ghsa,
            )
            log.info("  Created issue #%d: %s", issue["number"], issue["html_url"])
            existing_cve_ids.add(cve_id)  # guard against duplicates within this run
            _dispatch_triage(issue["number"], repo)
        except httpx.HTTPStatusError as exc:
            log.error("  Failed to create issue for %s: %s", cve_id, exc)

    log.info("Done. Passed: %d  Discarded: %d", passed, discarded)


def _fetch_existing_cve_ids(repo: str, *, timeout: float = 15.0) -> set[str]:
    """
    Return the set of CVE IDs that already have an issue in *repo* (any state).

    Paginates the Issues list API rather than the Search API so that issues
    created moments ago are immediately visible (the Search API indexes with
    a lag of several minutes).
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN env var is required")

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    cve_ids: set[str] = set()
    page = 1
    with httpx.Client(timeout=timeout) as client:
        while True:
            resp = client.get(
                f"https://api.github.com/repos/{repo}/issues",
                params={"state": "all", "per_page": 100, "page": page},
                headers=headers,
            )
            resp.raise_for_status()
            issues = resp.json()
            if not issues:
                break
            for issue in issues:
                title: str = issue.get("title", "")
                # Titles are "[Candidate] CVE-YYYY-NNNNN" but match any format.
                for word in title.split():
                    if word.startswith("CVE-"):
                        cve_ids.add(word)
            if len(issues) < 100:
                break
            page += 1

    return cve_ids


def _dispatch_triage(issue_number: int, repo: str, *, timeout: float = 10.0) -> None:
    """
    Trigger cve-triage.yml via workflow_dispatch for *issue_number*.

    Failures are logged but never re-raised — a failed dispatch does not abort
    the ingest run; triage can be re-run manually via workflow_dispatch.
    """
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        log.warning("Cannot dispatch triage for issue #%d: GITHUB_TOKEN not set", issue_number)
        return

    ref = os.environ.get("GITHUB_REF_NAME", "main")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload = {
        "ref": ref,
        "inputs": {"issue_number": str(issue_number)},
    }

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(
                f"https://api.github.com/repos/{repo}/actions/workflows/cve-triage.yml/dispatches",
                json=payload,
                headers=headers,
            )
            resp.raise_for_status()
        log.info("  Dispatched triage workflow for issue #%d", issue_number)
    except httpx.HTTPStatusError as exc:
        log.error(
            "  Failed to dispatch triage for issue #%d: %s %s",
            issue_number,
            exc.response.status_code,
            exc.response.text,
        )
    except httpx.HTTPError as exc:
        log.error("  Network error dispatching triage for issue #%d: %s", issue_number, exc)


def _fetch_epss_bulk(
    cve_ids: list[str],
    *,
    timeout: float = 20.0,
) -> dict[str, tuple[float, float]]:
    """
    Fetch EPSS scores for a list of CVE IDs from api.first.org.

    Returns a dict mapping CVE ID → (score, percentile).
    CVEs not found in the response are absent from the dict.

    The EPSS API accepts comma-separated CVE IDs via the ``cve`` parameter.
    We chunk to stay within URL length limits.
    """
    results: dict[str, tuple[float, float]] = {}
    chunk_size = 100  # well under URL length limit

    with httpx.Client(timeout=timeout) as client:
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i : i + chunk_size]
            params = {"cve": ",".join(chunk)}
            try:
                resp = client.get(EPSS_BASE_URL, params=params)
                resp.raise_for_status()
                data = resp.json()
                for entry in data.get("data", []):
                    cve_id = entry.get("cve", "")
                    score = float(entry.get("epss", 0.0))
                    percentile = float(entry.get("percentile", 0.0))
                    results[cve_id] = (score, percentile)
            except (httpx.HTTPError, ValueError, KeyError) as exc:
                log.warning("EPSS bulk fetch failed for chunk starting %s: %s", chunk[0], exc)

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fissure CVE ingest")
    parser.add_argument(
        "--repo",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="GitHub repo in owner/name format (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and filter CVEs but do not create GitHub issues",
    )
    args = parser.parse_args()

    if not args.repo:
        parser.error("--repo is required (or set GITHUB_REPOSITORY env var)")

    main(args.repo, dry_run=args.dry_run)
