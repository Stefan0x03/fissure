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

    passed = 0
    discarded = 0

    for vuln in vulns:
        cve_id: str = vuln.get("cve", {}).get("id", "UNKNOWN")
        epss_score, epss_percentile = epss_map.get(cve_id, (None, None))

        ok, reason = passes_prefilter(vuln, epss_score=epss_score)
        if not ok:
            log.debug("DISCARD %s — %s", cve_id, reason)
            discarded += 1
            continue

        log.info("PASS %s (EPSS=%.4f)", cve_id, epss_score or 0.0)
        passed += 1

        if dry_run:
            log.info("  [dry-run] would create issue for %s", cve_id)
            continue

        try:
            issue = create_candidate_issue(
                vuln,
                epss_score=epss_score,
                epss_percentile=epss_percentile,
                repo=repo,
            )
            log.info("  Created issue #%d: %s", issue["number"], issue["html_url"])
        except httpx.HTTPStatusError as exc:
            log.error("  Failed to create issue for %s: %s", cve_id, exc)

    log.info("Done. Passed: %d  Discarded: %d", passed, discarded)


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
                    percentile = float(entry.get("percentile", 0.0)) * 100.0
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
