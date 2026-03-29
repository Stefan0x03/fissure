"""
GitHub Issues glue — Phase 1 scope: candidate issue creation only.

Update/close/relabeling methods are Phase 3.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from config.settings import LABEL_CANDIDATE

_GITHUB_API = "https://api.github.com"


def issue_exists(
    cve_id: str,
    *,
    repo: str,
    token: str | None = None,
) -> bool:
    """
    Return True if an issue for *cve_id* already exists in *repo* (any state).

    Searches issue titles via the GitHub search API so it catches open,
    closed, and discarded issues — preventing re-ingestion of any CVE that
    has already been seen.
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError(
            "GitHub token required: pass token= or set GITHUB_TOKEN env var"
        )

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    params = {
        "q": f"repo:{repo} {cve_id} in:title is:issue",
        "per_page": 1,
    }

    with httpx.Client(timeout=15.0) as client:
        response = client.get(
            f"{_GITHUB_API}/search/issues",
            params=params,
            headers=headers,
        )
        response.raise_for_status()
        return response.json().get("total_count", 0) > 0


def create_candidate_issue(
    cve: dict[str, Any],
    epss_score: float | None,
    epss_percentile: float | None,
    *,
    repo: str,
    token: str | None = None,
) -> dict[str, Any]:
    """
    Create a GitHub Issue for a CVE that has passed the pre-filter.

    ``repo`` must be in ``owner/name`` format.
    ``token`` defaults to the ``GITHUB_TOKEN`` environment variable.

    Returns the GitHub API response body (dict with at least ``number`` and
    ``html_url``).

    Raises ``httpx.HTTPStatusError`` on non-2xx responses.
    """
    token = token or os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError(
            "GitHub token required: pass token= or set GITHUB_TOKEN env var"
        )

    cve_data = cve.get("cve", cve)  # tolerate both raw vuln wrapper and bare cve dict
    cve_id: str = cve_data.get("id", "UNKNOWN")
    title = f"[Candidate] {cve_id}"
    body = _build_issue_body(cve_data, cve_id, epss_score, epss_percentile)

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    payload: dict[str, Any] = {
        "title": title,
        "body": body,
        "labels": [LABEL_CANDIDATE],
    }

    with httpx.Client(timeout=15.0) as client:
        response = client.post(
            f"{_GITHUB_API}/repos/{repo}/issues",
            json=payload,
            headers=headers,
        )
        response.raise_for_status()
        return response.json()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_issue_body(
    cve_data: dict[str, Any],
    cve_id: str,
    epss_score: float | None,
    epss_percentile: float | None,
) -> str:
    description = _get_english_description(cve_data)
    published = cve_data.get("published", "unknown")
    cwes = _get_cwes(cve_data)
    cvss = _get_cvss_score(cve_data)
    refs = _get_reference_urls(cve_data)

    epss_line = (
        f"{epss_score:.4f} ({epss_percentile * 100:.1f}th percentile)"
        if epss_score is not None and epss_percentile is not None
        else "pending"
    )
    cwes_line = ", ".join(sorted(cwes)) if cwes else "none"
    cvss_line = str(cvss) if cvss is not None else "n/a"
    refs_section = (
        "\n".join(f"- {url}" for url in refs[:10]) if refs else "_none_"
    )

    return f"""\
## {cve_id}

**Published:** {published}
**EPSS:** {epss_line}
**CVSS:** {cvss_line}
**CWE:** {cwes_line}

### Description

{description or '_No English description available._'}

### References

{refs_section}

---

_Awaiting triage._
"""


def _get_english_description(cve_data: dict[str, Any]) -> str:
    for desc in cve_data.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _get_cwes(cve_data: dict[str, Any]) -> set[str]:
    cwes: set[str] = set()
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                cwes.add(value)
    return cwes


def _get_cvss_score(cve_data: dict[str, Any]) -> float | None:
    metrics = cve_data.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return entries[0].get("cvssData", {}).get("baseScore")
    return None


def _get_reference_urls(cve_data: dict[str, Any]) -> list[str]:
    return [ref.get("url", "") for ref in cve_data.get("references", []) if ref.get("url")]
