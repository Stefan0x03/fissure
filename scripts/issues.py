"""
GitHub Issues glue — candidate issue creation, triage comment posting, and issue reads.
"""

from __future__ import annotations

import os
from typing import Any

import httpx

from agents.triage.tools.ghsa import GHSAAdvisory
from config.settings import LABEL_CANDIDATE

_GITHUB_API = "https://api.github.com"



def create_candidate_issue(
    cve: dict[str, Any],
    epss_score: float | None,
    epss_percentile: float | None,
    *,
    repo: str,
    token: str | None = None,
    ghsa: GHSAAdvisory | None = None,
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
    body = _build_issue_body(cve_data, cve_id, epss_score, epss_percentile, ghsa)

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
    ghsa: GHSAAdvisory | None = None,
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

    ghsa_section = _build_ghsa_section(ghsa) if ghsa else "_No GHSA advisory found._"

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

## GHSA Advisory

{ghsa_section}

---

_Awaiting triage._
"""


def _build_ghsa_section(ghsa: GHSAAdvisory) -> str:
    cvss_line = (
        f"{ghsa.cvss_score} ({ghsa.cvss_vector})"
        if ghsa.cvss_score is not None
        else "n/a"
    )
    cwes_line = (
        ", ".join(f"{c['cwe_id']} ({c['name']})" for c in ghsa.cwes)
        if ghsa.cwes else "none"
    )
    refs_lines = "\n".join(f"- {url}" for url in ghsa.references[:15]) or "_none_"

    affected_lines = ""
    if ghsa.vulnerabilities:
        rows = []
        for v in ghsa.vulnerabilities:
            patched = v["first_patched"] or "no fix"
            rows.append(
                f"| {v['ecosystem']} | {v['package']} "
                f"| {v['vulnerable_range']} | {patched} |"
            )
        affected_lines = (
            "| Ecosystem | Package | Vulnerable range | First patched |\n"
            "|-----------|---------|-----------------|---------------|\n"
            + "\n".join(rows)
        )
    else:
        affected_lines = "_No affected package data._"

    return f"""\
**GHSA ID:** {ghsa.ghsa_id}
**Severity:** {ghsa.severity}
**CVSS:** {cvss_line}
**CWE:** {cwes_line}
**Published:** {ghsa.published_at}
**Updated:** {ghsa.updated_at}

### Summary

{ghsa.summary}

### Advisory Detail

{ghsa.description}

### Affected Packages

{affected_lines}

### Advisory References

{refs_lines}\
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


# ---------------------------------------------------------------------------
# Phase 3 additions — triage comment, issue body read, and queue listing
# ---------------------------------------------------------------------------


_OUTCOME_LABELS = {"approved", "needs-review", "discarded"}


def list_untriaged_candidates(repo: str, *, token: str | None = None) -> list[int]:
    """
    Return issue numbers (oldest-first) that have the ``candidate`` label but
    no outcome label (``approved``, ``needs-review``, or ``discarded``).

    ``repo`` must be in ``owner/name`` format.
    ``token`` defaults to the ``GITHUB_TOKEN`` environment variable.

    Raises ``httpx.HTTPStatusError`` on non-2xx responses.
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

    issue_numbers: list[int] = []
    page = 1

    with httpx.Client(timeout=15.0) as client:
        while True:
            response = client.get(
                f"{_GITHUB_API}/repos/{repo}/issues",
                params={
                    "labels": LABEL_CANDIDATE,
                    "state": "open",
                    "direction": "asc",
                    "per_page": 100,
                    "page": page,
                },
                headers=headers,
            )
            response.raise_for_status()
            items = response.json()
            if not items:
                break

            for issue in items:
                label_names = {lbl["name"] for lbl in issue.get("labels", [])}
                if not label_names & _OUTCOME_LABELS:
                    issue_numbers.append(issue["number"])

            if len(items) < 100:
                break
            page += 1

    return issue_numbers


def get_issue_body(issue_number: int, repo: str, *, token: str | None = None) -> str:
    """
    Fetch the body text of a GitHub Issue.

    ``repo`` must be in ``owner/name`` format.
    ``token`` defaults to the ``GITHUB_TOKEN`` environment variable.

    Returns the issue body string (may be empty if the issue has no body).
    Raises ``httpx.HTTPStatusError`` on non-2xx responses.
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

    with httpx.Client(timeout=15.0) as client:
        response = client.get(
            f"{_GITHUB_API}/repos/{repo}/issues/{issue_number}",
            headers=headers,
        )
        response.raise_for_status()

    return response.json().get("body") or ""


def post_triage_comment(
    issue_number: int,
    repo: str,
    body: str,
    label: str,
    *,
    close: bool = False,
    token: str | None = None,
) -> None:
    """
    Post *body* as a comment on *issue_number*, apply *label*, and optionally close the issue.

    Never edits the issue body — all triage output goes into comments.

    ``repo`` must be in ``owner/name`` format.
    ``token`` defaults to the ``GITHUB_TOKEN`` environment variable.

    Raises ``httpx.HTTPStatusError`` on non-2xx responses.
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
    issue_url = f"{_GITHUB_API}/repos/{repo}/issues/{issue_number}"

    with httpx.Client(timeout=15.0) as client:
        # 1. Post the comment.
        client.post(
            f"{issue_url}/comments",
            json={"body": body},
            headers=headers,
        ).raise_for_status()

        # 2. Apply the label.
        client.post(
            f"{issue_url}/labels",
            json={"labels": [label]},
            headers=headers,
        ).raise_for_status()

        # 3. Close the issue if requested.
        if close:
            client.patch(
                issue_url,
                json={"state": "closed"},
                headers=headers,
            ).raise_for_status()
