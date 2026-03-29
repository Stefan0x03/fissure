"""
GHSA fetcher — retrieves a full GitHub Security Advisory by CVE ID.

Uses the GitHub REST API (/advisories?cve_id=) which covers both reviewed
and unreviewed advisories. The GraphQL securityAdvisories endpoint only
returns reviewed advisories and misses the majority of the corpus.

Requires GITHUB_TOKEN. The default Actions token is sufficient.
Returns None when no advisory is found for a given CVE ID.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

_REST_URL = "https://api.github.com/advisories"
_GITHUB_TOKEN_ENV = "GITHUB_TOKEN"


@dataclass
class GHSAAdvisory:
    ghsa_id: str
    summary: str
    description: str
    severity: str                          # critical / high / moderate / low
    advisory_type: str                     # "reviewed" or "unreviewed"
    published_at: str
    updated_at: str
    cvss_score: float | None
    cvss_vector: str | None
    cwes: list[dict[str, str]]             # [{"cwe_id": "CWE-787", "name": "..."}]
    references: list[str]                  # plain URL strings
    vulnerabilities: list[dict[str, Any]]  # affected package records (reviewed only)


def fetch_ghsa_for_cve(
    cve_id: str,
    *,
    token: str | None = None,
    timeout: float = 20.0,
) -> GHSAAdvisory | None:
    """
    Fetch the GitHub Security Advisory for *cve_id* via the REST API.

    Returns a :class:`GHSAAdvisory` if an advisory exists, ``None`` otherwise.
    Raises ``httpx.HTTPStatusError`` on non-2xx HTTP responses.
    """
    token = token or os.environ.get(_GITHUB_TOKEN_ENV)
    if not token:
        raise ValueError(
            f"GitHub token required: pass token= or set {_GITHUB_TOKEN_ENV} env var"
        )

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    with httpx.Client(timeout=timeout) as client:
        response = client.get(
            _REST_URL,
            params={"cve_id": cve_id},
            headers=headers,
        )
        response.raise_for_status()

    advisories = response.json()
    if not advisories:
        return None

    a = advisories[0]
    cvss = a.get("cvss") or {}

    return GHSAAdvisory(
        ghsa_id=a.get("ghsa_id", ""),
        summary=a.get("summary", ""),
        description=a.get("description", ""),
        severity=a.get("severity", "unknown"),
        advisory_type=a.get("type", "unknown"),
        published_at=a.get("published_at", ""),
        updated_at=a.get("updated_at", ""),
        cvss_score=cvss.get("score"),
        cvss_vector=cvss.get("vector_string"),
        cwes=[
            {"cwe_id": c["cwe_id"], "name": c["name"]}
            for c in a.get("cwes") or []
        ],
        references=a.get("references") or [],
        vulnerabilities=[
            {
                "package": v.get("package", {}).get("name", ""),
                "ecosystem": v.get("package", {}).get("ecosystem", ""),
                "vulnerable_range": v.get("vulnerable_version_range", ""),
                "first_patched": v.get("first_patched_version"),
            }
            for v in a.get("vulnerabilities") or []
        ],
    )
