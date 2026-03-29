"""
GHSA fetcher — retrieves a full GitHub Security Advisory by CVE ID.

Uses the GitHub GraphQL API. Requires GITHUB_TOKEN (read:security_events
scope; the default Actions token is sufficient for public advisories).

Returns None when no advisory is found for a given CVE ID.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

import httpx

_GRAPHQL_URL = "https://api.github.com/graphql"
_GITHUB_TOKEN_ENV = "GITHUB_TOKEN"

_QUERY = """
query FetchAdvisoryByCVE($cveId: String!) {
  securityAdvisories(identifier: {type: CVE, value: $cveId}, first: 1) {
    nodes {
      ghsaId
      summary
      description
      severity
      publishedAt
      updatedAt
      cvss {
        score
        vectorString
      }
      cwes(first: 10) {
        nodes {
          cweId
          name
        }
      }
      references {
        url
      }
      vulnerabilities(first: 20) {
        nodes {
          package {
            name
            ecosystem
          }
          vulnerableVersionRange
          firstPatchedVersion {
            identifier
          }
        }
      }
    }
  }
}
"""


@dataclass
class GHSAAdvisory:
    ghsa_id: str
    summary: str
    description: str
    severity: str                        # CRITICAL / HIGH / MODERATE / LOW
    published_at: str
    updated_at: str
    cvss_score: float | None
    cvss_vector: str | None
    cwes: list[dict[str, str]]           # [{"cweId": "CWE-787", "name": "..."}]
    references: list[str]                # plain URL strings
    vulnerabilities: list[dict[str, Any]]  # affected package records


def fetch_ghsa_for_cve(
    cve_id: str,
    *,
    token: str | None = None,
    timeout: float = 20.0,
) -> GHSAAdvisory | None:
    """
    Fetch the GitHub Security Advisory for *cve_id*.

    Returns a :class:`GHSAAdvisory` if an advisory exists, ``None`` otherwise.
    Raises ``httpx.HTTPStatusError`` on non-2xx HTTP responses.
    Raises ``ValueError`` if the GraphQL response contains errors.
    """
    token = token or os.environ.get(_GITHUB_TOKEN_ENV)
    if not token:
        raise ValueError(
            f"GitHub token required: pass token= or set {_GITHUB_TOKEN_ENV} env var"
        )

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    payload = {"query": _QUERY, "variables": {"cveId": cve_id}}

    with httpx.Client(timeout=timeout) as client:
        response = client.post(_GRAPHQL_URL, json=payload, headers=headers)
        response.raise_for_status()

    data = response.json()
    if errors := data.get("errors"):
        raise ValueError(f"GraphQL errors for {cve_id}: {errors}")

    nodes = data.get("data", {}).get("securityAdvisories", {}).get("nodes", [])
    if not nodes:
        return None

    node = nodes[0]
    return GHSAAdvisory(
        ghsa_id=node["ghsaId"],
        summary=node.get("summary", ""),
        description=node.get("description", ""),
        severity=node.get("severity", "UNKNOWN"),
        published_at=node.get("publishedAt", ""),
        updated_at=node.get("updatedAt", ""),
        cvss_score=node.get("cvss", {}).get("score"),
        cvss_vector=node.get("cvss", {}).get("vectorString"),
        cwes=[
            {"cweId": c["cweId"], "name": c["name"]}
            for c in node.get("cwes", {}).get("nodes", [])
        ],
        references=[r["url"] for r in node.get("references", []) if r.get("url")],
        vulnerabilities=[
            {
                "package": v.get("package", {}).get("name", ""),
                "ecosystem": v.get("package", {}).get("ecosystem", ""),
                "vulnerable_range": v.get("vulnerableVersionRange", ""),
                "first_patched": (
                    v.get("firstPatchedVersion", {}).get("identifier", "")
                    if v.get("firstPatchedVersion")
                    else None
                ),
            }
            for v in node.get("vulnerabilities", {}).get("nodes", [])
        ],
    )
