"""
PoC search tool — two backends: GitHub code search and Exploit-DB.

GitHub code search requires GITHUB_TOKEN. Raises ValueError when absent.
Exploit-DB is public; returns an empty list on no results rather than raising.
"""

from __future__ import annotations

import os
import re
from typing import Any

import httpx

_GITHUB_API = "https://api.github.com"
_EXPLOITDB_SEARCH_URL = "https://www.exploit-db.com/search"
_EXPLOITDB_BASE_URL = "https://www.exploit-db.com/exploits"
_GITHUB_TOKEN_ENV = "GITHUB_TOKEN"
_MAX_GITHUB_RESULTS = 5


def _search_github(cve_id: str, token: str) -> list[dict[str, Any]]:
    """
    Search GitHub code for PoC-related files referencing *cve_id*.

    Returns up to _MAX_GITHUB_RESULTS result dicts, each containing at minimum:
    - html_url
    - repository.full_name
    - name
    """
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    query = f"{cve_id} poc exploit"
    params = {
        "q": query,
        "per_page": _MAX_GITHUB_RESULTS,
    }

    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.get(
                f"{_GITHUB_API}/search/code",
                params=params,
                headers=headers,
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        # Rate-limited or other non-fatal HTTP error — return empty rather than
        # crashing the triage run. The agent will proceed without PoC results.
        return []

    items = response.json().get("items", [])
    return [
        {
            "html_url": item.get("html_url", ""),
            "repository": {
                "full_name": item.get("repository", {}).get("full_name", ""),
            },
            "name": item.get("name", ""),
        }
        for item in items[:_MAX_GITHUB_RESULTS]
    ]


def _search_exploitdb(cve_id: str) -> list[dict[str, Any]]:
    """
    Search Exploit-DB for exploits referencing *cve_id*.

    Returns a list of result dicts, each containing at minimum:
    - id
    - description
    - url (full Exploit-DB URL)

    Returns an empty list if no results are found or on any error.

    Exploit-DB's search is a DataTables AJAX endpoint that requires a session
    cookie and CSRF token from a prior page load. We do a two-step request:
    1. GET /search to obtain the session cookie and CSRF token.
    2. GET /search?cve=... with the session cookie, CSRF token, and
       X-Requested-With: XMLHttpRequest to receive JSON.
    """
    try:
        with httpx.Client(timeout=20.0, follow_redirects=True) as client:
            # Step 1: load the search page to get session cookie + CSRF token.
            page = client.get(_EXPLOITDB_SEARCH_URL)
            page.raise_for_status()

            match = re.search(r'<meta name="csrf-token" content="([^"]+)"', page.text)
            if not match:
                return []
            csrf_token = match.group(1)

            # Step 2: DataTables AJAX call.
            response = client.get(
                _EXPLOITDB_SEARCH_URL,
                params={"cve": cve_id, "draw": 1, "start": 0, "length": 10},
                headers={
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "X-Requested-With": "XMLHttpRequest",
                    "X-CSRF-TOKEN": csrf_token,
                },
            )
            response.raise_for_status()
        data = response.json()
    except (httpx.HTTPStatusError, ValueError):
        # ValueError covers json.JSONDecodeError.
        return []
    # Exploit-DB returns {"data": [...], ...}
    rows = data.get("data", [])
    results = []
    for row in rows:
        exploit_id = row.get("id", "")
        results.append(
            {
                "id": exploit_id,
                "description": row.get("description", row.get("title", "")),
                "url": f"{_EXPLOITDB_BASE_URL}/{exploit_id}",
            }
        )
    return results


def search_poc(cve_id: str) -> dict[str, list[dict[str, Any]]]:
    """
    Search for public PoCs for *cve_id* across GitHub and Exploit-DB.

    Returns::

        {
            "github": [...],    # up to 5 results
            "exploitdb": [...], # 0 or more results
        }

    Raises ``ValueError`` if GITHUB_TOKEN is absent.
    """
    token = os.environ.get(_GITHUB_TOKEN_ENV)
    if not token:
        raise ValueError(
            f"GitHub token required: set {_GITHUB_TOKEN_ENV} env var"
        )

    github_results = _search_github(cve_id, token)
    exploitdb_results = _search_exploitdb(cve_id)

    return {
        "github": github_results,
        "exploitdb": exploitdb_results,
    }
