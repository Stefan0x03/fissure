"""
NVD API wrapper — fetches CVE records by publication date range.

Returns raw NVD API response objects; no filtering logic here.
Filtering is the responsibility of prefilter.py.
"""

import os
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from config.settings import NVD_API_KEY_ENV, NVD_BASE_URL

# NVD enforces a rolling rate limit. With no key: 5 req / 30 s.
# With a key: 50 req / 30 s. Sleep between paginated calls to stay safe.
_SLEEP_NO_KEY = 6.0   # seconds between requests without an API key
_SLEEP_WITH_KEY = 0.6  # seconds between requests with an API key

# NVD returns at most 2000 results per page.
_PAGE_SIZE = 2000


def fetch_cves_by_date_range(
    pub_start: datetime,
    pub_end: datetime,
    *,
    timeout: float = 30.0,
) -> list[dict[str, Any]]:
    """
    Fetch all CVE records published between *pub_start* and *pub_end* (inclusive).

    Both datetimes must be timezone-aware.  NVD accepts ISO 8601 with
    milliseconds: ``2024-01-01T00:00:00.000``.

    Returns a flat list of raw NVD ``vulnerabilities`` objects (each has a
    ``cve`` key at the top level).

    Raises ``httpx.HTTPStatusError`` on non-2xx responses.
    """
    if pub_start.tzinfo is None or pub_end.tzinfo is None:
        raise ValueError("pub_start and pub_end must be timezone-aware")

    api_key = os.environ.get(NVD_API_KEY_ENV)
    sleep_between = _SLEEP_WITH_KEY if api_key else _SLEEP_NO_KEY

    headers: dict[str, str] = {}
    if api_key:
        headers["apiKey"] = api_key

    def _fmt(dt: datetime) -> str:
        # NVD expects UTC, no timezone offset in the string.
        utc = dt.astimezone(timezone.utc)
        return utc.strftime("%Y-%m-%dT%H:%M:%S.000")

    params_base: dict[str, Any] = {
        "pubStartDate": _fmt(pub_start),
        "pubEndDate": _fmt(pub_end),
        "resultsPerPage": _PAGE_SIZE,
    }

    all_vulns: list[dict[str, Any]] = []
    start_index = 0

    with httpx.Client(timeout=timeout) as client:
        while True:
            params = {**params_base, "startIndex": start_index}
            response = client.get(NVD_BASE_URL, params=params, headers=headers)
            response.raise_for_status()

            data = response.json()
            vulns: list[dict[str, Any]] = data.get("vulnerabilities", [])
            all_vulns.extend(vulns)

            total_results: int = data.get("totalResults", 0)
            start_index += len(vulns)

            if start_index >= total_results or not vulns:
                break

            time.sleep(sleep_between)

    return all_vulns
