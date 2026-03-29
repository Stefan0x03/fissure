"""
Rule-based pre-filter for NVD CVE records.

No LLM calls. Takes a raw NVD vulnerability object and decides whether it's a
viable Fissure target. Returns a (bool, str) tuple: (passes, discard_reason).

Discard reason is an empty string when the CVE passes.
"""

from __future__ import annotations

import re
from typing import Any

from config.settings import CWE_ALLOWLIST, EPSS_PERCENTILE_FLOOR

# ---------------------------------------------------------------------------
# Out-of-scope keyword lists — matched against description and CPE strings.
# ---------------------------------------------------------------------------

# Products/platforms that indicate kernel, firmware, or embedded targets.
_OUT_OF_SCOPE_PRODUCT_TOKENS: frozenset[str] = frozenset(
    {
        # Kernel / OS
        "linux_kernel",
        "windows_kernel",
        "freebsd_kernel",
        # Firmware / embedded
        "firmware",
        "uefi",
        "bios",
        "bootloader",
        "embedded",
        "microcontroller",
        # Network / enterprise appliances
        "router",
        "switch",
        "firewall",
        "fortigate",
        "fortios",
        "junos",
        "ios_xe",
        "ios_xr",
        "asa",  # Cisco ASA
        "panos",  # Palo Alto
        "sonicwall",
        "bigip",  # F5
    }
)

# Description phrases that indicate web applications, SaaS, or enterprise software.
_OUT_OF_SCOPE_DESC_PATTERNS: list[re.Pattern[str]] = [
    re.compile(p, re.IGNORECASE)
    for p in [
        r"\bweb\s+application\b",
        r"\bweb\s+app\b",
        r"\bcross[- ]site\s+script",      # XSS
        r"\bsql\s+injection\b",
        r"\bserver[- ]side\s+request\b",  # SSRF
        r"\bremote\s+code\s+execution\b.*\bphp\b",
        r"\bjava\s+servlet\b",
        r"\bspring\s+boot\b",
        r"\bdjango\b",
        r"\brails\b",
        r"\bwordpress\b",
        r"\bdrupal\b",
        r"\bjoomla\b",
        r"\bsalesforce\b",
        r"\bsap\b",
        r"\boracle\s+database\b",
        r"\bmicrosoft\s+exchange\b",
        r"\bactive\s+directory\b",
        r"\bsharepoint\b",
        r"\bkubernetes\b.*\bapi\s+server\b",
    ]
]

# CPE vendor tokens that are strongly indicative of enterprise / cloud / SaaS.
_OUT_OF_SCOPE_VENDOR_TOKENS: frozenset[str] = frozenset(
    {
        "microsoft",
        "oracle",
        "sap",
        "salesforce",
        "servicenow",
        "vmware",
        "broadcom",
        "citrix",
        "f5",
        "paloaltonetworks",
        "fortinet",
        "sonicwall",
        "juniper",
        "cisco",
        "checkpoint",
    }
)


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------


def passes_prefilter(
    vuln: dict[str, Any],
    epss_percentile: float | None = None,
) -> tuple[bool, str]:
    """
    Decide whether *vuln* (a raw NVD ``vulnerabilities`` list item) survives the
    pre-filter.

    ``epss_percentile`` is passed in separately because the NVD record does not carry
    EPSS data — the caller fetches it from api.first.org.  When ``None``, the
    EPSS check is skipped so that unscored CVEs are not silently dropped.

    Returns ``(True, "")`` if the CVE passes; ``(False, reason)`` otherwise.
    """
    cve = vuln.get("cve", {})

    # 1. CWE allowlist check
    cwe_fail = _check_cwe(cve)
    if cwe_fail:
        return False, cwe_fail

    # 2. EPSS percentile floor (only when a percentile was provided)
    if epss_percentile is not None:
        epss_fail = _check_epss_percentile(epss_percentile)
        if epss_fail:
            return False, epss_fail

    # 3. Target scope heuristic
    scope_fail = _check_scope(cve)
    if scope_fail:
        return False, scope_fail

    return True, ""


# ---------------------------------------------------------------------------
# Individual checks (package-private; exposed for targeted unit tests)
# ---------------------------------------------------------------------------


def _check_cwe(cve: dict[str, Any]) -> str:
    """Return a discard reason if no in-scope CWE is present, else ''."""
    weaknesses: list[dict[str, Any]] = cve.get("weaknesses", [])
    found_cwes: set[str] = set()
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value.startswith("CWE-"):
                found_cwes.add(value)

    in_scope = found_cwes & CWE_ALLOWLIST
    if not in_scope:
        if found_cwes:
            return f"CWE not in allowlist: {', '.join(sorted(found_cwes))}"
        return "No CWE data"
    return ""


def _check_epss_percentile(percentile: float) -> str:
    """Return a discard reason if EPSS percentile is below the floor, else ''."""
    if percentile < EPSS_PERCENTILE_FLOOR:
        return f"EPSS percentile {percentile:.4f} below floor {EPSS_PERCENTILE_FLOOR}"
    return ""


def _check_scope(cve: dict[str, Any]) -> str:
    """
    Return a discard reason if the target appears to be out-of-scope
    (web app, firmware, kernel, enterprise), else ''.

    Heuristic: check CPE vendor/product strings and the English description.
    """
    # Build a set of lowercase CPE tokens from all configurations.
    cpe_tokens: set[str] = _extract_cpe_tokens(cve)

    # Check product/vendor tokens
    for token in _OUT_OF_SCOPE_PRODUCT_TOKENS:
        if token in cpe_tokens:
            return f"Out-of-scope product token in CPE: {token}"

    for token in _OUT_OF_SCOPE_VENDOR_TOKENS:
        if token in cpe_tokens:
            return f"Out-of-scope vendor in CPE: {token}"

    # Check description text
    description = _get_english_description(cve)
    for pattern in _OUT_OF_SCOPE_DESC_PATTERNS:
        if pattern.search(description):
            return f"Out-of-scope description pattern: {pattern.pattern!r}"

    return ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_cpe_tokens(cve: dict[str, Any]) -> set[str]:
    """
    Walk the NVD ``configurations`` tree and collect lowercased vendor and
    product tokens from all CPE 2.3 strings.

    CPE 2.3 format: ``cpe:2.3:a:<vendor>:<product>:<version>:...``
    We extract index 3 (vendor) and index 4 (product).
    """
    tokens: set[str] = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                parts = cpe.split(":")
                if len(parts) > 4:
                    tokens.add(parts[3].lower())  # vendor
                    tokens.add(parts[4].lower())  # product
    return tokens


def _get_english_description(cve: dict[str, Any]) -> str:
    """Return the English description string, or '' if not present."""
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""
