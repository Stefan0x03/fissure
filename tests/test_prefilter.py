"""
Unit tests for agents/triage/prefilter.py.

Pure function — no network calls, no mocking required.
"""

import pytest

from agents.triage.prefilter import (
    _check_cwe,
    _check_epss_percentile,
    _check_scope,
    passes_prefilter,
)
from config.settings import CWE_ALLOWLIST, EPSS_PERCENTILE_FLOOR


# ---------------------------------------------------------------------------
# Helpers to build minimal NVD-shaped dicts
# ---------------------------------------------------------------------------


def make_vuln(
    *,
    cwes: list[str] | None = None,
    description: str = "",
    cpe_strings: list[str] | None = None,
) -> dict:
    """Build a minimal NVD vulnerability object for testing."""
    weaknesses = []
    if cwes:
        weaknesses = [
            {"description": [{"lang": "en", "value": cwe} for cwe in cwes]}
        ]

    descriptions = []
    if description:
        descriptions = [{"lang": "en", "value": description}]

    nodes = []
    if cpe_strings:
        nodes = [
            {
                "cpeMatch": [
                    {"criteria": cpe, "vulnerable": True} for cpe in cpe_strings
                ]
            }
        ]

    return {
        "cve": {
            "id": "CVE-2024-99999",
            "weaknesses": weaknesses,
            "descriptions": descriptions,
            "configurations": [{"nodes": nodes}] if nodes else [],
        }
    }


# ---------------------------------------------------------------------------
# _check_cwe
# ---------------------------------------------------------------------------


class TestCheckCWE:
    def test_in_scope_cwe_passes(self):
        for cwe in CWE_ALLOWLIST:
            cve = make_vuln(cwes=[cwe])["cve"]
            assert _check_cwe(cve) == ""

    def test_out_of_scope_cwe_fails(self):
        cve = make_vuln(cwes=["CWE-79"])["cve"]  # XSS
        reason = _check_cwe(cve)
        assert reason != ""
        assert "CWE-79" in reason

    def test_no_cwe_fails(self):
        cve = make_vuln()["cve"]
        reason = _check_cwe(cve)
        assert reason != ""
        assert "No CWE" in reason

    def test_multiple_cwes_one_in_scope_passes(self):
        cve = make_vuln(cwes=["CWE-79", "CWE-787"])["cve"]
        assert _check_cwe(cve) == ""

    def test_multiple_cwes_none_in_scope_fails(self):
        cve = make_vuln(cwes=["CWE-79", "CWE-89"])["cve"]
        reason = _check_cwe(cve)
        assert reason != ""

    def test_all_allowlisted_cwes_individually(self):
        for cwe in ["CWE-122", "CWE-125", "CWE-416", "CWE-787"]:
            cve = make_vuln(cwes=[cwe])["cve"]
            assert _check_cwe(cve) == "", f"{cwe} should be in allowlist"


# ---------------------------------------------------------------------------
# _check_epss_percentile
# ---------------------------------------------------------------------------


class TestCheckEPSSPercentile:
    def test_above_floor_passes(self):
        assert _check_epss_percentile(EPSS_PERCENTILE_FLOOR + 0.01) == ""

    def test_at_floor_passes(self):
        assert _check_epss_percentile(EPSS_PERCENTILE_FLOOR) == ""

    def test_below_floor_fails(self):
        reason = _check_epss_percentile(EPSS_PERCENTILE_FLOOR - 0.001)
        assert reason != ""
        assert "EPSS" in reason

    def test_zero_fails(self):
        reason = _check_epss_percentile(0.0)
        assert reason != ""

    def test_one_passes(self):
        assert _check_epss_percentile(1.0) == ""


# ---------------------------------------------------------------------------
# _check_scope
# ---------------------------------------------------------------------------


class TestCheckScope:
    def test_clean_userspace_library_passes(self):
        cve = make_vuln(
            description="A heap-based buffer overflow in libpng before 1.6.40.",
            cpe_strings=["cpe:2.3:a:libpng:libpng:1.6.37:*:*:*:*:*:*:*"],
        )["cve"]
        assert _check_scope(cve) == ""

    def test_web_app_description_fails(self):
        cve = make_vuln(
            description="A SQL injection vulnerability in the web application login form.",
        )["cve"]
        reason = _check_scope(cve)
        assert reason != ""

    def test_xss_description_fails(self):
        cve = make_vuln(
            description="Cross-site scripting (XSS) in the admin panel.",
        )["cve"]
        reason = _check_scope(cve)
        assert reason != ""

    def test_firmware_cpe_fails(self):
        cve = make_vuln(
            cpe_strings=["cpe:2.3:o:vendor:firmware:1.0:*:*:*:*:*:*:*"],
        )["cve"]
        reason = _check_scope(cve)
        assert reason != ""
        assert "firmware" in reason

    def test_linux_kernel_cpe_fails(self):
        cve = make_vuln(
            cpe_strings=["cpe:2.3:o:linux:linux_kernel:6.5:*:*:*:*:*:*:*"],
        )["cve"]
        reason = _check_scope(cve)
        assert reason != ""
        assert "linux_kernel" in reason

    def test_cisco_vendor_fails(self):
        cve = make_vuln(
            cpe_strings=["cpe:2.3:o:cisco:ios_xe:17.3:*:*:*:*:*:*:*"],
        )["cve"]
        reason = _check_scope(cve)
        assert reason != ""

    def test_microsoft_vendor_fails(self):
        cve = make_vuln(
            cpe_strings=["cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*"],
        )["cve"]
        reason = _check_scope(cve)
        assert reason != ""

    def test_wordpress_description_fails(self):
        cve = make_vuln(
            description="A remote code execution vulnerability in WordPress 6.2.",
        )["cve"]
        reason = _check_scope(cve)
        assert reason != ""

    def test_no_cpe_no_desc_passes(self):
        """No CPE or description — we can't rule it out; let CWE/EPSS decide."""
        cve = make_vuln()["cve"]
        assert _check_scope(cve) == ""


# ---------------------------------------------------------------------------
# passes_prefilter — integration across all three checks
# ---------------------------------------------------------------------------


class TestPassesPrefilter:
    def _good_vuln(self) -> dict:
        return make_vuln(
            cwes=["CWE-787"],
            description="Out-of-bounds write in libwebp before 1.3.2.",
            cpe_strings=["cpe:2.3:a:webmproject:libwebp:1.3.1:*:*:*:*:*:*:*"],
        )

    def test_passes_all_checks(self):
        ok, reason = passes_prefilter(self._good_vuln(), epss_percentile=0.5)
        assert ok is True
        assert reason == ""

    def test_fails_cwe(self):
        vuln = make_vuln(cwes=["CWE-79"], description="XSS in libfoo.")
        ok, reason = passes_prefilter(vuln, epss_percentile=0.5)
        assert ok is False
        assert "CWE" in reason

    def test_fails_epss_percentile(self):
        ok, reason = passes_prefilter(self._good_vuln(), epss_percentile=0.0)
        assert ok is False
        assert "EPSS" in reason

    def test_fails_scope(self):
        vuln = make_vuln(
            cwes=["CWE-787"],
            cpe_strings=["cpe:2.3:o:linux:linux_kernel:6.5:*:*:*:*:*:*:*"],
        )
        ok, reason = passes_prefilter(vuln, epss_percentile=0.5)
        assert ok is False

    def test_epss_none_skips_epss_check(self):
        """When epss_percentile is None the EPSS check is skipped entirely."""
        ok, reason = passes_prefilter(self._good_vuln(), epss_percentile=None)
        assert ok is True
        assert reason == ""

    def test_epss_at_floor_passes(self):
        ok, reason = passes_prefilter(self._good_vuln(), epss_percentile=EPSS_PERCENTILE_FLOOR)
        assert ok is True

    def test_epss_just_below_floor_fails(self):
        ok, reason = passes_prefilter(self._good_vuln(), epss_percentile=EPSS_PERCENTILE_FLOOR - 0.001)
        assert ok is False
        assert "EPSS" in reason
