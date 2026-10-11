"""
Fissure configuration — tunable parameters for ingest, triage, and Lacuna invocation.
Adjust thresholds after the first batch of real runs.
"""

# --- Ingest / pre-filter ---

# Minimum EPSS percentile (0–1) to survive the pre-filter. Percentile is a stable
# relative ranking — 0.10 always means "top 90% of all scored CVEs" regardless of how
# the raw score distribution shifts. Calibrate after the first batch of labeled runs.
EPSS_PERCENTILE_FLOOR: float = 0.10

# CWE IDs in scope for fuzzing-based reproduction. Only memory-corruption classes that
# map cleanly to ASAN/fuzzer detection.
CWE_ALLOWLIST: set[str] = {
    "CWE-122",  # Heap-based buffer overflow
    "CWE-125",  # Out-of-bounds read
    "CWE-190",  # Integer overflow (often leads to heap corruption)
    "CWE-416",  # Use-after-free
    "CWE-787",  # Out-of-bounds write
}

# How many days back the NVD cron poll queries. Must overlap with cron cadence to avoid
# gaps; a small overlap (e.g. run daily, look back 2 days) is intentional.
NVD_LOOKBACK_DAYS: int = 2

# --- Model config (litellm model strings) ---

# Used by the ADK triage agent. Haiku during development; switch to Sonnet for
# quality evaluation runs only.
TRIAGE_MODEL: str = "claude-haiku-4-5-20251001"

# Passed to `lacuna scan` at invocation.
LACUNA_MODEL: str = "claude-haiku-4-5-20251001"

# Maximum agent iterations per Lacuna scan run.
LACUNA_MAX_ITERATIONS: int = 75

# Immutable commit SHA for Stefan0x03/lacuna checkout. SECURITY: This pin prevents
# supply-chain attacks via mutable branch references. The checked-out code is installed
# in editable mode and executed with ANTHROPIC_API_KEY and GITHUB_TOKEN in scope.
#
# REQUIRED: Must be a 40-character git commit SHA (lowercase hex). The workflow will
# fail if this is not set to a valid SHA.
#
# To set: (1) identify your target commit in Stefan0x03/lacuna, (2) audit that commit
# for malicious code in setup.py, pyproject.toml, build scripts, and CLI entry points,
# (3) set this value to the full 40-character commit SHA.
#
# Example: LACUNA_COMMIT_SHA: str = "a1b2c3d4e5f6789012345678901234567890abcd"
LACUNA_COMMIT_SHA: str = "REPLACE_WITH_AUDITED_COMMIT_SHA"

# --- NVD API ---

NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Optional — set via environment variable NVD_API_KEY for higher rate limits.
# When absent, NVD enforces a 5-request/30s rolling window.
NVD_API_KEY_ENV: str = "NVD_API_KEY"

# --- EPSS API ---

EPSS_BASE_URL: str = "https://api.first.org/data/v1/epss"

# --- GitHub ---

# Labels used across the issue state machine.
LABEL_CANDIDATE: str = "candidate"
LABEL_NEEDS_REVIEW: str = "needs-review"
LABEL_APPROVED: str = "approved"
LABEL_DISCARDED: str = "discarded"
LABEL_IN_PROGRESS: str = "in-progress"
LABEL_COMPLETE: str = "complete"
LABEL_FAILED: str = "failed"

# --- Triage confidence tiers ---
# Calibrate after the first batch of labeled runs.

CONFIDENCE_HIGH_THRESHOLD: float = 0.75
CONFIDENCE_MEDIUM_THRESHOLD: float = 0.40
