"""
Fissure configuration — tunable parameters for ingest, triage, and Lacuna invocation.
Adjust thresholds after the first batch of real runs.
"""

# --- Ingest / pre-filter ---

# Minimum EPSS score to survive the pre-filter. Start conservative; calibrate downward
# once real data accumulates.
EPSS_FLOOR: float = 0.1

# CWE IDs in scope for fuzzing-based reproduction. Only memory-corruption classes that
# map cleanly to ASAN/fuzzer detection.
CWE_ALLOWLIST: set[str] = {
    "CWE-122",  # Heap-based buffer overflow
    "CWE-125",  # Out-of-bounds read
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
LACUNA_MODEL: str = "claude-sonnet-4-6"

# --- NVD API ---

NVD_BASE_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Optional — set via environment variable NVD_API_KEY for higher rate limits.
# When absent, NVD enforces a 5-request/30s rolling window.
NVD_API_KEY_ENV: str = "NVD_API_KEY"

# --- EPSS API ---

EPSS_BASE_URL: str = "https://api.first.org/data/1.0/epss"

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
