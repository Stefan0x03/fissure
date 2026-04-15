# Fissure

Agentic CVE-to-exploit pipeline for memory corruption vulnerability research. Fissure orchestrates NVD ingestion, LLM-powered triage, and fuzzing-based reproduction via [Lacuna](https://github.com/Stefan0x03/lacuna) to answer one question: **does advisory-informed seed generation reach vulnerable code paths faster than a generic corpus?**

## How it works

Three GitHub Actions workflows move a CVE from discovery to fuzzing result:

```
NVD poll → pre-filter → GitHub Issue (candidate)
                              ↓
                        triage agent
                         ↙    ↓    ↘
                    discard needs-review approved
                                          ↓
                                   lacuna scan
                                          ↓
                                   findings comment
```

### 1. CVE Ingest (`cve-ingest.yml`)

Runs on a cron schedule. No LLM involved — pure rule-based filtering:

- Queries NVD for CVEs published since last run (`NVD_LOOKBACK_DAYS`)
- Keeps only in-scope CWEs: heap overflow (CWE-122), OOB read/write (CWE-125, CWE-787), use-after-free (CWE-416), integer overflow (CWE-190)
- Requires EPSS percentile above `EPSS_PERCENTILE_FLOOR` (default: top 90%)
- Excludes kernel, firmware, web apps, and enterprise software
- Creates a GitHub Issue per survivor with the `candidate` label and raw GHSA data

### 2. CVE Triage (`cve-triage.yml`)

Triggered after ingest, on a daily schedule, or via `workflow_dispatch`. Processes each `candidate` issue through a Google ADK agent (Haiku via litellm):

- Reasons over EPSS score, GHSA advisory, PoC availability, containerizability, and fuzzer alignment
- Posts a triage comment containing a **handoff YAML** (never edits the issue body)
- Applies outcome label: `approved` (auto-proceed), `needs-review` (human gate), or `discarded` (close)

### 3. Lacuna Runner (`lacuna-runner.yml`)

Triggered two ways:

- **`issues: labeled`** — fires immediately when the `approved` label is applied (covers manual approval of `needs-review` issues)
- **`workflow_run`** after CVE Triage completes — drains any remaining `approved` queue not yet processed

Per issue: extracts the handoff YAML from the triage comment, checks out and installs Lacuna, builds the sandbox image, runs `lacuna scan`, and posts findings back as a comment. After the immediate issue is handled, a drain loop processes any remaining `approved` issues in the queue.

## Issue state machine

| Label | Meaning |
|---|---|
| `candidate` | Survived pre-filter, awaiting triage |
| `needs-review` | Medium confidence — human must apply `approved` to proceed |
| `approved` | Triggers Lacuna runner |
| `discarded` | Low confidence, closed |
| `in-progress` | Lacuna scan running |
| `complete` | Scan finished, findings posted |
| `failed` | Scan error |

## Handoff YAML schema

The triage comment contains two fenced YAML blocks. The first is the Lacuna target spec:

```yaml
# Fissure handoff — Lacuna target spec
name: jq
version: 1.7.1
language: c
source:
  type: git
  url: https://github.com/jqlang/jq
  ref: fdf8ef0f0810e3d365cdd5160de43db46f57ed03~1
description: Command-line JSON processor with type confusion in _strindices builtin
attack_surface_hint: |
  _strindices in src/builtin.c passes arguments to jv_string_indexes() without type checks.
  Type confusion: numeric values where strings expected → assert-less pointer dereference.
  PoC: echo '[1,2,3]' | jq '_strindices(0)'
build_hint: |
  git clone https://github.com/jqlang/jq && cd jq
  git checkout <vulnerable-ref>
  CFLAGS="-fsanitize=address -g" ./configure && make
```

The second block is Fissure metadata (ignored by Lacuna, used for research tracking):

```yaml
# Fissure metadata
fissure:
  cve_id: CVE-YYYY-NNNNN
  epss_score: 0.97        # null if pending
  epss_percentile: 0.99   # null if pending
  confidence_tier: high   # high | medium
  ghsa_id: GHSA-xxxx-xxxx-xxxx   # if available
  poc_url: https://...            # if found
  schema_version: "1"
```

The schema is validated by [schemas/handoff.py](schemas/handoff.py). Supported languages are currently `c` and `cpp`.

## Repository layout

```
.github/workflows/
  cve-ingest.yml        # Cron: NVD poll → candidate issues
  cve-triage.yml        # ADK agent: triage → handoff YAML + labels
  lacuna-runner.yml     # On approved / post-triage: lacuna scan + drain loop
agents/
  triage/
    agent.py            # ADK agent definition
    prefilter.py        # Rule-based pre-filter (no LLM)
    tools/              # NVD, EPSS, GHSA, PoC search, web search
config/
  settings.py           # Thresholds, model strings, API URLs
schemas/
  handoff.py            # Pydantic model for handoff YAML
scripts/
  ingest.py             # NVD polling and issue creation
  issues.py             # GitHub Issues/labels/comments helpers
  triage.py             # Triage workflow entrypoint
  lacuna_runner.py      # Handoff extraction and lacuna invocation
tests/
```

## Setup

**Prerequisites:** Python 3.11+, GitHub repo with Actions enabled, secrets configured.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

**Required secrets (GitHub Actions):**

| Secret | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Triage agent and Lacuna scans |
| `GITHUB_TOKEN` | Auto-provided by Actions |
| `LACUNA_TOKEN` | PAT for checking out the Lacuna repo |
| `NVD_API_KEY` | Optional — higher NVD rate limits |

## Configuration

All tunable parameters are in [config/settings.py](config/settings.py):

| Parameter | Default | Notes |
|---|---|---|
| `EPSS_PERCENTILE_FLOOR` | `0.10` | Top 90% of all scored CVEs |
| `CWE_ALLOWLIST` | 5 CWEs | See settings.py |
| `NVD_LOOKBACK_DAYS` | `2` | Overlap with cron cadence |
| `TRIAGE_MODEL` | `claude-haiku-4-5-20251001` | Switch to Sonnet for quality eval |
| `LACUNA_MODEL` | `claude-haiku-4-5-20251001` | Passed to `lacuna scan` |
| `LACUNA_MAX_ITERATIONS` | `75` | Turn budget per scan |

## Key metric

**Turn at first crash** — tracked per Lacuna run, correlated against triage confidence tier. The core research result: do high-confidence (advisory-informed) targets show lower turn-at-first-crash than medium-confidence targets?

The GitHub Issues audit trail is the primary data source for this analysis and doubles as a labeled dataset for future confidence model calibration.

## Known-good validation targets

Before running against novel CVEs, validate the pipeline end-to-end against:

- **libwebp** CVE-2023-4863 — VP8L path, well-documented
- **libarchive** — frequent memory corruption CVEs, clean ASAN builds
- **libtiff** — long audit history, many known-good PoCs

## Cost model

| Stage | Model | Est. volume |
|---|---|---|
| Pre-filter | None | ~50–100 CVEs/day |
| Triage | Haiku | ~10–20/day (post-filter) |
| Lacuna scan | Haiku/Sonnet | ~3–5/week (post-approval) |

A few dollars/day during active research. Turn limit is the primary cost lever.

## Further reading

- [Fissure.md](Fissure.md) — full research context, hypothesis, and paper angle
- [config/settings.py](config/settings.py) — all tunable parameters
