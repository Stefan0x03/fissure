# Fissure — Claude Code Guide

Fissure is an agentic CVE-to-exploit pipeline for memory corruption vulnerability research. It orchestrates three GitHub Actions workflows to move CVEs from NVD ingestion through LLM triage to fuzzing-based reproduction via Lacuna. The primary research question: does LLM-informed seed generation using CVE advisory context reach vulnerable code paths faster than a generic corpus?

See `Fissure.md` for full research context, hypothesis, and paper angle.

---

## Tech stack

- **Language:** Python
- **Agent framework:** Google ADK (`google-adk`) with the Vertex AI flag disabled — ADK runs against any model via litellm, not GCP
- **Model routing:** litellm — provides portability across Claude, GPT, Gemini, etc. without code changes
- **Default model:** Haiku (cost control during development); Sonnet/Opus are toggled per-run for Lacuna via config
- **GitHub orchestration:** GitHub Actions + GitHub Issues (Issues serve as the audit trail and state machine)

---

## Repository layout

```
fissure/
  .github/workflows/
    cve-ingest.yml       # Cron: NVD poll → pre-filter → create candidate issues
    cve-triage.yml       # Per-issue: ADK triage agent → label + handoff or discard
    lacuna-runner.yml    # On approved label: extract handoff YAML → lacuna scan
  agents/
    triage/              # ADK triage agent and its tools
      agent.py
      tools/             # NVD, EPSS, GHSA, GitHub search API wrappers
  schemas/               # Pydantic models: handoff YAML, issue body
  config/                # Tunable thresholds and model config
  scripts/               # GitHub Issues glue, label management
  tests/
  Fissure.md
  CLAUDE.md
```

---

## GitHub Actions workflows

### `cve-ingest.yml` (cron)

Runs on a schedule. Responsibilities:
1. Query NVD API for CVEs published since last run
2. Apply rule-based pre-filter — no LLM involved:
   - CWE must be in scope: CWE-122, CWE-125, CWE-416, CWE-787
   - EPSS score must meet the configured floor (`config/settings.py`)
   - Target must be a userspace library or binary (exclude web apps, firmware, kernel, enterprise software)
3. Create a GitHub Issue per surviving CVE with the `candidate` label

No LLM calls in this workflow. Cost: free.

### `cve-triage.yml` (per candidate issue)

Triggered when a `candidate` issue is created (or on-demand). Runs the ADK triage agent against a single issue. Responsibilities:
1. Fetch full EPSS score and percentile
2. Fetch linked GitHub Security Advisory (GHSA) — often more detailed than NVD; may include patch diffs, affected version ranges, and vulnerable function names
3. Search for public PoCs (GitHub code search, Exploit-DB)
4. Reason over all gathered data and produce a confidence assessment
5. Update the issue:
   - **High confidence:** add `approved` label, embed handoff YAML in issue body
   - **Medium confidence:** add `needs-review` label, embed partial handoff YAML
   - **Low confidence:** close issue with discard rationale

### `lacuna-runner.yml` (on `approved` label)

Triggered by the `approved` label being applied to an issue. Responsibilities:
1. Extract the handoff YAML block from the issue body
2. Write it to a temporary file
3. Check out the Lacuna repository
4. Run `lacuna scan <handoff.yaml>` as a shell step
5. Post the findings report back to the issue as a comment

Lacuna is invoked directly as a CLI command — no ADK or litellm involvement in this workflow.

---

## Issue state machine

Issues carry workflow state via labels:

```
candidate → triage → discard (closed)
                   → needs-review (awaiting human approval)
                   → approved → lacuna-runner triggered → complete / failed
```

Human review: apply `approved` label to a `needs-review` issue. That label transition triggers `lacuna-runner.yml`.

Label set: `candidate`, `needs-review`, `approved`, `discarded`, `in-progress`, `complete`, `failed`

---

## Triage agent

Single ADK agent using Haiku via litellm. Not a multi-agent pipeline — the reasoning chain (fetch → enrich → synthesize) is linear enough for one agent with tools.

**Tools the agent has access to:**
- NVD API wrapper — fetch full CVE record
- EPSS API wrapper (`api.first.org/data/1.0/epss`) — fetch score and percentile by CVE ID
- GHSA fetcher — retrieve linked GitHub Security Advisories via GitHub GraphQL API
- PoC search — GitHub code search and Exploit-DB lookup
- GitHub Issues writer — update issue body and labels

**Confidence signals the agent reasons over:**
- EPSS score and percentile
- Advisory specificity (does it name the vulnerable function or code path?)
- PoC availability
- Target containerizability (can the affected version be built with ASAN or pulled as a known image?)
- Advisory-to-harness alignment (does the vulnerability type fit fuzzing-based reproduction?)

Confidence tier thresholds are tunable parameters in `config/settings.py`. Calibrate after the first batch of real runs.

---

## Handoff YAML schema

The triage agent's primary output is a Lacuna-compatible target YAML embedded in the issue body inside a fenced code block (` ```yaml `). This is the critical interface between triage and Lacuna.

The schema extends Lacuna's existing target spec:

```yaml
# Fissure handoff — Lacuna target spec
name: <library-name>
version: <affected-version>
language: <c|cpp|rust|...>        # Lacuna currently supports c/cpp; others tracked in Lacuna repo
source:
  type: <git|tarball|local>
  url: <repository or tarball url>
  ref: <tag or commit for the vulnerable version>
description: <one-line description>
attack_surface_hint: |
  <CVE advisory summary, vulnerable function or code path if known,
   GHSA patch diff context, PoC hints if available>
build_hint: |
  <build instructions with ASAN flags if determinable from advisory>

# Fissure metadata (not consumed by Lacuna, used for research tracking)
fissure:
  cve_id: <CVE-YYYY-NNNNN>
  epss_score: <float>
  epss_percentile: <float>
  confidence_tier: <high|medium>
  ghsa_id: <GHSA-xxxx-xxxx-xxxx>   # if available
  poc_url: <url>                    # if found
  schema_version: "1"
```

The `fissure:` block is ignored by Lacuna but preserved in the issue for research tracking and future confidence model calibration.

---

## Configuration (`config/settings.py`)

Tunable parameters:
- `EPSS_FLOOR` — minimum EPSS score to survive pre-filter (start around 0.1, calibrate)
- `CWE_ALLOWLIST` — set of in-scope CWE IDs
- `CONFIDENCE_HIGH_THRESHOLD` / `CONFIDENCE_MEDIUM_THRESHOLD` — triage tier cutoffs
- `TRIAGE_MODEL` — litellm model string for triage agent (default: Haiku)
- `LACUNA_MODEL` — model string passed to Lacuna at invocation (default: Sonnet)
- `NVD_LOOKBACK_DAYS` — how many days back the cron poll queries

---

## External APIs

- **NVD:** `https://services.nvd.nist.gov/rest/json/cves/2.0` — no key required for low-volume polling; key available for higher rate limits
- **EPSS:** `https://api.first.org/data/1.0/epss` — public, no key required
- **GHSA:** GitHub GraphQL API (`https://api.github.com/graphql`) — requires `GITHUB_TOKEN`
- **GitHub Issues / Labels:** GitHub REST API — uses `GITHUB_TOKEN` from Actions environment

---

## Scope boundaries

**In scope for this repo:**
- NVD ingest, pre-filter, and issue creation
- ADK triage agent and all its API tools
- Handoff YAML schema
- GitHub Actions workflows (all three)
- GitHub Issues label/state management
- Lacuna invocation glue in `lacuna-runner.yml`

**Out of scope for this repo:**
- Changes to Lacuna internals (tracked as issues in the Lacuna repo)
- Language-agnostic fuzzing tooling (Lacuna concern)
- CVE backfill or re-ingestion of updated CVEs
- Confidence score weighted formula (deferred until labeled data accumulates)
- Web application CVEs

---

## Development priorities

1. Implement `cve-ingest.yml` and the pre-filter first — this is the foundation and provides real CVE data to test triage against
2. Design and validate the handoff YAML schema against the known-good targets (libwebp CVE-2023-4863, libarchive, libtiff) before building the triage agent
3. Build the triage agent tools incrementally — NVD and EPSS first, GHSA second, PoC search last
4. Wire up `lacuna-runner.yml` only after at least one handoff YAML has been manually validated against a real Lacuna run

Use Haiku for all development and testing runs. Switch to Sonnet only when evaluating triage quality, not during iteration.

---

## Key research metric

**Turn at first crash** — tracked per Lacuna run, correlated against triage confidence tier and EPSS score. The core quantitative result for the paper is whether high-confidence (advisory-informed) targets show lower turn-at-first-crash than medium-confidence targets. The GitHub Issues audit trail is the primary data source for this analysis.
