# Fissure

Fissure is an agentic CVE-to-exploit pipeline for memory corruption vulnerability research. It automates the path from NVD ingestion through exploitability triage to fuzzing-based reproduction, using AI to compress the CVE-to-PoC timeline. The primary goal is publishable security research examining how effectively AI accelerates exploit development for memory corruption vulnerabilities — specifically whether advisory-informed seed generation outperforms blind fuzzing.

---

## Research hypothesis

AI-guided fuzzing with CVE advisory context reaches vulnerable code paths faster than a generic corpus. This is measurable via coverage metrics and turn-at-first-crash across a controlled sample of CVEs with known PoCs.

---

## Architecture overview

Fissure separates concerns into two distinct agents with different jobs:

**Triage agent** — broad information retrieval and go/no-go decision-making. Runs continuously via GitHub Actions on a cron schedule. Responsible for NVD polling, EPSS enrichment, GitHub Security Advisory (GHSA) retrieval, PoC discovery, and structured confidence scoring. Produces a handoff artifact consumed by the research loop.

**Lacuna research loop** — narrow execution-focused fuzzing agent. Receives a structured handoff from triage and attempts exploit reproduction against an isolated target environment. Operates within a turn budget, logs findings, and posts results back to the issue tracker.

These agents are intentionally decoupled. CVE retrieval and GHSA scraping live in the triage layer to keep Lacuna clean and focused.

---

## Triage agent

### Information retrieval

- Poll NVD API on a cron schedule for new CVEs
- Enrich with EPSS score from FIRST (0–1 float, probability of exploitation in the wild)
- Fetch linked GitHub Security Advisories — often more detailed than NVD entries, may include patch diffs and affected version ranges
- Search for public PoCs via GitHub code search and Exploit-DB

### Pre-filter (rule-based, no LLM)

Before any model is invoked, discard CVEs that do not meet baseline criteria:

- CWE must be in scope: heap overflow (CWE-122), OOB read (CWE-125), OOB write (CWE-787), use-after-free (CWE-416)
- EPSS score above a configurable floor
- Target must be a userspace C/C++ library or binary — exclude Windows kernel, enterprise software, IoT firmware, web applications

This culls the majority of daily CVE volume before any LLM cost is incurred.

### LLM tiering

- **Haiku** — shallow triage on pre-filtered survivors. Binary assessment: is this harness-feasible, is the advisory specific enough to act on? Cheap and fast.
- **Sonnet** — deep triage on CVEs that pass shallow triage. Full confidence scoring, PoC synthesis, structured handoff generation.

### Confidence model

The triage agent produces a confidence score synthesized from the following signals:

- EPSS score
- Advisory specificity — does it name the vulnerable function or code path, or is it vague?
- PoC availability — known PoC is a strong positive signal; patch diff is useful even without one
- Target containerizability — can the affected version be built with ASAN from source or pulled as a known image?
- Advisory-to-harness alignment — does the vulnerability type fit Lacuna's fuzzing approach?

Confidence scoring is performed via LLM reasoning over these inputs. A weighted formula approach is deferred to a later iteration once empirical data on triage accuracy is available.

### Confidence tiers

| Tier | Action |
|---|---|
| High | Auto-approve, create `approved` issue, trigger Lacuna |
| Medium | Create issue with `needs-review` label, queue for human review |
| Low | Discard, close issue automatically |

Tier thresholds are tunable parameters — calibrate after the first batch of runs.

---

## GitHub Actions orchestration

### Why Actions

- Cron-based NVD polling is free compute — no persistent service required
- GitHub Issues provides a natural audit trail and state machine for the research workflow
- Issue history is human-readable, useful for paper methodology documentation, and doubles as a labeled dataset for future confidence model calibration
- Migration from hosted to self-hosted runners is a one-line YAML change if needed

### Issue state machine

Issues carry workflow state via labels:

```
candidate → [shallow triage] → discard (closed)
                             → deep triage → low confidence (closed)
                                           → medium confidence → needs-review
                                           → high confidence → approved → Lacuna triggered
```

Human review consists of applying the `approved` label to a `needs-review` issue.

### Lacuna trigger

Lacuna polls for `approved` issues it has not yet processed (or receives a webhook trigger on label change). It extracts the structured handoff from the issue body, provisions the target environment, runs the research loop, and posts findings back to the issue as a comment.

### Runner strategy

Start with GitHub-hosted runners. The 6-hour job limit is sufficient for current 50-turn runs (typically 1–2 hours). Migrate to a self-hosted runner if run duration grows or consistent execution environment becomes important. Migration requires only changing `runs-on: ubuntu-latest` to `runs-on: self-hosted`.

Docker-in-Docker is supported on both hosted and self-hosted runners, enabling fully containerized Lacuna execution.

---

## Lacuna integration

### What changes

Minimal. Lacuna's existing turn-based agentic loop is largely unchanged. The primary addition is consuming the triage handoff as pre-loaded context before the loop starts — the model is given advisory knowledge and a specific hypothesis to test rather than starting blind.

Additional tooling to consider:

- Coverage-diff tool so the agent can assess whether seed inputs are reaching the code path described in the advisory
- Structured findings output compatible with the issue comment format

### Turn budget

50 turns initially, tuned based on empirical results. At current run durations (1–2 hours), cost per run is approximately $1–3 in Sonnet API calls depending on context accumulation.

### Context management

Context grows across turns as crash logs and ASAN output accumulate. Mitigations:

- Summarize completed turns periodically rather than retaining full history
- Truncate ASAN output to the relevant stack trace, not the full report
- Store full logs to disk for the findings record; inject only structured summaries back into context

### Key metric

**Turn at first crash.** Tracked per run and correlated against triage confidence tier. If advisory-informed seeding is effective, high-confidence targets should show lower turn-at-first-crash values than medium-confidence targets. This is the core quantitative result for the research paper.

---

## Triage handoff schema

*Deferred — to be designed in the first Claude Code session.*

The handoff is the critical interface between the triage agent and Lacuna. It must carry sufficient information for Lacuna to provision a target environment, initialize a meaningful seed corpus, and understand the vulnerable code path. Design this schema before implementing either agent.

---

## Target selection

### Vulnerability classes in scope

Memory corruption vulnerabilities in userspace C/C++ libraries with containerizable targets:

- Heap buffer overflow (CWE-122)
- Out-of-bounds read (CWE-125)
- Out-of-bounds write (CWE-787)
- Use-after-free (CWE-416)

### Suggested initial targets (known PoCs, containerizable)

Use these to validate the pipeline end-to-end before attempting novel reproduction:

- **libwebp** CVE-2023-4863 — well-documented, VP8L path is specific enough for targeted seeding
- **libarchive** — frequent memory corruption CVEs, well-maintained ASAN builds
- **libtiff** — long audit history, many known-good PoCs available

### Why not web application CVEs

Web app exploit validation requires reliable detection of exploitation success (e.g. RCE confirmation) from agent feedback, which is semantically ambiguous. Memory corruption with a local harness provides clean, unambiguous signals: crash or no crash, ASAN report or clean run. This makes the agent feedback loop tractable.

---

## Cost model

| Stage | Model | Volume | Notes |
|---|---|---|---|
| Pre-filter | None | ~50–100 CVEs/day | Rule-based, free |
| Shallow triage | Haiku | ~10–20/day | Low cost per token |
| Deep triage | Sonnet | ~3–5/day | Gated by Haiku pass |
| Research loop | Sonnet | ~3–5/week | Gated by confidence threshold |

Estimated API cost: a few dollars per day during active research. Research loop runs are the primary cost variable — controlled by turn limit and triage funnel tightness.

---

## Research paper angle

The differentiating contribution is not "AI can reproduce CVEs" but specifically: **does LLM-informed seed generation using CVE advisory context reach vulnerable code paths faster than a generic corpus?**

Supporting measurements:
- Turn at first crash (per run, correlated with confidence tier)
- Code coverage at crash vs. baseline fuzzing
- Time-to-PoC with vs. without advisory context (if feasible to instrument)
- Triage confidence vs. actual reproducibility (accumulated labeled dataset from issue history)

The issue tracker audit trail provides methodology documentation at no additional cost.

---

## Open questions

- Triage handoff schema (first design decision in implementation)
- Confidence tier thresholds (calibrate empirically after first batch)
- Whether to open-source the tooling alongside the paper
- Long-term: weighted formula for confidence scoring once labeled data accumulates
