# Fissure — Development Progress

## Status: Pre-implementation

Design and architecture complete. CLAUDE.md written. No code exists yet.

---

## Completed

- [x] Architecture design (`Fissure.md`)
- [x] Tech stack decisions (Python, Google ADK, litellm, Haiku default)
- [x] Three-workflow GitHub Actions decomposition
- [x] Handoff YAML schema design
- [x] Issue state machine and label set
- [x] `CLAUDE.md` authored

---

## Up next

### Phase 1 — Ingest
- [ ] `config/settings.py` — EPSS floor, CWE allowlist, NVD lookback, model config
- [ ] NVD API wrapper (`agents/triage/tools/nvd.py`)
- [ ] Pre-filter logic (rule-based, no LLM)
- [ ] GitHub Issues writer (`scripts/issues.py`) — create issue, apply labels
- [ ] `cve-ingest.yml` workflow — wires the above end-to-end

### Phase 2 — Handoff schema
- [ ] Pydantic model for handoff YAML (`schemas/handoff.py`)
- [ ] Manual validation: author handoff YAMLs for libwebp CVE-2023-4863, one libarchive CVE, one libtiff CVE
- [ ] Confirm each handoff runs cleanly with `lacuna scan`

### Phase 3 — Triage agent
- [ ] EPSS API tool (`agents/triage/tools/epss.py`)
- [ ] GHSA fetcher via GitHub GraphQL (`agents/triage/tools/ghsa.py`)
- [ ] PoC search tool — GitHub code search + Exploit-DB (`agents/triage/tools/poc_search.py`)
- [ ] ADK triage agent (`agents/triage/agent.py`)
- [ ] `cve-triage.yml` workflow

### Phase 4 — Lacuna runner
- [ ] Handoff extraction from issue body (`scripts/extract_handoff.py`)
- [ ] `lacuna-runner.yml` workflow
- [ ] Findings comment posting

### Phase 5 — Calibration
- [ ] Run pipeline against known-PoC targets
- [ ] Tune confidence tier thresholds
- [ ] Validate turn-at-first-crash tracking

---

## Notes

_Add session notes here as work progresses._
