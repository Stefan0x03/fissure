# Fissure — Development Progress

## Status: Phase 1 complete

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
- [x] `config/settings.py` — EPSS floor, CWE allowlist, NVD lookback, model config
- [x] NVD API wrapper (`agents/triage/tools/nvd.py`)
- [x] Pre-filter logic (`agents/triage/prefilter.py`, rule-based, no LLM)
- [x] Ingest entrypoint (`scripts/ingest.py`) — NVD → EPSS → pre-filter → issues glue
- [x] GitHub Issues writer (`scripts/issues.py`) — `create_candidate_issue()` only
- [x] `cve-ingest.yml` workflow — wires the above end-to-end
- [x] Unit tests: pre-filter (27 tests, pure function) + NVD wrapper (8 tests, httpx mocked); 35/35 passing
- [x] GHSA fetcher via GitHub GraphQL (`agents/triage/tools/ghsa.py`)
- [x] Wire GHSA fetch into `scripts/ingest.py` — called for all pre-filter survivors, result stored in issue body

### Phase 2 — Handoff schema
- [x] Pydantic model for handoff YAML (`schemas/handoff.py`)
- [x] Manual validation: author handoff YAMLs for libwebp CVE-2023-4863, one libarchive CVE, one libtiff CVE
- [ ] Confirm each handoff runs cleanly with `lacuna scan`

### Phase 3 — Triage agent
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
