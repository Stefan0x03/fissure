# Fissure — Development Progress

## Status: Phase 3 complete

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
- [x] PoC search tool — GitHub code search + Exploit-DB (`agents/triage/tools/poc_search.py`)
- [x] `post_triage_comment()` and `get_issue_body()` in `scripts/issues.py`
- [x] ADK triage agent (`agents/triage/agent.py`) — `google-adk==1.28.0`, `litellm==1.82.6`; init with `LiteLlm(model=TRIAGE_MODEL)`, `GOOGLE_GENAI_USE_VERTEXAI=FALSE`
- [x] Triage entrypoint (`scripts/triage.py`) — CLI wrapper called by workflow
- [x] Unit tests: `tests/test_poc_search.py`, smoke test for `scripts/triage.py`
- [x] `cve-triage.yml` workflow — trigger: `labeled` event ~~with `candidate` label (not `opened`)~~
      ↳ superseded by Phase 3 fix below
- [x] Sequential triage queue — replaced `issues: labeled` trigger with `workflow_run` + `schedule` +
      `workflow_dispatch`; added `list_untriaged_candidates()` to `scripts/issues.py`; drain-mode
      added to `scripts/triage.py`; concurrency group prevents double-processing

### Phase 4 — Lacuna runner
- [ ] Handoff extraction from triage comment (`scripts/extract_handoff.py`) — find comment by author `github-actions[bot]`, extract first ` ```yaml ` block
- [ ] `lacuna-runner.yml` workflow
- [ ] Findings comment posting

### Phase 5 — Calibration
- [ ] Run pipeline against known-PoC targets
- [ ] Tune confidence tier thresholds
- [ ] Validate turn-at-first-crash tracking

---

## Notes

- Triage agent never edits the issue body — all output (handoff YAML, discard rationale) goes into comments. Issue body is the ingest record; comments are the agent audit trail.
- `cve-triage.yml` does not use `issues: labeled`. GitHub blocks workflows from triggering other workflows via `GITHUB_TOKEN` — label events from `github-actions[bot]` are invisible to Actions. Trigger is `workflow_run` (primary) + `schedule` (safety net). Triage drain queries for open `candidate` issues without an outcome label and processes them sequentially.
- EPSS and GHSA data are pre-fetched at ingest and present in the issue body. The triage agent reads them from context — no EPSS or GHSA tool needed on the agent.
- Confidence is a self-reported qualitative tier (`high`/`medium`/`low`), not a numeric float. Numeric thresholds in `settings.py` are reserved for future calibration.
- ADK init: `LiteLlm(model="anthropic/claude-3-haiku-20240307")`, env `GOOGLE_GENAI_USE_VERTEXAI=FALSE`. Versions: `google-adk==1.28.0`, `litellm==1.82.6`.
- Lacuna YAML extraction: find comment by author `github-actions[bot]`, extract first ` ```yaml ` fenced code block via regex.
- `get_issue_body()` added to `scripts/issues.py` (GitHub Issues glue file) rather than a dedicated module.
