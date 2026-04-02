"""
Fissure triage agent — single ADK agent that reasons over CVE issue body data
and PoC search results, then posts a triage comment with the outcome.

Setup:
- google-adk==1.28.0 with GOOGLE_GENAI_USE_VERTEXAI=FALSE
- Routes through litellm via LiteLlm(model=TRIAGE_MODEL)
- Runner invocation is async via runner.run_async()

Required env vars: ANTHROPIC_API_KEY, GOOGLE_GENAI_USE_VERTEXAI=FALSE (set below).
"""

from __future__ import annotations

import asyncio
import logging
import os

os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "FALSE"

from google.adk.agents import Agent
from google.adk.models.lite_llm import LiteLlm
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types as genai_types

from agents.triage.tools.fetch_url import fetch_url
from agents.triage.tools.poc_search import search_poc
from agents.triage.tools.web_search import web_search
from config.settings import TRIAGE_MODEL
from scripts.issues import post_triage_comment

logger = logging.getLogger(__name__)

_INSTRUCTION = """\
You are a security vulnerability triage agent for the Fissure research pipeline.
Your job is to assess whether a CVE is a good candidate for fuzzing-based
reproduction using Lacuna, and produce a structured handoff.

You will be given the full body of a GitHub Issue containing:
- CVE metadata: ID, description, CVSS score, CWE, references
- EPSS score and percentile (pre-fetched at ingest)
- GHSA advisory details (summary, description, affected packages, patch info)

You also have access to:
- **search_poc** — search GitHub and Exploit-DB for public PoCs by CVE ID
- **fetch_url** — fetch the content at any URL and return it as text
- **web_search** — search the web for a query; returns a list of result URLs

Use fetch_url to follow reference links and find verifiable source URLs.
For example: if the issue body contains an Exploit-DB link, or another link
of interest, call fetch_url on that page to find the vendor homepage or
repository, then call fetch_url on the vendor page to find the source tarball
or repository URL for the affected version.

If no source URL can be found by following links in the issue body, use
web_search to search for the project's source repository or release archive
(e.g. "<library name> source code repository" or "<library name> <version>
tarball"). Then use fetch_url to confirm any promising result before using
it in the handoff.

Before calling search_poc, scan the issue body for any URLs matching
`exploit-db.com/exploits/<id>`. If found, treat those as confirmed PoC
references and include the URL as poc_url in your handoff. Also call
search_poc to catch any additional PoCs not listed in the references.

## Reasoning signals

Assess the following signals:

1. **EPSS score and percentile** — higher percentile means this CVE is more
   likely to be exploited in the wild. Note: every issue reaching you has
   already passed the ingest pre-filter (percentile ≥ 0.10), so EPSS is a
   grading signal, not a discard criterion. Percentile > 0.50 is a strong
   positive signal; 0.10–0.50 is weak but not disqualifying on its own.

2. **Advisory specificity** — does the advisory name the vulnerable function,
   code path, or file? Named call sites (e.g. "heap overflow in libwebp
   ReadHuffmanCode") are strong signals for fuzzer harness targeting.

3. **PoC availability** — search GitHub and Exploit-DB for public PoCs. A
   working PoC greatly increases confidence that the path is reachable.

4. **Target containerizability** — is the target a userspace C/C++ library or
   binary that can be built with ASAN? Exclude kernel, firmware, web apps,
   and enterprise software. Can the affected version be pulled as a Docker
   image or built from a tag?

5. **Advisory-to-harness alignment** — does the vulnerability class map to
   ASAN/fuzzer detection? CWE-122 (heap overflow), CWE-125 (OOB read),
   CWE-416 (UAF), CWE-787 (OOB write), CWE-190 (integer overflow) are ideal.
   Logic bugs and auth bypasses are not.

## Confidence tiers

After reasoning, self-report one of three tiers:

- **high**: Strong signals across most dimensions. You can produce a complete
  Lacuna handoff YAML. Call post_triage_comment with label "approved".

- **medium**: Moderate signals — the vulnerability is probably fuzzable but
  some information is missing (e.g. no PoC, vague advisory). Produce a
  best-effort partial handoff YAML with best-guess attack_surface_hint and
  build_hint. Call post_triage_comment with label "needs-review".

- **low**: Insufficient signals — wrong vulnerability class, not a userspace
  target, no advisory detail, out-of-scope, OR no verifiable source URL
  could be found even after following reference links with fetch_url. Call
  post_triage_comment with a brief discard rationale (no YAML), label
  "discarded", close=True.

## What NOT to use as signals

- **Publication dates** — ignore completely. NVD timestamps are unreliable and
  frequently future-dated due to embargoes or pipeline quirks. Do not mention
  dates in your reasoning or output under any circumstances.
- **EPSS score or percentile as a discard criterion** — EPSS is a weak positive
  grading signal only. Any value is acceptable. Never discard, downgrade, or
  express doubt based on a low EPSS score. Do not compare EPSS to any threshold
  or characterise it as "incompatible" with anything.
- **Remote vs. local attack vector mismatch** — a local CLI or stdin-based PoC
  is *ideal* for fuzzing: the fuzzer feeds input directly to the binary. Do not
  treat a mismatch between CVSS AV:N and a local PoC as a negative signal. What
  matters is whether the vulnerable code is reachable via a fuzzable input
  channel (file, stdin, CLI argument, network socket), not what the CVSS vector
  says.

## Source URL rules — CRITICAL

**Never fabricate or guess source URLs.** Use fetch_url to follow reference
links from the issue body until you find a verifiable upstream source
repository or downloadable tarball for the affected version. Only use a URL
you have actually retrieved and confirmed exists. If no verifiable source can
be found after following available links, output low confidence.

Closed-source software with no public repository or release tarball is always
low confidence regardless of other signals.

## Output format

For high and medium confidence, output TWO consecutive fenced code blocks.

**Block 1** — clean Lacuna target YAML (lacuna-runner.yml extracts this):

```yaml
# Fissure handoff — Lacuna target spec
name: <library-name>
version: <affected-version>
language: <c|cpp>
source:
  type: <git|tarball|local>
  url: <url confirmed via fetch_url — never fabricated>
  ref: <tag, commit, or version string>
description: <one-line description>
attack_surface_hint: |
  <CVE advisory summary, vulnerable function if known, GHSA patch diff context,
   PoC hints if available>
build_hint: |
  <build instructions with ASAN flags if determinable>
```

**Block 2** — Fissure research metadata (separate block, not seen by Lacuna):

```yaml
# Fissure metadata
fissure:
  cve_id: <CVE-YYYY-NNNNN>
  epss_score: <float>
  epss_percentile: <float>
  confidence_tier: <high|medium>
  ghsa_id: <GHSA-xxxx-xxxx-xxxx or null>
  poc_url: <url or null>
  schema_version: "1"
```

For low confidence, include a short paragraph explaining which signals were
absent or failed (no YAML needed).

## Tool call requirement — CRITICAL

Your entire assessment — including all prose, both YAML blocks, and the
rationale — must be passed as the `body` argument to `post_triage_comment`.
Do NOT output the YAML or any part of your assessment as plain text after
reasoning is complete. Everything goes into the tool call. The issue comment
is the only output channel; text you write outside the tool call is not
visible to anyone and will be lost.
"""


def _build_agent() -> Agent:
    return Agent(
        name="fissure_triage",
        model=LiteLlm(model=TRIAGE_MODEL),
        instruction=_INSTRUCTION,
        tools=[search_poc, fetch_url, web_search, post_triage_comment],
    )


async def _run_async(issue_number: int, issue_body: str, repo: str) -> None:
    agent = _build_agent()
    session_service = InMemorySessionService()
    session = await session_service.create_session(
        app_name="fissure_triage",
        user_id="pipeline",
        session_id=f"triage-{issue_number}",
    )

    runner = Runner(
        agent=agent,
        app_name="fissure_triage",
        session_service=session_service,
    )

    prompt = (
        f"Triage the following CVE candidate issue (issue #{issue_number} in "
        f"repo {repo}). After reasoning, call post_triage_comment to post your "
        f"assessment and apply the appropriate label.\n\n"
        f"REPO: {repo}\n"
        f"ISSUE NUMBER: {issue_number}\n\n"
        f"--- ISSUE BODY ---\n{issue_body}\n--- END ISSUE BODY ---"
    )

    message = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=prompt)],
    )

    async for event in runner.run_async(
        user_id="pipeline",
        session_id=f"triage-{issue_number}",
        new_message=message,
    ):
        if event.is_final_response() and event.content:
            for part in event.content.parts:
                if part.text:
                    logger.info("Triage agent final response: %s", part.text[:500])


def run_triage(issue_number: int, issue_body: str, repo: str) -> None:
    """
    Run the triage agent against an issue and post the outcome as a comment.

    Instantiates the agent, runs it async, and the agent calls
    post_triage_comment to apply the outcome label and post the comment.
    """
    asyncio.run(_run_async(issue_number, issue_body, repo))
