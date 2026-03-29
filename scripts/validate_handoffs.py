#!/usr/bin/env python3
"""
Validate all hand-authored handoff YAMLs against the Pydantic schema.

Exits with code 0 if all files pass, non-zero if any file fails.
Usable in CI as a schema regression check.

Usage:
    python scripts/validate_handoffs.py
"""

import sys
from pathlib import Path

# Ensure the repo root is on sys.path so `schemas` is importable when the
# script is invoked directly (e.g. python scripts/validate_handoffs.py).
_REPO_ROOT = Path(__file__).parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pydantic import ValidationError

from schemas.handoff import HandoffYAML

SCHEMAS_DIR = Path(__file__).parent.parent / "schemas"
HANDOFF_GLOB = "handoff_*.yaml"


def main() -> int:
    files = sorted(SCHEMAS_DIR.glob(HANDOFF_GLOB))
    if not files:
        print(f"No files matched {SCHEMAS_DIR / HANDOFF_GLOB}", file=sys.stderr)
        return 1

    failures = 0
    for path in files:
        try:
            HandoffYAML.from_yaml(path.read_text())
            print(f"OK  {path.name}")
        except ValidationError as exc:
            print(f"FAIL {path.name}")
            print(exc, file=sys.stderr)
            failures += 1
        except Exception as exc:  # noqa: BLE001 — surface YAML parse errors too
            print(f"FAIL {path.name} (parse error)")
            print(f"  {exc}", file=sys.stderr)
            failures += 1

    print(f"\n{len(files) - failures}/{len(files)} passed")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
