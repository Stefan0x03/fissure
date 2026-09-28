"""
Unit tests for scripts/lacuna_runner.py extract (handoff validation).

Comment listing is patched — no live requests.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from scripts.lacuna_runner import extract

_TARGET = """\
name: {name}
version: 1.2.3
language: c
source:
  type: {type}
  url: {url}
  ref: v1.2.3
description: A test target
attack_surface_hint: Heap overflow in foo_parse()
build_hint: make
"""

_METADATA = """\
fissure:
  cve_id: CVE-2024-99999
  schema_version: "1"
"""


def _comment(*blocks: str, login: str = "github-actions[bot]") -> dict:
    body = "Triage assessment\n\n" + "\n".join(f"```yaml\n{b}```\n" for b in blocks)
    return {"user": {"login": login}, "body": body}


def _target(name="libfoo", type="git", url="https://github.com/example/libfoo") -> str:
    return _TARGET.format(name=name, type=type, url=url)


def _extract(comments: list[dict], tmp_path) -> "Path":
    out = tmp_path / "handoff.yaml"
    with patch("scripts.lacuna_runner._list_comments", return_value=comments):
        extract(1, "owner/repo", out, token="tok")
    return out


def test_valid_block_written(tmp_path):
    block = _target()
    out = _extract([_comment(block, _METADATA)], tmp_path)
    assert out.read_text() == block


@pytest.mark.parametrize("block", [
    _target(type="local"),
    _target(url="file:///home/runner/.ssh"),
    _target(url="--upload-pack=touch /tmp/pwned"),
    _target(name="../../home/runner"),
    _METADATA,  # metadata block emitted first by mistake
    "",
])
def test_invalid_block_rejected_and_not_written(block, tmp_path):
    with pytest.raises(SystemExit) as exc:
        _extract([_comment(block, _METADATA)], tmp_path)
    assert exc.value.code == 1
    assert not (tmp_path / "handoff.yaml").exists()


def test_non_bot_comment_ignored(tmp_path):
    with pytest.raises(SystemExit):
        _extract([_comment(_target(), login="attacker")], tmp_path)
