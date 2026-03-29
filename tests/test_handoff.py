"""
Unit tests for schemas.handoff.HandoffYAML.

Tests cover:
- Required field enforcement
- Enum/literal validation for language, source.type, confidence_tier, schema_version
- from_yaml() / to_yaml() round-trip
"""

import pytest
from pydantic import ValidationError

from schemas.handoff import FissureMetadata, HandoffYAML, SourceSpec

# ---------------------------------------------------------------------------
# Minimal valid fixture used across multiple tests
# ---------------------------------------------------------------------------

MINIMAL_VALID = {
    "name": "libfoo",
    "version": "1.2.3",
    "language": "c",
    "source": {
        "type": "git",
        "url": "https://github.com/example/libfoo",
        "ref": "v1.2.3",
    },
    "description": "A test target",
    "attack_surface_hint": "Heap overflow in foo_parse()",
    "build_hint": "make CFLAGS=-fsanitize=address",
    "fissure": {
        "cve_id": "CVE-2024-99999",
        "epss_score": 0.5,
        "epss_percentile": 0.8,
        "confidence_tier": "high",
        "schema_version": "1",
    },
}


def _valid(**overrides) -> dict:
    """Return MINIMAL_VALID with top-level keys overridden."""
    return {**MINIMAL_VALID, **overrides}


def _valid_fissure(**overrides) -> dict:
    """Return MINIMAL_VALID with fissure sub-keys overridden."""
    fissure = {**MINIMAL_VALID["fissure"], **overrides}
    return {**MINIMAL_VALID, "fissure": fissure}


def _valid_source(**overrides) -> dict:
    """Return MINIMAL_VALID with source sub-keys overridden."""
    source = {**MINIMAL_VALID["source"], **overrides}
    return {**MINIMAL_VALID, "source": source}


# ---------------------------------------------------------------------------
# Required field enforcement
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("missing_field", [
    "name", "version", "language", "source", "description",
    "attack_surface_hint", "build_hint", "fissure",
])
def test_missing_top_level_field_raises(missing_field):
    data = {k: v for k, v in MINIMAL_VALID.items() if k != missing_field}
    with pytest.raises(ValidationError):
        HandoffYAML.model_validate(data)


@pytest.mark.parametrize("missing_field", ["type", "url", "ref"])
def test_missing_source_field_raises(missing_field):
    source = {k: v for k, v in MINIMAL_VALID["source"].items() if k != missing_field}
    data = {**MINIMAL_VALID, "source": source}
    with pytest.raises(ValidationError):
        HandoffYAML.model_validate(data)


@pytest.mark.parametrize("missing_field", [
    "cve_id", "epss_score", "epss_percentile", "confidence_tier", "schema_version",
])
def test_missing_fissure_field_raises(missing_field):
    fissure = {k: v for k, v in MINIMAL_VALID["fissure"].items() if k != missing_field}
    data = {**MINIMAL_VALID, "fissure": fissure}
    with pytest.raises(ValidationError):
        HandoffYAML.model_validate(data)


# ---------------------------------------------------------------------------
# Enum / Literal validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_lang", ["rust", "go", "python", "cpp2", "C", ""])
def test_invalid_language_raises(bad_lang):
    with pytest.raises(ValidationError):
        HandoffYAML.model_validate(_valid(language=bad_lang))


@pytest.mark.parametrize("good_lang", ["c", "cpp"])
def test_valid_language_accepted(good_lang):
    obj = HandoffYAML.model_validate(_valid(language=good_lang))
    assert obj.language == good_lang


@pytest.mark.parametrize("bad_type", ["svn", "zip", "docker", ""])
def test_invalid_source_type_raises(bad_type):
    with pytest.raises(ValidationError):
        HandoffYAML.model_validate(_valid_source(type=bad_type))


@pytest.mark.parametrize("good_type", ["git", "tarball", "local"])
def test_valid_source_type_accepted(good_type):
    obj = HandoffYAML.model_validate(_valid_source(type=good_type))
    assert obj.source.type == good_type


@pytest.mark.parametrize("bad_tier", ["low", "critical", "HIGH", ""])
def test_invalid_confidence_tier_raises(bad_tier):
    with pytest.raises(ValidationError):
        HandoffYAML.model_validate(_valid_fissure(confidence_tier=bad_tier))


@pytest.mark.parametrize("good_tier", ["high", "medium"])
def test_valid_confidence_tier_accepted(good_tier):
    obj = HandoffYAML.model_validate(_valid_fissure(confidence_tier=good_tier))
    assert obj.fissure.confidence_tier == good_tier


@pytest.mark.parametrize("bad_version", ["2", "0", "1.0", "v1"])
def test_invalid_schema_version_raises(bad_version):
    with pytest.raises(ValidationError):
        HandoffYAML.model_validate(_valid_fissure(schema_version=bad_version))


def test_valid_schema_version_accepted():
    obj = HandoffYAML.model_validate(MINIMAL_VALID)
    assert obj.fissure.schema_version == "1"


# ---------------------------------------------------------------------------
# Optional fields
# ---------------------------------------------------------------------------

def test_optional_ghsa_id_defaults_to_none():
    obj = HandoffYAML.model_validate(MINIMAL_VALID)
    assert obj.fissure.ghsa_id is None


def test_optional_poc_url_defaults_to_none():
    obj = HandoffYAML.model_validate(MINIMAL_VALID)
    assert obj.fissure.poc_url is None


def test_optional_fields_accept_string_values():
    obj = HandoffYAML.model_validate(_valid_fissure(
        ghsa_id="GHSA-xxxx-xxxx-xxxx",
        poc_url="https://example.com/poc",
    ))
    assert obj.fissure.ghsa_id == "GHSA-xxxx-xxxx-xxxx"
    assert obj.fissure.poc_url == "https://example.com/poc"


# ---------------------------------------------------------------------------
# from_yaml / to_yaml round-trip
# ---------------------------------------------------------------------------

ROUND_TRIP_YAML = """\
name: libbar
version: 2.0.0
language: cpp
source:
  type: tarball
  url: https://example.com/libbar-2.0.0.tar.gz
  ref: 2.0.0
description: A multiline test target
attack_surface_hint: |
  Heap overflow in bar_decode().
  Triggered by crafted input > 4096 bytes.
build_hint: |
  ./configure CFLAGS="-fsanitize=address"
  make
fissure:
  cve_id: CVE-2024-12345
  epss_score: 0.123
  epss_percentile: 0.456
  confidence_tier: medium
  ghsa_id: GHSA-aaaa-bbbb-cccc
  poc_url: https://example.com/poc
  schema_version: '1'
"""


def test_from_yaml_parses_correctly():
    obj = HandoffYAML.from_yaml(ROUND_TRIP_YAML)
    assert obj.name == "libbar"
    assert obj.language == "cpp"
    assert obj.source.type == "tarball"
    assert obj.fissure.cve_id == "CVE-2024-12345"
    assert obj.fissure.ghsa_id == "GHSA-aaaa-bbbb-cccc"
    assert obj.fissure.schema_version == "1"


def test_to_yaml_round_trip():
    original = HandoffYAML.from_yaml(ROUND_TRIP_YAML)
    serialised = original.to_yaml()
    restored = HandoffYAML.from_yaml(serialised)

    assert restored.name == original.name
    assert restored.version == original.version
    assert restored.language == original.language
    assert restored.source.type == original.source.type
    assert restored.source.url == original.source.url
    assert restored.source.ref == original.source.ref
    assert restored.description == original.description
    assert restored.attack_surface_hint == original.attack_surface_hint
    assert restored.build_hint == original.build_hint
    assert restored.fissure.cve_id == original.fissure.cve_id
    assert restored.fissure.epss_score == original.fissure.epss_score
    assert restored.fissure.epss_percentile == original.fissure.epss_percentile
    assert restored.fissure.confidence_tier == original.fissure.confidence_tier
    assert restored.fissure.ghsa_id == original.fissure.ghsa_id
    assert restored.fissure.poc_url == original.fissure.poc_url
    assert restored.fissure.schema_version == original.fissure.schema_version


def test_to_yaml_uses_block_scalar_for_multiline_fields():
    obj = HandoffYAML.from_yaml(ROUND_TRIP_YAML)
    serialised = obj.to_yaml()
    # Block scalar indicator must appear for the multiline hint fields
    assert "attack_surface_hint: |" in serialised
    assert "build_hint: |" in serialised


def test_to_yaml_single_line_not_block_scalar():
    data = _valid(
        attack_surface_hint="Single line hint",
        build_hint="make",
    )
    obj = HandoffYAML.model_validate(data)
    serialised = obj.to_yaml()
    # Single-line strings should NOT use block scalar style
    assert "attack_surface_hint: |" not in serialised
    assert "build_hint: |" not in serialised
