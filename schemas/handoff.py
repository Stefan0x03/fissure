"""
Pydantic model for the Fissure handoff YAML schema.

This is the critical interface between the triage agent and Lacuna.
Lacuna consumes all top-level fields; the nested `fissure:` block is
Fissure-only metadata used for research tracking and confidence calibration.
"""

from typing import Literal, Optional

import yaml
from pydantic import BaseModel


class SourceSpec(BaseModel):
    # "local" is for development/testing against a pre-checked-out tree.
    type: Literal["git", "tarball", "local"]
    url: str
    ref: str


class FissureMetadata(BaseModel):
    cve_id: str
    epss_score: float
    epss_percentile: float
    # Additional languages (Rust, Go, …) are tracked as feature requests
    # in the Lacuna repo; only c/cpp are currently supported.
    confidence_tier: Literal["high", "medium"]
    ghsa_id: Optional[str] = None
    poc_url: Optional[str] = None
    schema_version: Literal["1"]


class HandoffYAML(BaseModel):
    name: str
    version: str
    # Additional languages (Rust, Go, …) are tracked as feature requests
    # in the Lacuna repo; only c/cpp are currently supported.
    language: Literal["c", "cpp"]
    source: SourceSpec
    description: str
    attack_surface_hint: str
    build_hint: str
    fissure: FissureMetadata

    @classmethod
    def from_yaml(cls, text: str) -> "HandoffYAML":
        """Parse a raw YAML string into a HandoffYAML instance."""
        data = yaml.safe_load(text)
        return cls.model_validate(data)

    def to_yaml(self) -> str:
        """
        Serialize to a YAML string.

        ``attack_surface_hint`` and ``build_hint`` are emitted with block
        scalar style (``|``) so multiline content stays human-readable in
        issue bodies and diffs.
        """
        data = self.model_dump()

        # PyYAML represents nested models as plain dicts after model_dump(),
        # which is exactly what safe_dump expects.  We customise the Dumper
        # only to force block scalars for the two multiline hint fields.
        class _BlockStyleDumper(yaml.Dumper):
            pass

        def _str_representer(dumper: yaml.Dumper, value: str) -> yaml.ScalarNode:
            if "\n" in value:
                return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|")
            return dumper.represent_scalar("tag:yaml.org,2002:str", value)

        _BlockStyleDumper.add_representer(str, _str_representer)

        return yaml.dump(
            data,
            Dumper=_BlockStyleDumper,
            default_flow_style=False,
            allow_unicode=True,
            sort_keys=False,
        )
