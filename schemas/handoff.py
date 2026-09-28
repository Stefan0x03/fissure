"""
Pydantic model for the Fissure handoff YAML schema.

This is the critical interface between the triage agent and Lacuna.
Lacuna consumes all top-level fields; the nested `fissure:` block is
Fissure-only metadata used for research tracking and confidence calibration.
"""

import re
from typing import Literal, Optional
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, field_validator

# Lacuna uses `name` as a directory under its workspace (and rmtree()s it), so
# it must be a single safe path component.
_SAFE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*")


class SourceSpec(BaseModel):
    # "local" is intentionally absent: handoffs are LLM-authored from untrusted
    # content and must never point Lacuna at a path on the runner host.
    type: Literal["git", "tarball"]
    url: str
    ref: str

    @field_validator("url")
    @classmethod
    def _url_is_http(cls, v: str) -> str:
        # Rules out file://, ssh, git ext:: transports, and "-"-prefixed values
        # that git would parse as options.
        parsed = urlparse(v)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("source.url must be an http(s) URL")
        return v

    @field_validator("ref")
    @classmethod
    def _ref_not_option(cls, v: str) -> str:
        if v.startswith("-"):
            raise ValueError("source.ref must not start with '-'")
        return v


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


class LacunaTarget(BaseModel):
    """Block 1 of the triage comment: the Lacuna target spec on its own."""

    name: str
    version: str
    # Additional languages (Rust, Go, …) are tracked as feature requests
    # in the Lacuna repo; only c/cpp are currently supported.
    language: Literal["c", "cpp"]
    source: SourceSpec
    description: str
    attack_surface_hint: str
    build_hint: str

    @field_validator("name")
    @classmethod
    def _name_is_path_safe(cls, v: str) -> str:
        if not _SAFE_NAME_RE.fullmatch(v):
            raise ValueError("name must be a single path component: [A-Za-z0-9._+-], no leading dot")
        return v

    @classmethod
    def from_yaml(cls, text: str) -> "LacunaTarget":
        """
        Parse a raw YAML string into a LacunaTarget instance.

        Every target-spec field is a string, so scalars are loaded as strings
        (BaseLoader): an unquoted ``version: 1.22`` must validate, not be
        rejected as a float.
        """
        return cls.model_validate(yaml.load(text, Loader=yaml.BaseLoader))


class HandoffYAML(LacunaTarget):
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
