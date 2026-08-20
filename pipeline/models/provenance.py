"""Canonical provenance-lineage and advisory-alias contracts."""

from pydantic import BaseModel, Field

from corpus.models.github import CWE


class AdvisoryAlias(BaseModel):
    """One advisory/package label attached to a shared code-change lineage."""

    ghsa_id: str
    cve_id: str | None = None
    osv_id: str | None = None
    advisory_title: str = ""
    advisory_description: str = ""
    advisory_url: str = ""
    advisory_references: list[str] = Field(default_factory=list)
    cwes: list[CWE] = Field(default_factory=list)
    severity: str = "unknown"
    package_name: str | None = None
    ecosystem: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)


class FixBoundaryReference(BaseModel):
    """One concrete vulnerable-to-patched transition within a code family."""

    fix_boundary_id: str
    fix_commit_sha: str
    vulnerable_source_sha256: str
    patched_source_sha256: str
    advisories: list[AdvisoryAlias] = Field(default_factory=list)
