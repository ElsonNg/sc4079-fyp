"""Advisory and source metadata, independent of corpus and pipeline code."""

from pydantic import BaseModel, Field


class CWE(BaseModel):
    cwe_id: str
    name: str


class AdvisoryIdentity(BaseModel):
    ghsa_id: str
    cve_id: str | None = None
    cwes: list[CWE] = Field(default_factory=list)
    severity: str = "unknown"


class AdvisoryDetails(AdvisoryIdentity):
    advisory_title: str = ""
    advisory_description: str = ""
    advisory_url: str = ""
    advisory_references: list[str] = Field(default_factory=list)


class AdvisoryAlias(AdvisoryDetails):
    """One advisory/package label attached to a shared code-change lineage."""

    osv_id: str | None = None
    package_name: str | None = None
    ecosystem: str | None = None
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)


class PackageAdvisory(AdvisoryAlias):
    package_name: str
    ecosystem: str = "npm"


class CorpusAdvisory(PackageAdvisory):
    ecosystem: str


class SourceLocation(BaseModel):
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
    source_language: str = "javascript"


class SourceReference(SourceLocation):
    repo: str
