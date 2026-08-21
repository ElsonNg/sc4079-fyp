from typing import Literal

from pydantic import BaseModel, Field

from corpus.models.github import CWE
from pipeline.models.provenance import AdvisoryAlias


class FunctionFingerprint(BaseModel):
    hashable: bool
    exact_hash: str | None = None
    exact_length: int
    abstracted_hash: str | None = None
    abstracted_length: int


class HashMatch(BaseModel):
    lineage_id: str | None = None
    fix_boundary_id: str | None = None
    advisories: list[AdvisoryAlias] = Field(default_factory=list)
    ghsa_id: str
    cve_id: str | None = None
    osv_id: str | None = None
    advisory_title: str = ""
    advisory_description: str = ""
    advisory_url: str = ""
    advisory_references: list[str] = []
    side: Literal["vulnerable", "patched"]
    match_type: Literal["exact", "abstracted", "type_erased"]
    cwes: list[CWE] = []
    severity: str = "unknown"
    package_name: str | None = None
    ecosystem: str | None = None
    affected_versions: list[str] = []
    fixed_versions: list[str] = []
    repo: str
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
    source_language: str = "javascript"
    cross_language: bool = False
