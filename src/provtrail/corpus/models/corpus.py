from pydantic import BaseModel, Field

from provtrail.shared.metadata import CorpusAdvisory, SourceReference
from provtrail.shared.records import MetadataRecord


class DiagnosticLine(BaseModel):
    kind: str  # "removed" | "added"
    vulnerable_line: int | None = None
    patched_line: int | None = None
    text: str


class CorpusEntry(MetadataRecord):
    advisory: CorpusAdvisory
    origin: SourceReference

    vulnerable_function: str
    patched_function: str
    diagnostic_lines: list[DiagnosticLine] = []
    osv_confirmed: bool = False
    patch_hunk: str = ""
    native_hash: str = ""
    normalized_hash: str = ""
    ast_hash: str = ""
    release_boundary: dict = Field(default_factory=dict)
    high_impact: bool = False
    impact_metadata: dict = Field(default_factory=dict)
    evidence_label: str = "strictly evidence-attributed vulnerable origin"
    primary_evidence: bool = True
    advisory_aliases: list[dict] = Field(default_factory=list)


class AttritionReport(BaseModel):
    package: str = "all npm packages"
    advisories_found: int = 0
    advisories_wrong_package: int = 0
    advisories_withdrawn: int = 0
    advisories_processed: int = 0
    fix_commit_refs_found: int = 0
    advisories_without_commit_refs: int = 0
    fix_commits_rejected_unclean: int = 0
    rejection_reasons: dict[str, int] = {}
    fix_commits_processed: int = 0
    osv_confirmed_count: int = 0
    osv_unconfirmed_count: int = 0
    function_pairs_skipped_identical: int = 0
    function_pairs_extracted: int = 0
    corpus_entries_final: int = 0
    quarantined: int = 0
    duplicates_removed: int = 0
    high_impact_entries: int = 0


class QuarantineRecord(BaseModel):
    reason_code: str
    ghsa_id: str
    package_name: str = ""
    repo: str = ""
    fix_commit_sha: str = ""
    file_path: str = ""
    detail: str = ""


class BuildResult(BaseModel):
    entries: list[CorpusEntry] = Field(default_factory=list)
    reports: list[AttritionReport] = Field(default_factory=list)
    quarantine: list[QuarantineRecord] = Field(default_factory=list)
    source_manifest: dict = Field(default_factory=dict)
