from pydantic import BaseModel

from corpus.models.github import CWE


class DiagnosticLine(BaseModel):
    kind: str  # "removed" | "added"
    vulnerable_line: int | None = None
    patched_line: int | None = None
    text: str


class CorpusEntry(BaseModel):
    ghsa_id: str
    cve_id: str | None = None
    osv_id: str | None = None
    cwes: list[CWE] = []
    severity: str = "unknown"
    package_name: str
    ecosystem: str
    repo: str
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
    vulnerable_function: str
    patched_function: str
    diagnostic_lines: list[DiagnosticLine] = []
    affected_versions: list[str] = []
    fixed_versions: list[str] = []
    osv_confirmed: bool = False


class AttritionReport(BaseModel):
    package: str
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
