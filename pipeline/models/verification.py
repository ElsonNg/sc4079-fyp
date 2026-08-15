from typing import Literal

from pydantic import BaseModel

from corpus.models.github import CWE


class DiagnosticLineScore(BaseModel):
    """One CorpusEntry.diagnostic_lines entry, plus how well a candidate's alignment
    read at that position on each side it applies to -- None on a side the diagnostic
    line doesn't touch (a "removed" line has no patched_line, and vice versa), and also
    None if the position lookup itself missed (shouldn't happen for a well-formed
    corpus entry, but not assumed away)."""

    kind: str  # "removed" | "added", mirrors DiagnosticLine.kind
    vulnerable_line: int | None = None
    patched_line: int | None = None
    text: str
    vulnerable_score: float | None = None
    patched_score: float | None = None


class VerificationResult(BaseModel):
    """Stage 7's output for one (candidate, shortlisted corpus entry) pair. Metadata
    fields mirror RetrievalMatch/HashMatch's own established shape."""

    ghsa_id: str
    cve_id: str | None = None
    cwes: list[CWE] = []
    severity: str = "unknown"
    repo: str
    fix_commit_sha: str
    file_path: str
    function_name: str | None = None
    verification_score: float
    status: Literal["flagged", "cleared", "manual_review"]
    sim_vulnerable: float
    sim_patched: float
    vulnerable_fallback_used: bool
    patched_fallback_used: bool
    diagnostic_scores: list[DiagnosticLineScore] = []
