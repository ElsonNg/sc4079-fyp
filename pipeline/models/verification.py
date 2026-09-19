from typing import Literal

from pydantic import BaseModel

from shared.metadata import AdvisoryIdentity, SourceReference
from shared.records import MetadataRecord


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


class VerificationResult(MetadataRecord):
    """Diagnostic-line verification of a shortlisted corpus entry."""

    record_exclusions = {"origin": {"source_language"}}

    advisory: AdvisoryIdentity
    origin: SourceReference

    verification_score: float
    status: Literal["flagged", "cleared", "manual_review"]
    sim_vulnerable: float
    sim_patched: float
    vulnerable_fallback_used: bool
    patched_fallback_used: bool
    diagnostic_scores: list[DiagnosticLineScore] = []
