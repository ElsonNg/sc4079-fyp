"""Stage 7 -- verification mechanism. Turns a retrieval-shortlisted candidate's
whole-function similarity into a targeted verdict by reading hierarchical-alignment
quality specifically at the lines a fix commit touched (CorpusEntry.diagnostic_lines,
already computed once per entry at corpus-build time by
corpus.controller.extraction.compute_diagnostic_lines), then comparing that reading
against both the vulnerable and the patched side of the same corpus entry.

Candidate is always align_functions' side "a"; the corpus reference (vulnerable_function
or patched_function) is always side "b" -- DiagnosticLine.vulnerable_line/.patched_line
are raw line numbers into those same corpus strings, so this is the convention that
lets find_op_at_line(alignment, "b", line) read them off directly.
"""

from typing import Literal

from corpus.models.corpus import CorpusEntry, DiagnosticLine
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.hierarchy import EmbeddingCache, align_functions, find_op_at_line
from pipeline.models.hierarchy import HierarchicalAlignment
from pipeline.models.retrieval import RetrievalMatch
from pipeline.models.verification import DiagnosticLineScore, VerificationResult

IdentityKey = tuple[str, str, str, str | None]

# Placeholder pending real calibration against the corpus in module 11 (evaluation
# suite) -- unlike DEFAULT_GAP_PENALTY/DEFAULT_SPAN_MERGE_PENALTY, not yet backed by a
# measured probe set. Compared directly against verification_score, which is a
# difference of two shifted-score (cosine - match_midpoint) means, so 0 is already the
# same "unrelated/related" boundary those constants use.
#
# Known complication for that future calibration, not fixed here: sim_vulnerable and
# sim_patched are NOT always the same kind of number. When _sim_at_diagnostic falls
# back (empty diagnostic-line list on that side -- a pure insertion/deletion fix, which
# is common: see the module-7 real-corpus validation note in project memory for the
# measured fraction), the fallback side reports a whole-function normalized_score,
# while the non-fallback side reports a mean of per-op DP scores at specific lines --
# two different scales compared directly. It happens to give the right sign on every
# fixture checked so far (both synthetic and a real-corpus sample), but a single global
# margin cannot be cleanly calibrated across entries that mix fallback and non-fallback
# sides with entries that don't. Whoever calibrates this in module 11 should stratify
# by (vulnerable_fallback_used, patched_fallback_used) rather than pooling everything.
DEFAULT_VERIFICATION_MARGIN = 0.1


def _entry_key(entry: CorpusEntry) -> IdentityKey:
    return (entry.ghsa_id, entry.fix_commit_sha, entry.file_path, entry.function_name)


def _match_key(match: RetrievalMatch) -> IdentityKey:
    return (match.ghsa_id, match.fix_commit_sha, match.file_path, match.function_name)


def index_corpus_entries(entries: list[CorpusEntry]) -> dict[IdentityKey, CorpusEntry]:
    """Keyed identically to corpus.controller.store's own UNIQUE constraint.
    RetrievalMatch (Stage 2's output) carries only that identity tuple, not the
    function text -- this is how Stage 7 gets back to
    CorpusEntry.vulnerable_function/.patched_function for a shortlisted candidate."""
    return {_entry_key(entry): entry for entry in entries}


def _sim_at_diagnostic(
    alignment: HierarchicalAlignment, side: Literal["a", "b"], lines: list[int]
) -> tuple[float, bool]:
    """Mean HierarchicalOp.score at `lines` on `side` of `alignment`, skipping any line
    whose lookup misses rather than counting it as 0. Falls back to
    `alignment.normalized_score` (the whole-comparison score) -- and reports that via
    the returned bool -- when `lines` is empty (a pure insertion has no
    vulnerable-side diagnostic lines, a pure deletion has no patched-side ones) or when
    every lookup misses.

    The mean is over diagnostic LINES, not over ops -- if several consecutive
    diagnostic lines resolve to the same op (e.g. a multi-line container that gapped or
    matched as a single unit, as every line of a small added guard clause typically
    does), that op's score is counted once per line it covers, not once overall. This
    weights a verdict toward whichever side's diagnostic change spans more lines;
    undocumented in the build plan and not separately tested, since neither the flat
    nor the mean-of-ops alternative was clearly the one the build plan intended."""
    scores = [
        _verification_op_score(op)
        for line in lines
        if (op := find_op_at_line(alignment, side, line)) is not None
    ]
    if not scores:
        return alignment.normalized_score, True
    return sum(scores) / len(scores), False


def _bucket(score: float, margin: float) -> Literal["flagged", "cleared", "manual_review"]:
    if score >= margin:
        return "flagged"
    if score <= -margin:
        return "cleared"
    return "manual_review"


def _verification_op_score(op) -> float:
    """Use an identity score for exact normalized op text.

    Alignment scores are shifted by the model's unrelated/related midpoint, so an
    exact candidate/reference match is only about 0.54 for the default model. That
    baseline is not an identity signal and becomes biased when the vulnerable and
    patched sides have different numbers of diagnostic lines. Non-identical matches
    and gaps retain their model/DP score.
    """
    if op.a_lines and op.b_lines and op.a_lines == op.b_lines:
        return 1.0
    return op.score


def _diagnostic_scores(
    diagnostic_lines: list[DiagnosticLine],
    align_vs_vulnerable: HierarchicalAlignment,
    align_vs_patched: HierarchicalAlignment,
) -> list[DiagnosticLineScore]:
    scores = []
    for d in diagnostic_lines:
        vulnerable_score = None
        if d.vulnerable_line is not None:
            op = find_op_at_line(align_vs_vulnerable, "b", d.vulnerable_line)
            vulnerable_score = _verification_op_score(op) if op is not None else None
        patched_score = None
        if d.patched_line is not None:
            op = find_op_at_line(align_vs_patched, "b", d.patched_line)
            patched_score = _verification_op_score(op) if op is not None else None
        scores.append(
            DiagnosticLineScore(
                kind=d.kind,
                vulnerable_line=d.vulnerable_line,
                patched_line=d.patched_line,
                text=d.text,
                vulnerable_score=vulnerable_score,
                patched_score=patched_score,
            )
        )
    return scores


def verify_candidate(
    candidate_source: str,
    entry: CorpusEntry,
    cache: EmbeddingCache,
    model_id: str = DEFAULT_MODEL_ID,
    margin: float = DEFAULT_VERIFICATION_MARGIN,
) -> VerificationResult:
    """Runs align_functions(candidate, vulnerable) and align_functions(candidate,
    patched) -- candidate always side "a" -- then reads alignment quality specifically
    at entry.diagnostic_lines on each side. `cache` is caller-owned: pass the SAME
    instance across every call for one candidate (including across every shortlisted
    match for that candidate via `verify()`) for the embedding reuse EmbeddingCache
    was built for."""
    align_vs_vulnerable = align_functions(candidate_source, entry.vulnerable_function, cache, model_id=model_id)
    align_vs_patched = align_functions(candidate_source, entry.patched_function, cache, model_id=model_id)

    vulnerable_lines = [d.vulnerable_line for d in entry.diagnostic_lines if d.vulnerable_line is not None]
    patched_lines = [d.patched_line for d in entry.diagnostic_lines if d.patched_line is not None]

    sim_vulnerable, vulnerable_fallback_used = _sim_at_diagnostic(align_vs_vulnerable, "b", vulnerable_lines)
    sim_patched, patched_fallback_used = _sim_at_diagnostic(align_vs_patched, "b", patched_lines)
    verification_score = sim_vulnerable - sim_patched

    return VerificationResult(
        ghsa_id=entry.ghsa_id,
        cve_id=entry.cve_id,
        cwes=entry.cwes,
        severity=entry.severity,
        repo=entry.repo,
        fix_commit_sha=entry.fix_commit_sha,
        file_path=entry.file_path,
        function_name=entry.function_name,
        verification_score=verification_score,
        status=_bucket(verification_score, margin),
        sim_vulnerable=sim_vulnerable,
        sim_patched=sim_patched,
        vulnerable_fallback_used=vulnerable_fallback_used,
        patched_fallback_used=patched_fallback_used,
        diagnostic_scores=_diagnostic_scores(entry.diagnostic_lines, align_vs_vulnerable, align_vs_patched),
    )


def verify(
    candidate_source: str,
    matches: list[RetrievalMatch],
    corpus_index: dict[IdentityKey, CorpusEntry],
    model_id: str = DEFAULT_MODEL_ID,
    margin: float = DEFAULT_VERIFICATION_MARGIN,
) -> list[VerificationResult]:
    """One candidate against its own retrieval shortlist -- owns a single
    EmbeddingCache shared across every match, since the candidate's own node texts
    (and any corpus text shared between matches) don't change between them."""
    cache = EmbeddingCache()
    return [
        verify_candidate(candidate_source, corpus_index[_match_key(match)], cache, model_id=model_id, margin=margin)
        for match in matches
    ]
