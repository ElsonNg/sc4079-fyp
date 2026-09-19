import pytest

from corpus.controller.extraction import compute_diagnostic_lines
from corpus.models.corpus import CorpusEntry, DiagnosticLine
from pipeline.controller import hierarchy
from pipeline.controller.hierarchy import EmbeddingCache
from pipeline.controller.verification import (
    DEFAULT_VERIFICATION_MARGIN,
    _bucket,
    _diagnostic_scores,
    _sim_at_diagnostic,
    index_corpus_entries,
    verify,
    verify_candidate,
)
from pipeline.models.hierarchy import HierarchicalAlignment, HierarchicalOp, NodeRange
from pipeline.models.retrieval import RetrievalMatch

# This file mixes fast pure-logic tests (hand-built HierarchicalAlignment trees, no
# model) with slow real-embedding integration tests -- same per-function `slow`
# marker convention as tests/test_alignment.py and tests/test_hierarchy.py.


def _range(start_line: int, end_line: int) -> NodeRange:
    return NodeRange(node_type="statement", start_byte=0, end_byte=0, start_line=start_line, end_line=end_line)


def _alignment(ops: list[HierarchicalOp], normalized_score: float = 0.3) -> HierarchicalAlignment:
    return HierarchicalAlignment(
        a=_range(0, 5), b=_range(0, 5), is_leaf=True, raw_score=0.9, normalized_score=normalized_score, ops=ops
    )


# --- _sim_at_diagnostic ----------------------------------------------------------------


def test_sim_at_diagnostic_averages_scores_at_given_lines():
    alignment = _alignment(
        [
            HierarchicalOp(kind="match", score=0.8, a=_range(1, 1), b=_range(1, 1)),
            HierarchicalOp(kind="gap", score=-0.07, a=_range(2, 2), b=None),
            HierarchicalOp(kind="match", score=0.6, a=_range(3, 3), b=_range(3, 3)),
        ]
    )
    score, fallback_used = _sim_at_diagnostic(alignment, "b", [1, 3])
    assert score == pytest.approx(0.7)
    assert fallback_used is False


def test_sim_at_diagnostic_skips_missing_line_rather_than_counting_zero():
    alignment = _alignment(
        [HierarchicalOp(kind="match", score=0.8, a=_range(1, 1), b=_range(1, 1))]
    )
    score, fallback_used = _sim_at_diagnostic(alignment, "b", [1, 999])
    assert score == pytest.approx(0.8)
    assert fallback_used is False


def test_sim_at_diagnostic_falls_back_to_normalized_score_when_no_lines_given():
    alignment = _alignment([], normalized_score=0.42)
    score, fallback_used = _sim_at_diagnostic(alignment, "b", [])
    assert score == pytest.approx(0.42)
    assert fallback_used is True


def test_sim_at_diagnostic_falls_back_when_every_lookup_misses():
    alignment = _alignment(
        [HierarchicalOp(kind="match", score=0.8, a=_range(1, 1), b=_range(1, 1))], normalized_score=0.11
    )
    score, fallback_used = _sim_at_diagnostic(alignment, "b", [999])
    assert score == pytest.approx(0.11)
    assert fallback_used is True


def test_sim_at_diagnostic_treats_exact_op_text_as_identity():
    alignment = _alignment(
        [
            HierarchicalOp(
                kind="match", score=0.2, a=_range(1, 1), b=_range(1, 1),
                a_lines=["return value;"], b_lines=["return value;"],
            )
        ]
    )
    score, fallback_used = _sim_at_diagnostic(alignment, "b", [1])
    assert score == pytest.approx(1.0)
    assert fallback_used is False


# --- _bucket -----------------------------------------------------------------------------


def test_bucket_boundaries():
    margin = DEFAULT_VERIFICATION_MARGIN
    assert _bucket(margin, margin) == "flagged"
    assert _bucket(margin + 0.01, margin) == "flagged"
    assert _bucket(-margin, margin) == "cleared"
    assert _bucket(-margin - 0.01, margin) == "cleared"
    assert _bucket(0.0, margin) == "manual_review"
    assert _bucket(margin - 0.001, margin) == "manual_review"
    assert _bucket(-margin + 0.001, margin) == "manual_review"


# --- index_corpus_entries ----------------------------------------------------------------


def _entry(ghsa_id: str, file_path: str, function_name: str, vulnerable: str, patched: str) -> CorpusEntry:
    return CorpusEntry(
        ghsa_id=ghsa_id,
        package_name="demo-pkg",
        ecosystem="npm",
        repo="demo/repo",
        fix_commit_sha="deadbeef",
        file_path=file_path,
        function_name=function_name,
        vulnerable_function=vulnerable,
        patched_function=patched,
        diagnostic_lines=compute_diagnostic_lines(vulnerable, patched),
    )


def test_index_corpus_entries_keys_by_identity_tuple():
    entry = _entry("GHSA-demo-0001", "src/a.js", "fn", "function fn() {}", "function fn() { return 1; }")
    index = index_corpus_entries([entry])
    assert index[("GHSA-demo-0001", "deadbeef", "src/a.js", "fn")] is entry
    assert ("GHSA-demo-9999", "deadbeef", "src/a.js", "fn") not in index


# --- _diagnostic_scores ------------------------------------------------------------------


def test_diagnostic_scores_pairs_kind_specific_lines_with_the_matching_side():
    diagnostic_lines = [
        DiagnosticLine(kind="removed", vulnerable_line=1, text="old"),
        DiagnosticLine(kind="added", patched_line=1, text="new"),
    ]
    align_vs_vulnerable = _alignment([HierarchicalOp(kind="gap", score=-0.07, a=_range(1, 1), b=_range(1, 1))])
    align_vs_patched = _alignment([HierarchicalOp(kind="match", score=0.55, a=_range(1, 1), b=_range(1, 1))])

    scores = _diagnostic_scores(diagnostic_lines, align_vs_vulnerable, align_vs_patched)

    assert scores[0].vulnerable_score == pytest.approx(-0.07)
    assert scores[0].patched_score is None
    assert scores[1].vulnerable_score is None
    assert scores[1].patched_score == pytest.approx(0.55)


# --- Slow: real model, real embeddings -----------------------------------------------------
#
# DEFAULT_MODEL_ID only, same faiss/torch segfault rationale documented in
# tests/test_hierarchy.py / tests/test_alignment.py.

# A single-line "replace" diff -- both vulnerable_line and patched_line are populated
# by compute_diagnostic_lines, so this exercises the real diagnostic-line reading path
# on both sides, not the empty-lines fallback. Used below as the corpus entry for the
# manual_review demo -- not with candidate == vulnerable_function/patched_function
# verbatim (that's a self-anchor/self-clear case, and _verification_op_score's exact-
# text identity bonus now correctly resolves those decisively -- see
# BUILD_QUERY_AMBIGUOUS_CANDIDATE below for the actual manual_review fixture) but
# AUTHORIZE_VULNERABLE/_PATCHED below carries a much larger, multi-line semantic
# difference and is used for the flagged/cleared anchors instead.
BUILD_QUERY_VULNERABLE = """
function buildQuery(input) {
    const query = "SELECT * FROM users WHERE name = '" + input + "'";
    return query;
}
"""

BUILD_QUERY_PATCHED = """
function buildQuery(input) {
    const query = "SELECT * FROM users WHERE name = " + db.escape(input);
    return query;
}
"""

# A third variant of the diagnostic line -- a template literal -- that matches neither
# side's exact text (so neither alignment gets _verification_op_score's identity
# bonus), while still resembling both. Measured directly: scores only ~0.03 apart,
# inside the default margin. This is the intended behavior, not a bug: the
# manual_review bucket exists precisely for edits an embedding alone can't confidently
# separate (build plan module 7: "don't collapse this to binary").
BUILD_QUERY_AMBIGUOUS_CANDIDATE = """
function buildQuery(input) {
    const query = `SELECT * FROM users WHERE name = ${input}`;
    return query;
}
"""

# examples/hierarchy_demo's fixture pair -- a pure insertion (patched only adds a new
# leading guard, removes nothing), so this exercises the fallback path end-to-end with
# real embeddings, not just the hand-built fast tests above. Measured directly (smoke
# test, both models): the added guard's lines score strongly negative (~gap_penalty)
# against a candidate that lacks them, giving a decisive, comfortably-above-margin
# separation -- used below as the flagged/cleared anchor fixture.
AUTHORIZE_VULNERABLE = """
function authorize(user, resource) {
    if (user.isAdmin) {
        return true;
    }
    if (resource.owner === user.id) {
        return true;
    }
    return false;
}
"""

AUTHORIZE_PATCHED = """
function authorize(user, resource) {
    if (resource.locked) {
        return false;
    }
    if (user.isAdmin) {
        return true;
    }
    if (resource.owner === user.id) {
        return true;
    }
    return false;
}
"""

# Same statement shape as AUTHORIZE_VULNERABLE, identifiers renamed only (Type-2-like).
RENAMED_AUTHORIZE_CLONE = """
function checkAccess(currentUser, targetResource) {
    if (currentUser.isAdmin) {
        return true;
    }
    if (targetResource.owner === currentUser.id) {
        return true;
    }
    return false;
}
"""


def _build_query_entry() -> CorpusEntry:
    return _entry("GHSA-demo-query", "src/query.js", "buildQuery", BUILD_QUERY_VULNERABLE, BUILD_QUERY_PATCHED)


def _authorize_entry() -> CorpusEntry:
    return _entry("GHSA-demo-authz", "src/authorize.js", "authorize", AUTHORIZE_VULNERABLE, AUTHORIZE_PATCHED)


# Pinned explicitly rather than relying on DEFAULT_VERIFICATION_MARGIN's current
# value: these tests assert bucketing behavior at a known margin, not that the
# placeholder constant stays 0.1 forever (module 11 is expected to recalibrate it).
_TEST_MARGIN = 0.1


@pytest.mark.slow
def test_candidate_identical_to_vulnerable_is_flagged():
    entry = _authorize_entry()
    result = verify_candidate(entry.vulnerable_function, entry, EmbeddingCache(), margin=_TEST_MARGIN)
    assert result.verification_score > 0
    assert result.status == "flagged"


@pytest.mark.slow
def test_candidate_identical_to_patched_is_cleared():
    entry = _authorize_entry()
    result = verify_candidate(entry.patched_function, entry, EmbeddingCache(), margin=_TEST_MARGIN)
    assert result.verification_score < 0
    assert result.status == "cleared"


@pytest.mark.slow
def test_renamed_identifier_clone_of_vulnerable_is_still_flagged():
    entry = _authorize_entry()
    result = verify_candidate(RENAMED_AUTHORIZE_CLONE, entry, EmbeddingCache(), margin=_TEST_MARGIN)
    assert result.status == "flagged"


@pytest.mark.slow
def test_ambiguous_candidate_lands_in_manual_review():
    # Neither exactly vulnerable_function nor exactly patched_function -- genuinely
    # too close to call, not just an unresolved self-anchor/self-clear case. Pins the
    # deliberate three-bucket design: this must not silently resolve to flagged or
    # cleared.
    entry = _build_query_entry()
    result = verify_candidate(BUILD_QUERY_AMBIGUOUS_CANDIDATE, entry, EmbeddingCache(), margin=_TEST_MARGIN)
    assert result.status == "manual_review"


@pytest.mark.slow
def test_pure_insertion_diagnostic_entry_uses_fallback_on_vulnerable_side_only():
    # AUTHORIZE_PATCHED only adds lines relative to AUTHORIZE_VULNERABLE -- no
    # "removed" diagnostic lines exist, so sim_vulnerable has nothing to average and
    # must fall back to the whole-alignment normalized_score; sim_patched has real
    # "added" lines to read directly.
    entry = _authorize_entry()
    assert all(d.kind == "added" for d in entry.diagnostic_lines)

    result = verify_candidate(entry.vulnerable_function, entry, EmbeddingCache())
    assert result.vulnerable_fallback_used is True
    assert result.patched_fallback_used is False


@pytest.mark.slow
def test_verify_shares_one_cache_across_all_matches_and_sides():
    entry_a = _build_query_entry()
    entry_b = _authorize_entry()
    corpus_index = index_corpus_entries([entry_a, entry_b])
    match_a = RetrievalMatch(
        ghsa_id=entry_a.advisory.ghsa_id, repo=entry_a.origin.repo, fix_commit_sha=entry_a.origin.fix_commit_sha,
        file_path=entry_a.origin.file_path, function_name=entry_a.origin.function_name,
    )
    match_b = RetrievalMatch(
        ghsa_id=entry_b.advisory.ghsa_id, repo=entry_b.origin.repo, fix_commit_sha=entry_b.origin.fix_commit_sha,
        file_path=entry_b.origin.file_path, function_name=entry_b.origin.function_name,
    )

    calls: list[list[str]] = []
    real = hierarchy.embedding.encode

    def counting_encode(model_id, texts, batch_size=32):
        calls.append(list(texts))
        return real(model_id, texts, batch_size)

    hierarchy.embedding.encode = counting_encode
    try:
        verify(BUILD_QUERY_VULNERABLE, [match_a, match_b], corpus_index)
    finally:
        hierarchy.embedding.encode = real

    all_texts = [text for call in calls for text in call]
    assert len(all_texts) == len(set(all_texts)), "same text encoded more than once across the shared-cache run"
