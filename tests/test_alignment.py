import numpy as np
import pytest

from pipeline.controller.alignment import (
    DEFAULT_GAP_PENALTY,
    DEFAULT_SPAN_MERGE_PENALTY,
    SpanScoreTables,
    align,
    align_with_scores,
    compute_score_tables,
    get_match_midpoint,
)
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.parsing import normalize_source

# This file mixes fast DP-mechanics tests (hand-built SpanScoreTables, no model load) with
# slow real-embedding tests -- unlike the other test files' module-level pytestmark, the
# `slow` marker is applied per-function here since both kinds of test genuinely belong in
# the same file.

TRANSFER_A = """
function transfer(sender, receiver, amount) {
    let balance = sender.balance;
    if (balance < amount) { throw new Error('insufficient'); }
    sender.balance = balance - amount;
    receiver.balance = receiver.balance + amount;
    return receiver.balance;
}
"""

# Same as TRANSFER_A: identifiers renamed only.
TRANSFER_RENAMED = """
function transfer(from, to, amt) {
    let bal = from.balance;
    if (bal < amt) { throw new Error('insufficient'); }
    from.balance = bal - amt;
    to.balance = to.balance + amt;
    return to.balance;
}
"""

UNRELATED = """
function formatDate(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}
"""

# Reconstructed process_orders example -- no original exists in prior research, only its
# shape (6-line vs 7-line JS function, a `for` and a `return`, one line split via
# extract-variable). The split targets the return statement, not the brace-less for body,
# so it doesn't also force an unrelated structural brace-addition into the 6-vs-7 shape.
PROCESS_ORDERS_BASE = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++)
        total += orders[i].price * orders[i].quantity;
    return total;
}
"""

# Identical to BASE except the return statement is split into a variable declaration plus
# return, via extract-variable.
PROCESS_ORDERS_SPLIT_RETURN = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++)
        total += orders[i].price * orders[i].quantity;
    const result = total;
    return result;
}
"""


def _op_kinds(alignment):
    return [op.kind for op in alignment.ops]


# --- Fast: pure DP mechanics, hand-built score tables ------------------------------------


def test_identical_sequences_align_as_all_matches():
    seq = ["a", "b", "c"]
    match = np.where(np.eye(3, dtype=bool), 1.0, -1.0)
    scores = SpanScoreTables(match=match, b_merge_2=None, b_merge_3=None, a_merge_2=None, a_merge_3=None)

    alignment = align_with_scores(seq, seq, scores)

    assert _op_kinds(alignment) == ["match", "match", "match"]
    assert alignment.raw_score == pytest.approx(3.0)


def test_dissimilar_sequences_prefer_gaps_over_forced_match():
    seq_a, seq_b = ["a", "b"], ["x", "y"]
    match = np.full((2, 2), -10.0)
    scores = SpanScoreTables(match=match, b_merge_2=None, b_merge_3=None, a_merge_2=None, a_merge_3=None)

    alignment = align_with_scores(seq_a, seq_b, scores, gap_penalty=-1.0)

    assert _op_kinds(alignment) == ["gap", "gap", "gap", "gap"]
    assert alignment.raw_score == pytest.approx(4 * -1.0)


def test_span_merge_chosen_when_join_score_dominates():
    seq_a, seq_b = ["x"], ["p", "q"]
    match = np.full((1, 2), -5.0)
    b_merge_2 = np.full((1, 1), 5.0)
    scores = SpanScoreTables(match=match, b_merge_2=b_merge_2, b_merge_3=None, a_merge_2=None, a_merge_3=None)

    alignment = align_with_scores(seq_a, seq_b, scores, gap_penalty=-1.0, span_merge_penalty=-0.1)

    assert len(alignment.ops) == 1
    op = alignment.ops[0]
    assert op.kind == "span_merge"
    assert (op.a_start, op.a_end, op.b_start, op.b_end) == (0, 1, 0, 2)
    assert op.score == pytest.approx(4.9)


def test_process_orders_split_scores_as_span_merge_not_gap_dp_level():
    seq_a = normalize_source(PROCESS_ORDERS_BASE)
    seq_b = normalize_source(PROCESS_ORDERS_SPLIT_RETURN)
    assert (len(seq_a), len(seq_b)) == (6, 7)

    # Hand-built scores encoding the calibrated bands measured against the real model
    # (see pipeline/controller/alignment.py's get_match_midpoint): identical lines shifted
    # ~+0.55, the process_orders merge shifted +0.408, the deceptive partial match
    # ("return total;" vs "const result = total;") shifted +0.374, everything else
    # low/unrelated.
    match = np.full((6, 7), -0.3)
    for i in range(4):
        match[i, i] = 0.55
    match[4, 4] = 0.374  # "return total;" vs "const result = total;" (deceptive)
    match[4, 5] = -0.088  # "return total;" vs "return result;"
    match[5, 6] = 0.55  # closing brace vs closing brace

    b_merge_2 = np.full((6, 6), -0.5)
    b_merge_2[4, 4] = 0.408  # "return total;" vs joined "const result = total; return result;"

    scores = SpanScoreTables(match=match, b_merge_2=b_merge_2, b_merge_3=None, a_merge_2=None, a_merge_3=None)
    alignment = align_with_scores(seq_a, seq_b, scores)

    assert "gap" not in _op_kinds(alignment)
    span_merges = [op for op in alignment.ops if op.kind == "span_merge"]
    assert len(span_merges) == 1
    merge = span_merges[0]
    assert (merge.a_start, merge.a_end, merge.b_start, merge.b_end) == (4, 5, 4, 6)
    assert _op_kinds(alignment) == ["match", "match", "match", "match", "span_merge", "match"]


def test_tie_breaking_follows_fixed_priority_order():
    # Both sub-cases align seq_a=["x"] against seq_b=["p","q"], so the only cell that
    # matters is the final one, (1,2) -- reachable via "match" (from (0,1), matching x
    # against "q") or "span_merge" (from (0,0), merging x against join("p","q")).

    # match vs span_merge tie at (1,2): match must win (it's first in candidate priority).
    # dp[0][1] = gap_penalty = -1.0; LHS = gap_penalty + match[0,1] = -1.0 + 5.0 = 4.0.
    # RHS = b_merge_2[0,0] + span_merge_penalty = 4.0 + 0.0 = 4.0 -- exact tie.
    match = np.full((1, 2), -100.0)
    match[0, 1] = 5.0
    b_merge_2 = np.full((1, 1), 4.0)
    scores = SpanScoreTables(match=match, b_merge_2=b_merge_2, b_merge_3=None, a_merge_2=None, a_merge_3=None)
    alignment = align_with_scores(["x"], ["p", "q"], scores, gap_penalty=-1.0, span_merge_penalty=0.0)
    assert _op_kinds(alignment) == ["gap", "match"]

    # span_merge vs gap tie at (1,2): span_merge must win (it's before gap in priority).
    # Uses a *positive* raw merge score (0.01) so the merge candidate is actually eligible
    # (see test_span_merge_rejected_when_raw_score_is_not_positive below for the negative
    # case) -- best gap-only path to (1,2) costs 3*gap_penalty = -0.03 (dp[0][1]=1 more
    # gap_penalty via cell (1,1), whose own best predecessor is itself a gap since match is
    # set low). RHS = b_merge_2[0,0] + span_merge_penalty = 0.01 + -0.04 = -0.03 -- exact tie.
    match2 = np.full((1, 2), -100.0)
    b_merge_2_tied = np.full((1, 1), 0.01)
    scores2 = SpanScoreTables(match=match2, b_merge_2=b_merge_2_tied, b_merge_3=None, a_merge_2=None, a_merge_3=None)
    alignment2 = align_with_scores(["x"], ["p", "q"], scores2, gap_penalty=-0.01, span_merge_penalty=-0.04)
    assert _op_kinds(alignment2) == ["span_merge"]


def test_span_merge_rejected_when_raw_score_is_not_positive():
    # Minimal repro of a real failure mode found via smoke-testing: 3 genuinely unrelated
    # A-lines merged against 1 unrelated B-line can score better than 4 honest gaps purely
    # by paying the merge penalty once instead of the gap penalty 4 times (raw merge score
    # -0.20 + span_merge_penalty -0.05 = -0.25, vs. 4*gap_penalty = -0.28 -- the merge
    # would win on arithmetic alone despite representing no real correspondence). Gating
    # span_merge candidates on a positive raw score must reject it, leaving gaps as the
    # only option.
    match = np.full((3, 1), -10.0)  # no line has any real 1:1 correspondence
    a_merge_3 = np.array([[-0.20]])  # negative -- these 3 lines don't really match this 1 line
    scores = SpanScoreTables(match=match, b_merge_2=None, b_merge_3=None, a_merge_2=None, a_merge_3=a_merge_3)

    alignment = align_with_scores(["a", "b", "c"], ["x"], scores)

    assert "span_merge" not in _op_kinds(alignment)
    assert _op_kinds(alignment).count("gap") == 4
    assert alignment.raw_score == pytest.approx(4 * DEFAULT_GAP_PENALTY)


def test_match_rejected_when_raw_score_is_not_positive():
    # Minimal repro of the same failure mode found on embeddinggemma-300m via
    # smoke-testing, but for a plain 1:1 match: a barely-negative match score can still
    # beat 2*gap_penalty on arithmetic alone (2*-0.07=-0.14 is more negative than -0.05),
    # even though the negative score itself says these two lines aren't really alike.
    # Gating match candidates on a positive raw score must reject it, leaving gaps as the
    # only option.
    match = np.array([[-0.05]])
    scores = SpanScoreTables(match=match, b_merge_2=None, b_merge_3=None, a_merge_2=None, a_merge_3=None)

    alignment = align_with_scores(["p"], ["q"], scores)

    assert _op_kinds(alignment) == ["gap", "gap"]
    assert alignment.raw_score == pytest.approx(2 * DEFAULT_GAP_PENALTY)


def test_traceback_ops_cover_full_sequences_without_overlap():
    seq_a, seq_b = ["a", "b", "c"], ["a", "x", "b", "c"]
    match = np.full((3, 4), -1.0)
    for i, line in enumerate(seq_a):
        for j, other in enumerate(seq_b):
            if line == other:
                match[i, j] = 1.0
    scores = SpanScoreTables(match=match, b_merge_2=None, b_merge_3=None, a_merge_2=None, a_merge_3=None)

    alignment = align_with_scores(seq_a, seq_b, scores)

    a_covered = [i for op in alignment.ops for i in range(op.a_start, op.a_end)]
    b_covered = [j for op in alignment.ops for j in range(op.b_start, op.b_end)]
    assert a_covered == list(range(3))
    assert b_covered == list(range(4))
    assert sum(op.score for op in alignment.ops) == pytest.approx(alignment.raw_score)


def test_one_side_empty_returns_all_gaps():
    match = np.empty((0, 2))
    scores = SpanScoreTables(match=match, b_merge_2=None, b_merge_3=None, a_merge_2=None, a_merge_3=None)

    alignment = align_with_scores([], ["x", "y"], scores, gap_penalty=-0.5)

    assert _op_kinds(alignment) == ["gap", "gap"]
    assert alignment.raw_score == pytest.approx(2 * -0.5)


def test_both_sides_empty_returns_trivial_alignment():
    match = np.empty((0, 0))
    scores = SpanScoreTables(match=match, b_merge_2=None, b_merge_3=None, a_merge_2=None, a_merge_3=None)

    alignment = align_with_scores([], [], scores)

    assert alignment.ops == []
    assert alignment.raw_score == pytest.approx(0.0)
    assert alignment.normalized_score == pytest.approx(1.0)


# --- Slow: real embeddings, real model ------------------------------------------------------
#
# DEFAULT_MODEL_ID only, deliberately not parametrized across MODEL_REGISTRY here: loading a
# second SentenceTransformer model in the same process as `faiss` (imported transitively via
# test_retrieval.py, collected as part of the same pytest run) segfaults intermittently on
# this machine -- confirmed to be a faiss/torch native conflict, not a logic bug: a plain
# script loading both models sequentially with no faiss import succeeds reliably every time.
# Cross-model verification (this fix exists because a model-specific bug slipped past
# single-model tests -- see the match/span_merge gating comments in alignment.py) lives in
# scripts/smoke_test_alignment.py instead, which never imports faiss and is safe to run
# standalone for both models.


@pytest.mark.slow
def test_process_orders_split_line_scores_as_span_merge_real_model():
    seq_a = normalize_source(PROCESS_ORDERS_BASE)
    seq_b = normalize_source(PROCESS_ORDERS_SPLIT_RETURN)

    alignment = align(seq_a, seq_b)

    assert "gap" not in _op_kinds(alignment)
    span_merges = [op for op in alignment.ops if op.kind == "span_merge"]
    assert len(span_merges) == 1
    assert span_merges[0].score > 0
    assert (span_merges[0].a_start, span_merges[0].a_end) == (4, 5)
    assert (span_merges[0].b_start, span_merges[0].b_end) == (4, 6)


@pytest.mark.slow
def test_renamed_variant_aligns_as_matches_not_gaps():
    seq_a = normalize_source(TRANSFER_A)
    seq_b = normalize_source(TRANSFER_RENAMED)

    alignment = align(seq_a, seq_b)

    kinds = _op_kinds(alignment)
    assert kinds.count("match") > kinds.count("gap")


@pytest.mark.slow
def test_unrelated_functions_align_with_mostly_gaps_and_no_false_matches():
    seq_a = normalize_source(TRANSFER_A)
    seq_b = normalize_source(UNRELATED)

    alignment = align(seq_a, seq_b)

    kinds = _op_kinds(alignment)
    assert kinds.count("gap") > kinds.count("match")
    # The true-negative check the merge/match gating fix exists for: no match or
    # span_merge op should ever carry a non-positive score -- a below-midpoint pair has no
    # business being reported as "these correspond."
    for op in alignment.ops:
        if op.kind in ("match", "span_merge"):
            assert op.score > 0, f"{op.kind} at A[{op.a_start}:{op.a_end}] scored {op.score}"


@pytest.mark.slow
def test_compute_score_tables_shapes_match_expected_span_counts():
    seq_a = normalize_source(TRANSFER_A)
    seq_b = normalize_source(TRANSFER_RENAMED)
    m, n = len(seq_a), len(seq_b)

    scores = compute_score_tables(seq_a, seq_b)

    assert scores.match.shape == (m, n)
    assert scores.b_merge_2.shape == (m, n - 1)
    assert scores.b_merge_3.shape == (m, n - 2)
    assert scores.a_merge_2.shape == (m - 1, n)
    assert scores.a_merge_3.shape == (m - 2, n)


@pytest.mark.slow
def test_get_match_midpoint_is_cached():
    first = get_match_midpoint(DEFAULT_MODEL_ID)
    second = get_match_midpoint(DEFAULT_MODEL_ID)
    assert first == second  # cached, not recomputed
    # Sanity bound -- a real calibrated midpoint should land strictly between the
    # unrelated and related probe bands, not at a degenerate extreme.
    assert 0.0 < first < 1.0
