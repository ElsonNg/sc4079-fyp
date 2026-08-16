import numpy as np
import pytest

from pipeline.controller import hierarchy
from pipeline.controller.alignment import (
    DEFAULT_GAP_PENALTY,
    DEFAULT_MAX_SPAN_LINES,
    DEFAULT_SPAN_MERGE_PENALTY,
    compute_score_tables,
)
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.hierarchy import (
    EmbeddingCache,
    _align_node_pair,
    _line_byte_offsets,
    _root_function_node,
    align_functions,
    compute_score_tables_cached,
    find_op_at_line,
)
from pipeline.controller.parsing import (
    get_structural_children,
    is_container_node_type,
    normalize_source,
    normalize_source_with_lines,
)

# This file mixes fast tree/DP-mechanics tests (hand-built or fake-encoded vectors, no
# real model load) with slow real-embedding tests -- same convention as
# tests/test_alignment.py: the `slow` marker is applied per-function, not module-level.

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

# Flat (un-nested), matches tests/test_alignment.py's own fixtures exactly -- used here
# for the grid-size and incoherent-candidate claims, which are about the *un-nested*
# shape (3 statements vs. 4).
PROCESS_ORDERS_BASE = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++)
        total += orders[i].price * orders[i].quantity;
    return total;
}
"""

PROCESS_ORDERS_SPLIT_RETURN = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++)
        total += orders[i].price * orders[i].quantity;
    const result = total;
    return result;
}
"""

# Nested variant: same split-return change, but the for-loop body is now an if/else
# block rather than a single bare statement -- exercises real recursion (for_statement
# -> statement_block -> if_statement -> statement_block/else_clause) rather than
# bottoming out immediately.
PROCESS_ORDERS_BASE_NESTED = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++) {
        if (orders[i].valid) {
            total += orders[i].price * orders[i].quantity;
        } else {
            total += 0;
        }
    }
    return total;
}
"""

PROCESS_ORDERS_SPLIT_RETURN_NESTED = """
function processOrders(orders) {
    let total = 0;
    for (let i = 0; i < orders.length; i++) {
        if (orders[i].valid) {
            total += orders[i].price * orders[i].quantity;
        } else {
            total += 0;
        }
    }
    const result = total;
    return result;
}
"""

# Two statements, swapped -- the order-sensitivity fixture named in the build plan
# (sanitize-before/after: order can be security-relevant, so this must not align as if
# reordering were free).
SANITIZE_BEFORE = """
function handleInput(input) {
    sanitize(input);
    use(input);
}
"""

SANITIZE_AFTER = """
function handleInput(input) {
    use(input);
    sanitize(input);
}
"""

METHOD_ONLY = """constructor(message) {
    super(message);
    this.name = 'AxiosError';
}"""


@pytest.fixture
def fake_embedding(monkeypatch):
    """Deterministic fake encode(): a fixed unit vector per unique text, stable within
    a test (identical text always cosine=1.0 with itself, regardless of dimension).
    High-dimensional enough (64) that two *different* auto-generated texts are
    approximately orthogonal, but tests needing a guaranteed sign relationship should
    still pre-seed specific texts into the returned dict before exercising the code
    under test, rather than relying on random near-orthogonality."""
    dim = 64
    vectors: dict[str, np.ndarray] = {}

    class _FakeModel:
        def get_embedding_dimension(self) -> int:
            return dim

    def fake_get_model(model_id: str):
        return _FakeModel()

    def fake_encode(model_id: str, texts: list[str], batch_size: int = 32) -> np.ndarray:
        out = np.empty((len(texts), dim), dtype=np.float32)
        for i, text in enumerate(texts):
            if text not in vectors:
                rng = np.random.default_rng(abs(hash(text)) % (2**32))
                vector = rng.normal(size=dim).astype(np.float32)
                vector /= np.linalg.norm(vector)
                vectors[text] = vector
            out[i] = vectors[text]
        return out

    monkeypatch.setattr(hierarchy.embedding, "encode", fake_encode)
    monkeypatch.setattr(hierarchy.embedding, "get_model", fake_get_model)
    return vectors


def _body(source: str):
    node = _root_function_node(source)
    return node.child_by_field_name("body")


def _walk_ops(alignment):
    """Yields every HierarchicalOp in the tree, depth-first."""
    for op in alignment.ops:
        yield op
        if op.children is not None:
            yield from _walk_ops(op.children)


def _walk_alignments(alignment):
    """Yields every HierarchicalAlignment in the tree, including `alignment` itself."""
    yield alignment
    for op in alignment.ops:
        if op.children is not None:
            yield from _walk_alignments(op.children)


# --- get_structural_children coverage --------------------------------------------------


def test_if_statement_structural_children():
    body = _body("function f(x) { if (x) { a(); } else { b(); } }")
    if_node = get_structural_children(body)[0]
    assert if_node.type == "if_statement"
    kids = get_structural_children(if_node)
    assert [k.type for k in kids] == ["parenthesized_expression", "statement_block", "else_clause"]


def test_for_statement_excludes_anchor_semicolons():
    body = _body("function f() { for (let i = 0; i < 10; i++) { d(); } }")
    for_node = get_structural_children(body)[0]
    assert for_node.type == "for_statement"
    kids = get_structural_children(for_node)
    assert [k.type for k in kids] == [
        "lexical_declaration", "binary_expression", "update_expression", "statement_block",
    ]


def test_switch_case_repeated_body_field():
    body = _body("function f(x) { switch (x) { case 1: h(); i(); break; default: j(); } }")
    switch_node = get_structural_children(body)[0]
    switch_body = get_structural_children(switch_node)[1]
    assert switch_body.type == "switch_body"
    case_node, default_node = get_structural_children(switch_body)
    assert [c.type for c in get_structural_children(case_node)] == [
        "number", "expression_statement", "expression_statement", "break_statement",
    ]
    assert [c.type for c in get_structural_children(default_node)] == ["expression_statement"]


def test_try_catch_finally_structural_children():
    body = _body("function f() { try { j(); } catch (err) { k(); } finally { l(); } }")
    try_node = get_structural_children(body)[0]
    assert try_node.type == "try_statement"
    kids = get_structural_children(try_node)
    assert [k.type for k in kids] == ["statement_block", "catch_clause", "finally_clause"]
    catch_node = kids[1]
    assert [k.type for k in get_structural_children(catch_node)] == ["identifier", "statement_block"]


def test_bare_catch_has_no_parameter_child():
    body = _body("function f() { try { j(); } catch { k(); } }")
    try_node = get_structural_children(body)[0]
    catch_node = get_structural_children(try_node)[1]
    assert [k.type for k in get_structural_children(catch_node)] == ["statement_block"]


def test_unregistered_node_types_have_no_structural_children():
    body = _body("function f() { return 1 + 2; }")
    return_stmt = get_structural_children(body)[0]
    assert return_stmt.type == "return_statement"
    assert get_structural_children(return_stmt) == []
    assert is_container_node_type(return_stmt.type) is False


def test_is_container_node_type_matches_registration():
    assert is_container_node_type("if_statement") is True
    assert is_container_node_type("statement_block") is True
    assert is_container_node_type("expression_statement") is False


# --- EmbeddingCache ----------------------------------------------------------------------


def test_get_or_encode_batches_misses_in_one_call(fake_embedding, monkeypatch):
    cache = EmbeddingCache()
    calls = []
    real_encode = hierarchy.embedding.encode

    def counting_encode(model_id, texts, batch_size=32):
        calls.append(list(texts))
        return real_encode(model_id, texts, batch_size)

    monkeypatch.setattr(hierarchy.embedding, "encode", counting_encode)
    vectors = cache.get_or_encode(DEFAULT_MODEL_ID, ["a", "b", "a", "c"])

    assert len(calls) == 1
    assert sorted(calls[0]) == ["a", "b", "c"]
    assert vectors.shape == (4, 64)
    assert np.array_equal(vectors[0], vectors[2])  # duplicate "a" reuses the same vector


def test_get_or_encode_reuses_primed_vectors_without_encoding(monkeypatch):
    cache = EmbeddingCache()
    primed = np.ones(4, dtype=np.float32)
    cache.prime(DEFAULT_MODEL_ID, "x", primed)

    def failing_encode(model_id, texts, batch_size=32):
        raise AssertionError("encode() should not be called for an already-primed text")

    monkeypatch.setattr(hierarchy.embedding, "encode", failing_encode)
    vectors = cache.get_or_encode(DEFAULT_MODEL_ID, ["x", "x"])

    assert np.array_equal(vectors[0], primed)
    assert np.array_equal(vectors[1], primed)


def test_get_or_encode_empty_texts_returns_empty_array_without_encoding(fake_embedding):
    cache = EmbeddingCache()
    vectors = cache.get_or_encode(DEFAULT_MODEL_ID, [])
    assert vectors.shape == (0, 64)


# --- compute_score_tables_cached ----------------------------------------------------------


def test_compute_score_tables_cached_shapes_match_flat_compute_score_tables(fake_embedding):
    seq_a = ["a0", "a1", "a2", "a3", "a4"]
    seq_b = ["b0", "b1", "b2", "b3", "b4", "b5"]
    m, n = len(seq_a), len(seq_b)

    cache = EmbeddingCache()
    scores = compute_score_tables_cached(seq_a, seq_b, cache, DEFAULT_MODEL_ID, match_midpoint=0.0)

    assert scores.match.shape == (m, n)
    assert scores.b_merge_2.shape == (m, n - 1)
    assert scores.b_merge_3.shape == (m, n - 2)
    assert scores.a_merge_2.shape == (m - 1, n)
    assert scores.a_merge_3.shape == (m - 2, n)


def test_compute_score_tables_cached_matches_flat_values_for_same_vectors(fake_embedding):
    # Same texts, same fake encoder -- cached and uncached builders must agree exactly,
    # since compute_score_tables_cached is a drop-in cache-sourced replica of
    # alignment.compute_score_tables.
    seq_a = ["p", "q", "r"]
    seq_b = ["p", "x", "r"]

    flat = compute_score_tables(seq_a, seq_b, model_id=DEFAULT_MODEL_ID, match_midpoint=0.0)
    cache = EmbeddingCache()
    cached = compute_score_tables_cached(seq_a, seq_b, cache, DEFAULT_MODEL_ID, match_midpoint=0.0)

    assert np.allclose(flat.match, cached.match)
    assert np.allclose(flat.b_merge_2, cached.b_merge_2)
    assert np.allclose(flat.a_merge_2, cached.a_merge_2)


# --- Recursive core, fake embeddings -------------------------------------------------------


def _align(source_a, source_b, **kwargs):
    cache = EmbeddingCache()
    kwargs.setdefault("match_midpoint", 0.0)
    return align_functions(source_a, source_b, cache, model_id=DEFAULT_MODEL_ID, **kwargs)


def test_identical_nested_functions_align_as_matches_at_every_level(fake_embedding):
    # Identical source on both sides -> identical text at every node -> cosine 1.0
    # everywhere matched content is compared, regardless of the fake encoder's
    # per-text randomness (same text always maps to the same vector).
    result = _align(PROCESS_ORDERS_BASE_NESTED, PROCESS_ORDERS_BASE_NESTED)

    for alignment in _walk_alignments(result):
        assert all(op.kind == "match" for op in alignment.ops)


def test_match_op_children_populated_only_for_recursed_pairs(fake_embedding):
    result = _align(PROCESS_ORDERS_BASE_NESTED, PROCESS_ORDERS_SPLIT_RETURN_NESTED)

    for op in _walk_ops(result):
        if op.kind in ("gap", "span_merge"):
            assert op.children is None, f"{op.kind} ops must be recursion-terminal"


def test_trivial_single_line_leaf_match_has_no_children(fake_embedding):
    # "let total = 0;" on both sides is a single-line, non-container leaf match --
    # already fully described by its own op, so no further DP/children.
    result = _align(PROCESS_ORDERS_BASE, PROCESS_ORDERS_BASE)
    body_alignment = result.ops[0].children  # function -> body passthrough

    lexical_decl_op = next(op for op in body_alignment.ops if op.a and op.a.node_type == "lexical_declaration")
    assert lexical_decl_op.kind == "match"
    assert lexical_decl_op.children is None


def test_score_is_not_rolled_up_from_children(fake_embedding):
    result = _align(PROCESS_ORDERS_BASE_NESTED, PROCESS_ORDERS_BASE_NESTED)
    body_alignment = result.ops[0].children

    # body_alignment's own raw_score must equal the sum of ITS OWN ops' scores (the
    # sibling DP result at this level), not something derived from the deeper nested
    # if/else alignment inside the for-loop.
    assert body_alignment.raw_score == pytest.approx(sum(op.score for op in body_alignment.ops))


def test_function_body_passthrough_forces_recursion_regardless_of_content(fake_embedding):
    # doA()/doB() are auto-generated fake vectors -- essentially orthogonal in 64-dim
    # space, i.e. this pair would gap under a scored sibling DP. Passthrough must still
    # force recursion into the two function bodies unconditionally.
    result = _align("function f() { doA(); }", "function g() { doB(); }")

    assert result.ops[0].kind == "match"
    assert result.ops[0].score == pytest.approx(1.0)
    assert result.ops[0].children is not None


def _find_node(root, node_type):
    if root.type == node_type:
        return root
    for child in root.children:
        found = _find_node(child, node_type)
        if found is not None:
            return found
    return None


def test_else_clause_passthrough_forces_recursion(fake_embedding):
    # Exercises the else_clause passthrough directly (not through the outer
    # if_statement/body DP): the two else_clause subtrees differ deep inside
    # (qA() vs qB()), so with the fake encoder's un-gradiented random vectors their
    # OVERALL representative text could easily score as unrelated at an outer level --
    # that's a limitation of the fake encoder, not of passthrough, so this test targets
    # the else_clause pair in isolation to avoid depending on an outer DP's luck.
    source_a = "function f(x) { if (x) { p(); } else { qA(); } }"
    source_b = "function f(x) { if (x) { p(); } else { qB(); } }"

    node_a = _root_function_node(source_a)
    node_b = _root_function_node(source_b)
    else_a = _find_node(node_a, "else_clause")
    else_b = _find_node(node_b, "else_clause")

    cache = EmbeddingCache()
    result = _align_node_pair(
        else_a, else_b,
        normalize_source_with_lines(source_a), normalize_source_with_lines(source_b),
        _line_byte_offsets(source_a), _line_byte_offsets(source_b),
        source_a.encode("utf-8"), source_b.encode("utf-8"),
        cache, DEFAULT_MODEL_ID, 0.0,
        DEFAULT_MAX_SPAN_LINES, DEFAULT_GAP_PENALTY, DEFAULT_SPAN_MERGE_PENALTY,
    )

    assert result is not None
    assert result.ops[0].kind == "match"
    assert result.ops[0].score == pytest.approx(1.0)
    assert result.ops[0].children is not None  # forced, even though qA()/qB() bodies differ


def test_method_only_source_is_wrapped_and_ranges_map_back(fake_embedding):
    result = align_functions(METHOD_ONLY, METHOD_ONLY, EmbeddingCache(), match_midpoint=0.0)

    assert result.a.start_line == 0
    assert result.a.end_line == 3
    assert result.b.start_line == 0
    assert result.b.end_line == 3
    op = find_op_at_line(result, "b", 1)
    assert op is not None
    assert op.b.start_line <= 1 <= op.b.end_line


def test_catch_clause_is_not_forced_through_passthrough(fake_embedding):
    # catch_clause is deliberately excluded from _PASSTHROUGH_NODE_TYPES -- a bare
    # `catch {}` (1 child) vs. a `catch (err) {}` (2 children) is a real DP question.
    assert "catch_clause" not in hierarchy._PASSTHROUGH_NODE_TYPES


def test_containment_invariant_nested_ops_fall_within_parent_range(fake_embedding):
    result = _align(PROCESS_ORDERS_BASE_NESTED, PROCESS_ORDERS_SPLIT_RETURN_NESTED)

    def check(alignment):
        for op in alignment.ops:
            if op.children is None:
                continue
            nested = op.children
            for side_range, node_range in ((op.a, nested.a), (op.b, nested.b)):
                assert side_range is not None
                assert node_range.start_byte >= side_range.start_byte
                assert node_range.end_byte <= side_range.end_byte
            check(nested)

    check(result)


def test_order_preservation_swap_never_yields_two_matches(fake_embedding):
    # SANITIZE_BEFORE/AFTER swap two statements. Even though the same two statement
    # texts appear on both sides (just reordered), an order-preserving DP can recover
    # at most one of the two correspondences -- never both, since that would require
    # traversing the DP grid non-monotonically.
    result = _align(SANITIZE_BEFORE, SANITIZE_AFTER)
    body = result.ops[0].children

    kinds = [op.kind for op in body.ops]
    assert kinds.count("match") <= 1
    assert kinds.count("gap") >= 2
    # Sequentiality: op ranges are monotonically non-decreasing in source position.
    a_starts = [op.a.start_byte for op in body.ops if op.a is not None]
    b_starts = [op.b.start_byte for op in body.ops if op.b is not None]
    assert a_starts == sorted(a_starts)
    assert b_starts == sorted(b_starts)


def test_find_op_at_line_resolves_deepest_containing_op(fake_embedding):
    result = _align(PROCESS_ORDERS_BASE_NESTED, PROCESS_ORDERS_BASE_NESTED)
    # Line 5 (0-indexed) is `total += orders[i].price * orders[i].quantity;`, inside
    # the if-branch, inside the for-loop -- an unambiguous, single-owner line.
    op = find_op_at_line(result, "a", 5)
    assert op is not None
    assert op.a is not None
    assert op.a.start_line <= 5 <= op.a.end_line
    # Should resolve to the specific statement, not just the enclosing function/body.
    assert op.a.node_type == "expression_statement"


def test_find_op_at_line_prefers_narrowest_range_on_shared_boundary_line(fake_embedding):
    result = _align(PROCESS_ORDERS_BASE_NESTED, PROCESS_ORDERS_BASE_NESTED)
    # Line 4 is `if (orders[i].valid) {` -- both the if_statement's condition
    # (parenthesized_expression, a 0-width single-line range) and the consequence
    # block (which also starts on that same physical line, since its opening brace
    # sits on it) contain this line. The narrower one (the condition) is the more
    # specific, correct answer.
    op = find_op_at_line(result, "a", 4)
    assert op is not None
    assert op.a is not None
    assert op.a.node_type == "parenthesized_expression"


def test_find_op_at_line_returns_none_outside_range(fake_embedding):
    result = _align(PROCESS_ORDERS_BASE, PROCESS_ORDERS_BASE)
    assert find_op_at_line(result, "a", 10_000) is None


def test_line_byte_offsets_round_trip():
    source = "line0\nline1\nline2"
    offsets = _line_byte_offsets(source)
    encoded = source.encode("utf-8")
    assert offsets[-1] == len(encoded)
    assert encoded[offsets[1] : offsets[2]] == b"line1\n"


# --- Slow: real model, real embeddings -----------------------------------------------------
#
# DEFAULT_MODEL_ID only, same faiss/torch segfault rationale documented in
# tests/test_alignment.py: loading a second SentenceTransformer model in the same
# process as faiss (imported transitively via test_retrieval.py in the same pytest
# run) segfaults intermittently on this machine.


@pytest.mark.slow
def test_top_level_body_grid_is_exactly_3x4_on_the_flat_fixture():
    # The literal, reproducible form of the build plan's "~12-cell" claim: the
    # statement_block-level sibling DP specifically (3 statements vs. 4), not a sum
    # over the whole recursive run, which lands larger (~28, see the next test) since
    # it also includes the for-loop's own internals and any leaf-level DPs.
    calls = []
    real = hierarchy.align_with_scores

    def spy(seq_a, seq_b, *args, **kwargs):
        calls.append((len(seq_a), len(seq_b)))
        return real(seq_a, seq_b, *args, **kwargs)

    hierarchy.align_with_scores = spy
    try:
        cache = EmbeddingCache()
        align_functions(PROCESS_ORDERS_BASE, PROCESS_ORDERS_SPLIT_RETURN, cache)
    finally:
        hierarchy.align_with_scores = real

    assert (3, 4) in calls


@pytest.mark.slow
def test_hierarchical_total_cell_count_is_smaller_than_flat_42():
    calls = []
    real = hierarchy.align_with_scores

    def spy(seq_a, seq_b, *args, **kwargs):
        calls.append((len(seq_a), len(seq_b)))
        return real(seq_a, seq_b, *args, **kwargs)

    hierarchy.align_with_scores = spy
    try:
        cache = EmbeddingCache()
        align_functions(PROCESS_ORDERS_BASE, PROCESS_ORDERS_SPLIT_RETURN, cache)
    finally:
        hierarchy.align_with_scores = real

    total_cells = sum(m * n for m, n in calls)
    flat_cells = 6 * 7  # normalize_source(PROCESS_ORDERS_BASE/SPLIT_RETURN) -> 6 vs. 7 lines
    assert total_cells < flat_cells


@pytest.mark.slow
def test_cannot_construct_the_flat_incoherent_span_merge():
    # Flat alignment's own span generator is free to join the for-loop's last line
    # with the following return line -- a real, previously-identified incoherent
    # candidate (no coherent structural meaning: it crosses the for-loop's closing
    # boundary). Confirm that exact joined text is never even *offered* as a candidate
    # to any hierarchical align_with_scores call, at any recursion level.
    from pipeline.controller.alignment import DEFAULT_MAX_SPAN_LINES, _generate_spans

    flat_seq = normalize_source(PROCESS_ORDERS_BASE)
    flat_spans = _generate_spans(flat_seq, DEFAULT_MAX_SPAN_LINES)
    # flat_seq[3] is the for-loop's (brace-less) body statement, flat_seq[4] is the
    # following return -- flat alignment is free to join them into one span candidate
    # even though they sit on opposite sides of the for-loop's structural boundary.
    assert flat_seq[3] == "total += orders[i].price * orders[i].quantity;"
    assert flat_seq[4] == "return total;"
    boundary_text = flat_spans[(3, 5)]

    seen_texts: set[str] = set()
    real = hierarchy.align_with_scores

    def spy(seq_a, seq_b, *args, **kwargs):
        seen_texts.update(seq_a)
        seen_texts.update(seq_b)
        return real(seq_a, seq_b, *args, **kwargs)

    hierarchy.align_with_scores = spy
    try:
        cache = EmbeddingCache()
        align_functions(PROCESS_ORDERS_BASE, PROCESS_ORDERS_SPLIT_RETURN, cache)
    finally:
        hierarchy.align_with_scores = real

    assert boundary_text not in seen_texts


@pytest.mark.slow
def test_renamed_variant_aligns_mostly_as_matches_at_every_level():
    cache = EmbeddingCache()
    result = align_functions(TRANSFER_A, TRANSFER_RENAMED, cache)

    for alignment in _walk_alignments(result):
        kinds = [op.kind for op in alignment.ops]
        if kinds:
            assert kinds.count("match") >= kinds.count("gap")


@pytest.mark.slow
def test_unrelated_functions_align_mostly_as_gaps_with_no_false_matches():
    cache = EmbeddingCache()
    result = align_functions(TRANSFER_A, UNRELATED, cache)

    for op in _walk_ops(result):
        if op.kind in ("match", "span_merge") and op.score != pytest.approx(1.0):
            # score == 1.0 marks a forced passthrough (not a computed similarity);
            # every genuinely *scored* match/span_merge must be positive -- the same
            # true-negative check test_alignment.py's flat-level test performs.
            assert op.score > 0, f"{op.kind} at A{op.a} scored {op.score}"


@pytest.mark.slow
def test_cache_reuse_across_vulnerable_and_patched_comparisons():
    # Module 7's actual usage pattern: one candidate compared against both
    # vulnerable_function and patched_function, sharing one cache instance.
    cache = EmbeddingCache()
    align_functions(TRANSFER_A, PROCESS_ORDERS_BASE, cache)
    primed_after_first = set(cache._vectors.keys())

    calls = []
    real = hierarchy.embedding.encode

    def counting_encode(model_id, texts, batch_size=32):
        calls.append(list(texts))
        return real(model_id, texts, batch_size)

    hierarchy.embedding.encode = counting_encode
    try:
        align_functions(TRANSFER_A, PROCESS_ORDERS_SPLIT_RETURN, cache)
    finally:
        hierarchy.embedding.encode = real

    # TRANSFER_A's own texts were already cached by the first call -- none of them
    # should be re-encoded on the second call (only PROCESS_ORDERS_SPLIT_RETURN's new
    # texts, which TRANSFER_A does not share, should trigger a real encode() call).
    all_second_call_texts = {text for call in calls for text in call}
    transfer_a_texts = {text for (mid, text) in primed_after_first if mid == DEFAULT_MODEL_ID}
    assert transfer_a_texts.isdisjoint(all_second_call_texts)
