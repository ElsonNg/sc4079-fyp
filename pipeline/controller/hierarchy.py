"""Stage 3b -- hierarchical decomposition. Recurses along the AST, reusing Stage 3a's
flat line-alignment primitive (pipeline.controller.alignment) at every level instead of
flattening a whole function body into one line sequence: a node's structural children
are aligned as a short sibling sequence, each resulting 1:1 match is recursed into, and
recursion bottoms out at the flat primitive for genuine leaf statements. Because
recursion only ever descends through a 1:1 match between siblings under the same
parent, a span merge can never join lines across an unrelated structural boundary the
way flat (whole-function) alignment can.
"""

from dataclasses import dataclass, field
from typing import Literal

import numpy as np
import tree_sitter

from pipeline.controller import embedding
from pipeline.controller.alignment import (
    DEFAULT_GAP_PENALTY,
    DEFAULT_MAX_SPAN_LINES,
    DEFAULT_SPAN_MERGE_PENALTY,
    SpanScoreTables,
    _generate_spans,
    align_with_scores,
    get_match_midpoint,
)
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.parsing import (
    FUNCTION_NODE_TYPES,
    get_normalized_node_text,
    get_structural_children,
    is_container_node_type,
    normalize_source_with_lines,
    parse_source,
)
from pipeline.models.hierarchy import HierarchicalAlignment, HierarchicalOp, NodeRange

# Node types with an exactly-one-structural-child correspondence guaranteed by grammar
# construction, not by data -- a function's own body, and the two clauses that only
# exist at all when their single child is present. Recursing into these directly (see
# _align_node_pair) skips the scored sibling DP entirely: match_midpoint is calibrated
# on short 2-4 line snippets, and running a whole-body-joined representative string
# through it risks a spurious "gap" that would silently stop recursion before it
# starts, for a correspondence that was never in question.
#
# catch_clause is deliberately excluded -- its "parameter" field is optional (bare
# `catch { }` is legal JS), so its child count genuinely varies 1 vs 2 between two real
# catch clauses. That is a real DP question, not a guaranteed passthrough.
_PASSTHROUGH_NODE_TYPES = FUNCTION_NODE_TYPES | {"else_clause", "finally_clause"}


@dataclass
class EmbeddingCache:
    """In-process, caller-owned memoization of embedding.encode() results, keyed by
    (model_id, text) -- embedding is a pure function of (model, text), so this is valid
    regardless of which node/tree/comparison a text came from. Not persisted (mirrors
    alignment.py's _match_midpoint_cache: cheap to recompute, deterministic, no
    staleness/invalidation question).

    Owned by the caller, not created per align_functions() call -- module 7 calls
    align_functions() twice per shortlisted candidate (once vs vulnerable_function,
    once vs patched_function) and once per corpus entry per scan; passing the SAME
    cache instance across all of those calls is where the reuse payoff comes from,
    since the candidate's own node texts don't change between those calls.
    """

    _vectors: dict[tuple[str, str], np.ndarray] = field(default_factory=dict)

    def prime(self, model_id: str, text: str, vector: np.ndarray) -> None:
        """Seed a hand-built vector directly -- lets fast tests exercise cache-aware
        code paths without loading a real model."""
        self._vectors[(model_id, text)] = vector

    def get_or_encode(self, model_id: str, texts: list[str]) -> np.ndarray:
        """Vectors for `texts`, in order, duplicates included. Every cache miss across
        this call is batched through exactly one embedding.encode() call (mirrors
        compute_score_tables's own sorted(set(...)) batching)."""
        missing = sorted({text for text in texts if (model_id, text) not in self._vectors})
        if missing:
            vectors = embedding.encode(model_id, missing)
            for text, vector in zip(missing, vectors):
                self._vectors[(model_id, text)] = vector
        if not texts:
            dim = embedding.get_model(model_id).get_embedding_dimension()
            return np.empty((0, dim), dtype=np.float32)
        return np.stack([self._vectors[(model_id, text)] for text in texts])


def compute_score_tables_cached(
    seq_a: list[str],
    seq_b: list[str],
    cache: EmbeddingCache,
    model_id: str,
    match_midpoint: float,
    max_span_lines: int = DEFAULT_MAX_SPAN_LINES,
) -> SpanScoreTables:
    """Identical matrix-assembly logic to alignment.compute_score_tables, sourcing
    vectors from `cache` (batched, cache-miss-only) instead of calling encode()
    unconditionally. Output is drop-in compatible with align_with_scores.

    `match_midpoint` has no default -- callers must compute get_match_midpoint(model_id)
    once and thread the same value through every recursive call (get_match_midpoint's
    own docstring: "module 6 runs this on 2-4-line AST-sibling sequences, too small for
    any per-call statistic to mean anything"). A None-default here would let a
    recursive caller silently drift back into per-call recomputation."""
    m, n = len(seq_a), len(seq_b)
    spans_a = _generate_spans(seq_a, max_span_lines)
    spans_b = _generate_spans(seq_b, max_span_lines)

    all_texts = sorted(set(spans_a.values()) | set(spans_b.values()))
    vectors = cache.get_or_encode(model_id, all_texts)
    dim = vectors.shape[1] if all_texts else embedding.get_model(model_id).get_embedding_dimension()
    text_to_vec = {text: vectors[i] for i, text in enumerate(all_texts)}

    def span_vectors(seq_len: int, length: int, spans: dict[tuple[int, int], str]) -> np.ndarray | None:
        count = seq_len - length + 1
        if count <= 0:
            return None
        out = np.empty((count, dim), dtype=np.float32)
        for start in range(count):
            out[start] = text_to_vec[spans[(start, start + length)]]
        return out

    a1 = span_vectors(m, 1, spans_a)
    b1 = span_vectors(n, 1, spans_b)
    a2 = span_vectors(m, 2, spans_a) if max_span_lines >= 2 else None
    a3 = span_vectors(m, 3, spans_a) if max_span_lines >= 3 else None
    b2 = span_vectors(n, 2, spans_b) if max_span_lines >= 2 else None
    b3 = span_vectors(n, 3, spans_b) if max_span_lines >= 3 else None

    def score(x: np.ndarray | None, y: np.ndarray | None) -> np.ndarray | None:
        if x is None or y is None:
            return None
        return (x @ y.T).astype(np.float64) - match_midpoint

    match = score(a1, b1)
    if match is None:
        match = np.empty((m, n), dtype=np.float64)

    return SpanScoreTables(
        match=match,
        b_merge_2=score(a1, b2),
        b_merge_3=score(a1, b3),
        a_merge_2=score(a2, b1),
        a_merge_3=score(a3, b1),
    )


def _representative_text(node: tree_sitter.Node, source_bytes: bytes) -> str:
    """One "line" of text standing in for `node` as a whole in its parent's sibling
    sequence -- mirrors _generate_spans's own " ".join(...) joining convention."""
    return " ".join(get_normalized_node_text(node, source_bytes))


def _node_range(node: tree_sitter.Node) -> NodeRange:
    return NodeRange(
        node_type=node.type,
        start_byte=node.start_byte,
        end_byte=node.end_byte,
        start_line=node.start_point[0],
        end_line=node.end_point[0],
    )


def _node_range_span(nodes: list[tree_sitter.Node]) -> NodeRange:
    """Covering range for a contiguous run of >=1 sibling nodes (a span_merge's
    multi-node side). Nodes are already in source order, so the first/last suffice."""
    if len(nodes) == 1:
        return _node_range(nodes[0])
    return NodeRange(
        node_type="span",
        start_byte=nodes[0].start_byte,
        end_byte=nodes[-1].end_byte,
        start_line=nodes[0].start_point[0],
        end_line=nodes[-1].end_point[0],
    )


def _line_byte_offsets(source: str) -> list[int]:
    """offsets[i] = byte offset of the start of physical (0-indexed) line i in
    `source`; offsets[-1] = total byte length. Used to give leaf-level (sub-node,
    per-line) HierarchicalOps a real byte range -- normalize_source_with_lines only
    carries line numbers, not byte offsets, since it operates on comment-stripped text
    rather than tree-sitter nodes."""
    offsets = [0]
    for line in source.splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line.encode("utf-8")))
    return offsets


def _leaf_node_range(
    line_offsets: list[int], filtered_lines: list[tuple[int, str]], start_idx: int, end_idx: int
) -> NodeRange:
    """NodeRange for a leaf-level op spanning local indices [start_idx, end_idx) into
    `filtered_lines` (a node's own normalize_source_with_lines subset)."""
    start_line_no = filtered_lines[start_idx][0]
    end_line_no = filtered_lines[end_idx - 1][0]
    return NodeRange(
        node_type="line_range",
        start_byte=line_offsets[start_line_no],
        end_byte=line_offsets[end_line_no + 1],
        start_line=start_line_no,
        end_line=end_line_no,
    )


def _collect_required_texts(
    root: tree_sitter.Node,
    source_bytes: bytes,
    line_texts: list[str],
    max_span_lines: int,
) -> set[str]:
    """Every text one batched encode() call needs to cover, for one side of one
    align_functions() comparison: every bounded span of the whole function's own
    normalized lines (covers any node's own line range, since any node's filtered
    lines are a contiguous sub-window of `line_texts` -- so this single whole-function
    pass already covers every possible leaf-vs-leaf DP at any depth), plus every
    container's child-representative texts and their bounded spans (AST-shape
    dependent, so these do need a per-node walk)."""
    required: set[str] = set(_generate_spans(line_texts, max_span_lines).values())

    def walk(node: tree_sitter.Node) -> None:
        children = get_structural_children(node)
        if children:
            texts = [_representative_text(child, source_bytes) for child in children]
            required.update(_generate_spans(texts, max_span_lines).values())
            for child in children:
                walk(child)

    walk(root)
    return required


def _root_function_node(source: str) -> tree_sitter.Node:
    tree = parse_source(source)

    def find(node: tree_sitter.Node) -> tree_sitter.Node | None:
        if node.type in FUNCTION_NODE_TYPES:
            return node
        for child in node.children:
            found = find(child)
            if found is not None:
                return found
        return None

    result = find(tree.root_node)
    if result is None:
        raise ValueError("No function node found in source")
    return result


def _align_node_pair(
    node_a: tree_sitter.Node,
    node_b: tree_sitter.Node,
    lines_a: list[tuple[int, str]],
    lines_b: list[tuple[int, str]],
    line_offsets_a: list[int],
    line_offsets_b: list[int],
    source_bytes_a: bytes,
    source_bytes_b: bytes,
    cache: EmbeddingCache,
    model_id: str,
    match_midpoint: float,
    max_span_lines: int,
    gap_penalty: float,
    span_merge_penalty: float,
) -> HierarchicalAlignment | None:
    """Recursive core. Returns None only for the trivial leaf case where both sides
    reduce to <=1 line each -- already fully described by the caller's own match op
    (its a/b/a_lines/b_lines/score), so a further 1x1 DP call would add nothing."""
    a_range = _node_range(node_a)
    b_range = _node_range(node_b)

    if is_container_node_type(node_a.type) and is_container_node_type(node_b.type):
        children_a = get_structural_children(node_a)
        children_b = get_structural_children(node_b)

        if (
            node_a.type in _PASSTHROUGH_NODE_TYPES
            and node_b.type in _PASSTHROUGH_NODE_TYPES
            and len(children_a) == 1
            and len(children_b) == 1
        ):
            nested = _align_node_pair(
                children_a[0], children_b[0], lines_a, lines_b, line_offsets_a, line_offsets_b,
                source_bytes_a, source_bytes_b, cache, model_id, match_midpoint,
                max_span_lines, gap_penalty, span_merge_penalty,
            )
            raw_score = nested.raw_score if nested is not None else 1.0
            normalized_score = nested.normalized_score if nested is not None else 1.0
            op = HierarchicalOp(
                kind="match",
                score=1.0,  # forced passthrough -- a grammar-guaranteed correspondence, not a computed similarity
                a=_node_range(children_a[0]),
                b=_node_range(children_b[0]),
                a_lines=[_representative_text(children_a[0], source_bytes_a)],
                b_lines=[_representative_text(children_b[0], source_bytes_b)],
                children=nested,
            )
            return HierarchicalAlignment(
                a=a_range, b=b_range, is_leaf=False,
                raw_score=raw_score, normalized_score=normalized_score, ops=[op],
            )

        texts_a = [_representative_text(child, source_bytes_a) for child in children_a]
        texts_b = [_representative_text(child, source_bytes_b) for child in children_b]
        scores = compute_score_tables_cached(texts_a, texts_b, cache, model_id, match_midpoint, max_span_lines)
        sibling = align_with_scores(texts_a, texts_b, scores, gap_penalty, span_merge_penalty)

        ops: list[HierarchicalOp] = []
        for sib_op in sibling.ops:
            nested = None
            a_range_op = None
            b_range_op = None
            if sib_op.kind == "match":
                child_a = children_a[sib_op.a_start]
                child_b = children_b[sib_op.b_start]
                nested = _align_node_pair(
                    child_a, child_b, lines_a, lines_b, line_offsets_a, line_offsets_b,
                    source_bytes_a, source_bytes_b, cache, model_id, match_midpoint,
                    max_span_lines, gap_penalty, span_merge_penalty,
                )
                a_range_op = _node_range(child_a)
                b_range_op = _node_range(child_b)
            else:
                # gap/span_merge: terminal by design -- there is no single node pair to
                # recurse into (span_merge pairs one node against several; gap pairs one
                # node against none). This is what makes "can't construct incoherent
                # candidates" true: recursion only ever crosses into sibling pairs under
                # the same parent, never spans a structural boundary.
                if sib_op.a_end > sib_op.a_start:
                    a_range_op = _node_range_span(children_a[sib_op.a_start : sib_op.a_end])
                if sib_op.b_end > sib_op.b_start:
                    b_range_op = _node_range_span(children_b[sib_op.b_start : sib_op.b_end])
            ops.append(
                HierarchicalOp(
                    kind=sib_op.kind, score=sib_op.score,
                    a=a_range_op, b=b_range_op,
                    a_lines=sib_op.a_lines, b_lines=sib_op.b_lines,
                    children=nested,
                )
            )
        return HierarchicalAlignment(
            a=a_range, b=b_range, is_leaf=False,
            raw_score=sibling.raw_score, normalized_score=sibling.normalized_score, ops=ops,
        )

    # --- Leaf base case: at least one side isn't a registered container type, so there
    # is no node-to-node structural correspondence left to exploit -- fall back to
    # comparing each side's own normalized lines directly (Stage 3a's flat primitive).
    filt_a = [(line_no, text) for line_no, text in lines_a if node_a.start_point[0] <= line_no <= node_a.end_point[0]]
    filt_b = [(line_no, text) for line_no, text in lines_b if node_b.start_point[0] <= line_no <= node_b.end_point[0]]
    seq_a = [text for _, text in filt_a]
    seq_b = [text for _, text in filt_b]

    if len(seq_a) <= 1 and len(seq_b) <= 1:
        return None

    scores = compute_score_tables_cached(seq_a, seq_b, cache, model_id, match_midpoint, max_span_lines)
    leaf = align_with_scores(seq_a, seq_b, scores, gap_penalty, span_merge_penalty)

    ops = []
    for op in leaf.ops:
        a_range_op = _leaf_node_range(line_offsets_a, filt_a, op.a_start, op.a_end) if op.a_end > op.a_start else None
        b_range_op = _leaf_node_range(line_offsets_b, filt_b, op.b_start, op.b_end) if op.b_end > op.b_start else None
        ops.append(
            HierarchicalOp(
                kind=op.kind, score=op.score, a=a_range_op, b=b_range_op,
                a_lines=op.a_lines, b_lines=op.b_lines, children=None,
            )
        )
    return HierarchicalAlignment(
        a=a_range, b=b_range, is_leaf=True,
        raw_score=leaf.raw_score, normalized_score=leaf.normalized_score, ops=ops,
    )


def align_functions(
    source_a: str,
    source_b: str,
    cache: EmbeddingCache,
    model_id: str = DEFAULT_MODEL_ID,
    gap_penalty: float = DEFAULT_GAP_PENALTY,
    span_merge_penalty: float = DEFAULT_SPAN_MERGE_PENALTY,
    match_midpoint: float | None = None,
    max_span_lines: int = DEFAULT_MAX_SPAN_LINES,
) -> HierarchicalAlignment:
    """Top-level entry point -- given two standalone function-source strings (the shape
    of CorpusEntry.vulnerable_function/.patched_function), produces one full
    hierarchical alignment tree. `cache` is caller-owned: pass the SAME instance across
    multiple calls (e.g. one candidate vs. vulnerable_function, then vs.
    patched_function) to get embedding reuse across them.

    The two function nodes themselves are never run through a scored DP -- both sides
    are FUNCTION_NODE_TYPES, which is a passthrough type, so _align_node_pair recurses
    straight into their bodies. Module 7 already knows the two sides correspond (it's
    calling this once per shortlisted candidate against its own corpus entry); it's
    never asking whether they do.
    """
    node_a = _root_function_node(source_a)
    node_b = _root_function_node(source_b)
    source_bytes_a = source_a.encode("utf-8")
    source_bytes_b = source_b.encode("utf-8")
    lines_a = normalize_source_with_lines(source_a)
    lines_b = normalize_source_with_lines(source_b)
    line_offsets_a = _line_byte_offsets(source_a)
    line_offsets_b = _line_byte_offsets(source_b)
    resolved_midpoint = match_midpoint if match_midpoint is not None else get_match_midpoint(model_id)

    required = _collect_required_texts(node_a, source_bytes_a, [text for _, text in lines_a], max_span_lines)
    required |= _collect_required_texts(node_b, source_bytes_b, [text for _, text in lines_b], max_span_lines)
    cache.get_or_encode(model_id, sorted(required))

    result = _align_node_pair(
        node_a, node_b, lines_a, lines_b, line_offsets_a, line_offsets_b,
        source_bytes_a, source_bytes_b, cache, model_id, resolved_midpoint,
        max_span_lines, gap_penalty, span_merge_penalty,
    )
    # Root nodes are always FUNCTION_NODE_TYPES, i.e. always containers -- the
    # leaf-trivial None case can only occur inside recursion, never at the top.
    assert result is not None
    return result


def find_op_at_line(alignment: HierarchicalAlignment, side: Literal["a", "b"], line: int) -> HierarchicalOp | None:
    """Deepest (most specific) op whose NodeRange on `side` contains `line`, walking
    down through .children wherever present. Module 7's read-off-similarity-at-
    diagnostic-line-positions entry point.

    Among sibling ops at one level, prefers the NARROWEST containing range, not simply
    the last one in source order -- a block's opening brace can sit on the same
    physical line as its enclosing header (e.g. `if (cond) {`), so more than one
    sibling's range can legitimately contain a given line; the narrower one is the
    more specific answer."""

    def side_range(op: HierarchicalOp) -> NodeRange | None:
        return op.a if side == "a" else op.b

    candidates = [op for op in alignment.ops if (r := side_range(op)) is not None and r.start_line <= line <= r.end_line]
    if not candidates:
        return None

    best = min(candidates, key=lambda op: side_range(op).end_line - side_range(op).start_line)
    if best.children is not None:
        nested = find_op_at_line(best.children, side, line)
        if nested is not None:
            return nested
    return best
