from dataclasses import dataclass

import numpy as np

from pipeline.controller import embedding
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.models.alignment import Alignment, AlignmentOp

# Bounded span window (k=2-3) for 1:2/2:1/1:3/3:1 merge candidates -- a build plan
# requirement, not tunable in the sense of "try k=4"; unbounded span alignment was
# explicitly ruled out in research as reintroducing pooling-dilution at a smaller scale.
DEFAULT_MAX_SPAN_LINES = 3

# A model's raw cosine similarity for "genuinely unrelated" short code lines does not sit
# at a fixed absolute value -- it's a property of that embedding model's geometry, not of
# the code. Measured directly: qwen3-embedding-0.6b's unrelated-line band sits at
# ~0.18-0.28, but embeddinggemma-300m's sits at ~0.22-0.38 -- no single hand-picked
# constant serves both, and treating one model's calibration as a global default silently
# breaks on any other model (confirmed: it produced negative-similarity line pairs scoring
# as "matches" on embeddinggemma-300m). get_match_midpoint() calibrates this per model
# instead, once, from a small fixed probe set -- not per alignment call, which would make
# scores incomparable across calls (module 6 runs this on 2-4-line AST-sibling sequences,
# too small for any per-call statistic to mean anything; module 7 thresholds
# verification_score with fixed cutoffs across every candidate and corpus entry, which
# requires one stable scale per model, not a floating one).
_UNRELATED_PROBES = [
    ("for (let i = 0; i < orders.length; i++)", "return total;"),
    ("if (balance < amount) { throw new Error('insufficient'); }", "const year = date.getFullYear();"),
    ("receiver.balance = receiver.balance + amount;", "const day = String(date.getDate()).padStart(2, '0');"),
    ("return receiver.balance;", "return `${year}-${month}-${day}`;"),
]

# Deliberately similar-but-reworded lines (same statement shape, renamed identifiers) --
# the other end of the band the midpoint needs to sit between.
_RELATED_PROBES = [
    ("sender.balance = balance - amount;", "from.balance = bal - amt;"),
    ("let balance = sender.balance;", "let bal = from.balance;"),
    ("return receiver.balance;", "return to.balance;"),
]

_match_midpoint_cache: dict[str, float] = {}


def get_match_midpoint(model_id: str = DEFAULT_MODEL_ID) -> float:
    """The cosine value that separates "genuinely unrelated" from "genuinely related"
    short code lines, for this specific model -- the midpoint between the mean cosine of
    _UNRELATED_PROBES and the mean cosine of _RELATED_PROBES, both embedded in one batched
    call. Computed once per model_id and cached in-process (not persisted to disk -- it's
    cheap to recompute, deterministic, and depends only on the model, never on the corpus
    or a specific alignment call, so there's no staleness/invalidation question the way
    there is for the corpus-dependent FAISS index)."""
    if model_id not in _match_midpoint_cache:
        pairs = _UNRELATED_PROBES + _RELATED_PROBES
        texts = [text for pair in pairs for text in pair]
        vectors = embedding.encode(model_id, texts)
        cosines = [float(np.dot(vectors[2 * i], vectors[2 * i + 1])) for i in range(len(pairs))]
        unrelated_mean = float(np.mean(cosines[: len(_UNRELATED_PROBES)]))
        related_mean = float(np.mean(cosines[len(_UNRELATED_PROBES) :]))
        _match_midpoint_cache[model_id] = (unrelated_mean + related_mean) / 2
    return _match_midpoint_cache[model_id]


# In shifted-score units (score = cosine - match_midpoint), not raw cosine -- this is the
# part that *does* transfer across models, since match_midpoint already absorbs each
# model's absolute similarity scale. 2*gap_penalty must beat forcing a match on the worst
# observed unrelated pair (qwen3-embedding-0.6b: cosine 0.276 -> shifted -0.174, the
# tightest margin measured): 2*(-0.07) = -0.14 > -0.174, margin 0.034.
DEFAULT_GAP_PENALTY = -0.07

# The process_orders merge (shifted +0.408 on qwen3-embedding-0.6b) must beat the best
# competing two-step decomposition -- gapping the split's second line and matching the
# first half directly ("const result = total;", shifted +0.374, deceptively high via the
# shared word "total"): 0.408 - 0.05 = 0.358 > -0.07 + 0.374 = 0.304, margin 0.054.
DEFAULT_SPAN_MERGE_PENALTY = -0.05


@dataclass
class SpanScoreTables:
    """Transient in-process scoring state for one align() call -- shifted-cosine score
    matrices, not a returned/serialized result (mirrors RetrievalIndex/HashIndex)."""

    match: np.ndarray
    b_merge_2: np.ndarray | None
    b_merge_3: np.ndarray | None
    a_merge_2: np.ndarray | None
    a_merge_3: np.ndarray | None


def _generate_spans(lines: list[str], max_span_lines: int) -> dict[tuple[int, int], str]:
    """All contiguous spans of length 1..max_span_lines in `lines`, as {(start, end): text},
    end exclusive. Joined with " " -- matches retrieval.py's _normalized_text convention."""
    spans: dict[tuple[int, int], str] = {}
    n = len(lines)
    for length in range(1, max_span_lines + 1):
        if length > n:
            break
        for start in range(0, n - length + 1):
            end = start + length
            spans[(start, end)] = " ".join(lines[start:end])
    return spans


def compute_score_tables(
    seq_a: list[str],
    seq_b: list[str],
    model_id: str = DEFAULT_MODEL_ID,
    max_span_lines: int = DEFAULT_MAX_SPAN_LINES,
    match_midpoint: float | None = None,
) -> SpanScoreTables:
    """Embeds every single line and every bounded joined span from both sequences in one
    batched encode() call, then assembles the DP's score matrices via matmul -- vectors are
    already L2-normalized (encode()'s contract), so `@` is cosine similarity directly, same
    as retrieval.py/hashing.py already rely on. Only one-line-vs-2/3-line-span combinations
    are computed (never span-vs-span), matching the build plan's exact wording.

    match_midpoint defaults to get_match_midpoint(model_id) -- the per-model-calibrated
    value -- when not given explicitly."""
    if match_midpoint is None:
        match_midpoint = get_match_midpoint(model_id)
    m, n = len(seq_a), len(seq_b)
    spans_a = _generate_spans(seq_a, max_span_lines)
    spans_b = _generate_spans(seq_b, max_span_lines)

    all_texts = sorted(set(spans_a.values()) | set(spans_b.values()))
    if all_texts:
        vectors = embedding.encode(model_id, all_texts)
        dim = vectors.shape[1]
    else:
        dim = embedding.get_model(model_id).get_embedding_dimension()
        vectors = np.empty((0, dim), dtype=np.float32)
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


def align_with_scores(
    seq_a: list[str],
    seq_b: list[str],
    scores: SpanScoreTables,
    gap_penalty: float = DEFAULT_GAP_PENALTY,
    span_merge_penalty: float = DEFAULT_SPAN_MERGE_PENALTY,
) -> Alignment:
    """Pure DP -- no embedding calls, no model, no I/O. Global (Needleman-Wunsch) alignment:
    every line on both sides is accounted for by exactly one op, no free prefix/suffix,
    order-preserving (no move-detection). This is the module-6 reuse point: hierarchical
    decomposition builds its own SpanScoreTables per AST-sibling-sequence call and hands
    them straight to this function."""
    m, n = len(seq_a), len(seq_b)

    dp = np.zeros((m + 1, n + 1), dtype=np.float64)
    back: list[list[tuple[str, int, int] | None]] = [[None] * (n + 1) for _ in range(m + 1)]

    for i in range(1, m + 1):
        dp[i][0] = i * gap_penalty
        back[i][0] = ("gap", 1, 0)
    for j in range(1, n + 1):
        dp[0][j] = j * gap_penalty
        back[0][j] = ("gap", 0, 1)

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            # Fixed priority order -- also the tie-break rule, via max()'s
            # first-of-equal-maxima semantics.
            #
            # Both match and span_merge candidates are gated on a positive raw
            # (pre-penalty) score -- the underlying content must actually be more similar
            # than dissimilar (cosine > match_midpoint), not just merely-supported by
            # arithmetic. Without this gate, any candidate only has to beat
            # gap_penalty*(N+1) (the honest all-gap decomposition covering the same net
            # advance) to win -- and for a single 1:1 match, N+1=2, so a barely-negative
            # match can still beat 2*gap_penalty on arithmetic alone (confirmed in
            # practice: embeddinggemma-300m's weaker unrelated/related separation produced
            # exactly this on genuinely unrelated lines before this gate existed). Wider
            # merges have an even looser bar (N+1 gaps avoided at once), which is the
            # span_merge version of the same defect. Gating both turns "match"/"span_merge"
            # back into genuine correspondence signals; when nothing qualifies, gaps win by
            # default, which is correct when there genuinely isn't a match.
            candidates: list[tuple[float, str, int, int]] = []
            match_raw = scores.match[i - 1, j - 1]
            if match_raw > 0:
                candidates.append((dp[i - 1][j - 1] + match_raw, "match", 1, 1))
            if j >= 2 and scores.b_merge_2 is not None:
                raw = scores.b_merge_2[i - 1, j - 2]
                if raw > 0:
                    candidates.append((dp[i - 1][j - 2] + raw + span_merge_penalty, "span_merge", 1, 2))
            if i >= 2 and scores.a_merge_2 is not None:
                raw = scores.a_merge_2[i - 2, j - 1]
                if raw > 0:
                    candidates.append((dp[i - 2][j - 1] + raw + span_merge_penalty, "span_merge", 2, 1))
            if j >= 3 and scores.b_merge_3 is not None:
                raw = scores.b_merge_3[i - 1, j - 3]
                if raw > 0:
                    candidates.append((dp[i - 1][j - 3] + raw + span_merge_penalty, "span_merge", 1, 3))
            if i >= 3 and scores.a_merge_3 is not None:
                raw = scores.a_merge_3[i - 3, j - 1]
                if raw > 0:
                    candidates.append((dp[i - 3][j - 1] + raw + span_merge_penalty, "span_merge", 3, 1))
            candidates.append((dp[i - 1][j] + gap_penalty, "gap", 1, 0))
            candidates.append((dp[i][j - 1] + gap_penalty, "gap", 0, 1))

            best_score, best_kind, best_di, best_dj = max(candidates, key=lambda c: c[0])
            dp[i][j] = best_score
            back[i][j] = (best_kind, best_di, best_dj)

    ops: list[AlignmentOp] = []
    i, j = m, n
    while (i, j) != (0, 0):
        kind, di, dj = back[i][j]
        if kind == "match":
            op = AlignmentOp(
                kind="match",
                a_start=i - 1, a_end=i, b_start=j - 1, b_end=j,
                a_lines=[seq_a[i - 1]], b_lines=[seq_b[j - 1]],
                score=float(scores.match[i - 1, j - 1]),
            )
        elif kind == "gap":
            if di == 1:
                op = AlignmentOp(
                    kind="gap", a_start=i - 1, a_end=i, b_start=j, b_end=j,
                    a_lines=[seq_a[i - 1]], b_lines=[], score=gap_penalty,
                )
            else:
                op = AlignmentOp(
                    kind="gap", a_start=i, a_end=i, b_start=j - 1, b_end=j,
                    a_lines=[], b_lines=[seq_b[j - 1]], score=gap_penalty,
                )
        else:  # span_merge
            if di == 1 and dj == 2:
                raw = float(scores.b_merge_2[i - 1, j - 2])
                op = AlignmentOp(
                    kind="span_merge", a_start=i - 1, a_end=i, b_start=j - 2, b_end=j,
                    a_lines=[seq_a[i - 1]], b_lines=seq_b[j - 2 : j], score=raw + span_merge_penalty,
                )
            elif di == 2 and dj == 1:
                raw = float(scores.a_merge_2[i - 2, j - 1])
                op = AlignmentOp(
                    kind="span_merge", a_start=i - 2, a_end=i, b_start=j - 1, b_end=j,
                    a_lines=seq_a[i - 2 : i], b_lines=[seq_b[j - 1]], score=raw + span_merge_penalty,
                )
            elif di == 1 and dj == 3:
                raw = float(scores.b_merge_3[i - 1, j - 3])
                op = AlignmentOp(
                    kind="span_merge", a_start=i - 1, a_end=i, b_start=j - 3, b_end=j,
                    a_lines=[seq_a[i - 1]], b_lines=seq_b[j - 3 : j], score=raw + span_merge_penalty,
                )
            else:  # di == 3 and dj == 1
                raw = float(scores.a_merge_3[i - 3, j - 1])
                op = AlignmentOp(
                    kind="span_merge", a_start=i - 3, a_end=i, b_start=j - 1, b_end=j,
                    a_lines=seq_a[i - 3 : i], b_lines=[seq_b[j - 1]], score=raw + span_merge_penalty,
                )
        ops.append(op)
        i -= di
        j -= dj

    ops.reverse()
    raw_score = float(dp[m][n])
    normalized_score = raw_score / max(m, n) if max(m, n) > 0 else 1.0

    return Alignment(ops=ops, raw_score=raw_score, normalized_score=normalized_score, a_length=m, b_length=n)


def align(
    seq_a: list[str],
    seq_b: list[str],
    model_id: str = DEFAULT_MODEL_ID,
    gap_penalty: float = DEFAULT_GAP_PENALTY,
    span_merge_penalty: float = DEFAULT_SPAN_MERGE_PENALTY,
    match_midpoint: float | None = None,
    max_span_lines: int = DEFAULT_MAX_SPAN_LINES,
) -> Alignment:
    scores = compute_score_tables(
        seq_a, seq_b, model_id=model_id, max_span_lines=max_span_lines, match_midpoint=match_midpoint
    )
    return align_with_scores(seq_a, seq_b, scores, gap_penalty=gap_penalty, span_merge_penalty=span_merge_penalty)
