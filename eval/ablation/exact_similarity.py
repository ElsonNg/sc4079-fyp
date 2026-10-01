"""Exact acceleration of the frozen best-substring Levenshtein scorer.

No thresholds, edit costs, tokenization, candidate limits or score rounding are
changed. Uses KMP for exact substrings and Myers bit vectors for fuzzy matches:
https://doi.org/10.1145/316542.316550

Python's arbitrary-precision integer operations process many DP cells in native
code at once. This remains exact semi-global alignment, not a heuristic or a
bounded search. It is an evaluation adapter, leaving the frozen source intact.
"""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import patch


def _contains(query: list[str], candidate: list[str]) -> bool:
    """Linear-time exact contiguous token match; callers ensure nonempty query."""
    if len(query) > len(candidate):
        return False
    if query == candidate:
        return True
    prefix = [0] * len(query)
    matched = 0
    for i in range(1, len(query)):
        while matched and query[i] != query[matched]:
            matched = prefix[matched - 1]
        if query[i] == query[matched]:
            matched += 1
        prefix[i] = matched
    matched = 0
    for token in candidate:
        while matched and token != query[matched]:
            matched = prefix[matched - 1]
        if token == query[matched]:
            matched += 1
        if matched == len(query):
            return True
    return False


def fuzzy_substring_similarity(query: list[str], candidate: list[str]) -> float:
    """Same result as the frozen DP: max(0, 1 - min(last_row) / len(query)).

    The original DP has D[0,j]=0 (free candidate prefix) and D[i,0]=i.
    Accordingly, the shifted positive bit vector receives a ZERO low bit.
    Inserting the usual global-alignment carry of one would change semantics.
    Taking the minimum score over text endpoints also allows a free suffix.
    """
    if not query or not candidate:
        return 0.0
    if _contains(query, candidate):
        return 1.0
    length = len(query)
    equal_masks: dict[str, int] = {}
    for i, token in enumerate(query):
        equal_masks[token] = equal_masks.get(token, 0) | (1 << i)
    mask = (1 << length) - 1
    high = 1 << (length - 1)
    positive = mask
    negative = 0
    score = best = length
    for token in candidate:
        equal = equal_masks.get(token, 0)
        vertical = equal | negative
        horizontal = (((equal & positive) + positive) ^ positive) | equal
        positive_horizontal = negative | ~(horizontal | positive)
        negative_horizontal = positive & horizontal
        score += bool(positive_horizontal & high) - bool(negative_horizontal & high)
        if score < best:
            best = score
            if best == 0:
                return 1.0
        positive_horizontal = (positive_horizontal << 1) & mask
        negative_horizontal = (negative_horizontal << 1) & mask
        positive = (negative_horizontal | ~(vertical | positive_horizontal)) & mask
        negative = positive_horizontal & vertical
    return max(0.0, 1.0 - best / length)


@contextmanager
def exact_backend():
    """Accelerate patch-local edit scoring and restore the original on exit."""
    from provtrail.pipeline.detection.verification import edit_distance

    with patch.object(edit_distance, "fuzzy_substring_similarity", fuzzy_substring_similarity):
        yield
