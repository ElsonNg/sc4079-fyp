"""Sequence similarity with bounded containment and unchanged-edge trimming."""

from __future__ import annotations

import difflib

from provtrail.pipeline.detection.verification.edit_distance import fuzzy_substring_similarity


def sequence_similarity(left: list[str], right: list[str]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    if left == right:
        return 1.0

    # Large generated/bundled functions commonly differ in only a tiny interior
    # region. Running SequenceMatcher with autojunk disabled over the complete
    # 100k+ token/shape sequences can become effectively quadratic. Peel off the
    # guaranteed identical edges, compare only the changed core, then fold the
    # common elements back into the standard 2*M/(len(a)+len(b)) ratio.
    prefix = 0
    shared_limit = min(len(left), len(right))
    while prefix < shared_limit and left[prefix] == right[prefix]:
        prefix += 1

    suffix = 0
    suffix_limit = shared_limit - prefix
    while suffix < suffix_limit and left[-1 - suffix] == right[-1 - suffix]:
        suffix += 1

    left_end = len(left) - suffix if suffix else len(left)
    right_end = len(right) - suffix if suffix else len(right)
    left_core = left[prefix:left_end]
    right_core = right[prefix:right_end]
    core_total = len(left_core) + len(right_core)
    core_ratio = (
        difflib.SequenceMatcher(
            a=left_core,
            b=right_core,
            autojunk=core_total > 4096,
        ).ratio()
        if core_total
        else 1.0
    )
    common_matches = prefix + suffix
    return (2 * common_matches + core_ratio * core_total) / (len(left) + len(right))


def containment_similarity(
    left: list[str], right: list[str], max_cells: int | None = None
) -> tuple[float, float]:
    """Score the shorter sequence inside the longer, guarded by size coverage."""
    if not left or not right:
        return 0.0, 0.0
    shorter, longer = (left, right) if len(left) <= len(right) else (right, left)
    coverage = len(shorter) / len(longer)
    if max_cells is not None and len(shorter) * len(longer) > max_cells:
        return 0.0, coverage
    return fuzzy_substring_similarity(shorter, longer), coverage
