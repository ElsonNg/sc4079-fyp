"""Evaluation adapters for region eligibility; scanner defaults stay unchanged."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from unittest.mock import patch

import faiss
import numpy as np

TYPES = ("changed", "block", "context", "function")
ARMS = {
    "all_types": TYPES,
    **{f"no_{kind}": tuple(t for t in TYPES if t != kind) for kind in TYPES},
    "function_only": ("function",),
}


class EligibleHNSW:
    """Restrict eligible results during search, retaining the frozen HNSW graph.

    IDs remain the original vector row IDs, so reference metadata and complete
    function pairs stay available to verification. Excluded rows may be traversed
    by HNSW but cannot occupy a result slot. This is an eligibility experiment,
    not a measurement of the memory footprint of a rebuilt smaller index.
    """

    def __init__(self, index, eligible):
        self.index = index
        self.rows = np.asarray(eligible, dtype=np.int64)
        if not len(self.rows):
            raise ValueError("Region arm has no searchable reference vectors")
        self.selector = faiss.IDSelectorBatch(self.rows)

    def search(self, vectors, k):
        params = faiss.SearchParametersHNSW()
        params.efSearch = self.index.hnsw.efSearch
        params.sel = self.selector
        return self.index.search(vectors, k, params=params)


def eligible_rows(region_index, allowed):
    pairs = {p.pair_id: p for p in region_index.pairs}
    return [i for i, pid in enumerate(region_index.indexed_pair_ids)
            if pairs[pid].vulnerable_region.granularity in allowed]


@contextmanager
def region_mode(detector, allowed):
    """Apply candidate eligibility before the cap and reference eligibility at search.

    The extractor counts only accepted regions toward its existing cap. Its
    order, informativeness gate and function-region insertion stay unchanged.
    The full function pairs remain available for diagnostic-line computation,
    including the no_function arm. Process-local and deliberately single-threaded.
    """
    from provtrail.pipeline.controller import region_detection as controller
    from provtrail.pipeline.controller import region_extraction as extraction

    allowed = frozenset(allowed)
    if not allowed or allowed - set(TYPES):
        raise ValueError("Unknown or empty region types")
    original_index = detector.region_index
    original_enumerate = controller.enumerate_candidate_regions
    original_gate = extraction.candidate_region_is_informative

    def enumerate_allowed(*args, **kwargs):
        if allowed == frozenset(TYPES):
            return original_enumerate(*args, **kwargs)
        # Only the function is eligible here; stop the target loop immediately.
        if allowed == {"function"}:
            kwargs["max_regions"] = 1
        cap = kwargs.get("max_regions", 96)
        # The original loop reserves one slot for the function. When it is
        # excluded, that slot belongs to another eligible candidate instead.
        if "function" not in allowed:
            kwargs["max_regions"] = cap + 1
        with patch.object(extraction, "candidate_region_is_informative",
                          lambda r: r.granularity in allowed and original_gate(r)):
            return original_enumerate(*args, **kwargs)[:cap]

    try:
        if allowed != frozenset(TYPES):
            detector.region_index = replace(
                original_index,
                index=EligibleHNSW(original_index.index, eligible_rows(original_index, allowed)),
            )
        with patch.object(controller, "enumerate_candidate_regions", enumerate_allowed):
            yield
    finally:
        detector.region_index = original_index
