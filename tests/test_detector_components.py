"""Contracts for the components coordinated by RegionDetector."""

import json
from pathlib import Path

import pytest

from pipeline.detection.hashing import build_hash_result
from pipeline.detection.lineage import lineage_confidence
from pipeline.detection.retrieval import aggregate_retrieval_matches
from pipeline.models.boundary import VulnerableRegionPair
from pipeline.models.hashing import HashMatch
from pipeline.models.region_retrieval import RegionRetrievalMatch


PAYLOADS = json.loads(
    (Path(__file__).parent / "fixtures" / "region_model_contracts.json").read_text(encoding="utf-8")
)["payloads"]


def test_hash_result_keeps_aliases_and_contradictions_scoped_to_each_fix():
    match = HashMatch.from_record(PAYLOADS["hash_match"]["payload"])
    match = match.model_copy(update={
        "lineage_id": "lineage", "fix_boundary_id": "fix-a",
        "advisories": [match.advisory],
    })
    patched = match.model_copy(update={"side": "patched"})
    later = match.model_copy(update={"fix_boundary_id": "fix-b"})

    result = build_hash_result([match, patched, later], "candidate")

    assert result.priority == "automatic_vulnerability"
    assert result.hash_match_types == ["exact"]
    assert result.candidate_region_count == result.retrieval_match_count == 0
    assert len(result.lineages) == 1
    assert result.lineages[0].associated_advisories == [match.advisory]
    assert [(state.boundary.fix_boundary_id, state.status) for state in result.vulnerability_states] == [
        ("fix-a", "uncertain"), ("fix-b", "vulnerable"),
    ]
    assert result.vulnerability_states[0].abstention_reason == "CONTRADICTORY_EVIDENCE"
    assert not result.vulnerability_states[1].support.contradictions
    assert [(item.package, item.status) for item in result.package_applicabilities] == [
        ("fixture", "unknown"),
    ]


def test_retrieval_ranks_pairs_before_limiting_and_counts_all_support():
    pair = VulnerableRegionPair.from_record(PAYLOADS["region_pair"]["payload"])
    pairs = {key: pair.model_copy(update={"pair_id": key}) for key in ("a", "b", "c")}
    saved = PAYLOADS["vulnerable"]["payload"]["aggregates"][0]["top_matches"][0]
    match = RegionRetrievalMatch.model_validate(saved)
    matches = [
        match.model_copy(update={"pair_id": "b", "candidate_region_id": f"region-{i}"})
        for i in range(7)
    ]
    matches += [match.model_copy(update={"pair_id": "a", "similarity": 0.99})]
    matches += [match.model_copy(update={"pair_id": "c"})]

    aggregates = aggregate_retrieval_matches(matches, pairs, limit=2)

    assert [item.pair_id for item in aggregates] == ["a", "b"]
    assert aggregates[1].support_count == 7
    assert len(aggregates[1].top_matches) == 5
    assert [item.candidate_region_id for item in aggregates[1].top_matches] == [
        f"region-{i}" for i in range(5)
    ]
    assert aggregate_retrieval_matches(matches, pairs, limit=0) == []
    assert aggregate_retrieval_matches([], pairs, limit=2) == []


@pytest.mark.parametrize("score,expected", [
    (0.549, "none"), (0.55, "low"), (0.679, "low"),
    (0.68, "medium"), (0.819, "medium"), (0.82, "high"),
])
def test_lineage_confidence_preserves_threshold_boundaries(score, expected):
    assert lineage_confidence(score) == expected
