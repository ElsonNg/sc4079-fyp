"""Contracts for the components coordinated by RegionDetector."""

import json
from pathlib import Path

import pytest

from provtrail.pipeline.detection.hashing import build_hash_result
from provtrail.pipeline.detection.lineage import lineage_confidence
from provtrail.pipeline.detection.retrieval import aggregate_retrieval_matches
from provtrail.pipeline.models.boundary import VulnerableRegionPair
from provtrail.pipeline.models.hashing import HashMatch
from provtrail.pipeline.models.region_retrieval import RegionRetrievalMatch


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


@pytest.mark.parametrize("exact_side", ["vulnerable", "patched"])
def test_exact_hash_resolves_shared_abstracted_fix_sides(exact_side):
    match = HashMatch.from_record(PAYLOADS["hash_match"]["payload"])
    match = match.model_copy(update={"lineage_id": "lineage", "fix_boundary_id": "fix-a"})
    abstracted = [match.model_copy(update={"match_type": "abstracted", "side": side})
                  for side in ("vulnerable", "patched")]
    exact = match.model_copy(update={"side": exact_side, "match_type": "exact"})
    for matches in ([*abstracted, exact], [exact, *reversed(abstracted)]):
        result = build_hash_result(matches, "candidate")
        state = result.vulnerability_states[0]
        assert state.status == exact_side
        assert state.abstention_reason is None
        assert not state.support.contradictions
        assert len(result.hash_matches) == 3
        assert result.priority == ("automatic_vulnerability" if exact_side == "vulnerable" else "informational_lineage")


def test_shared_abstracted_hash_is_ambiguous_without_exact_evidence():
    match = HashMatch.from_record(PAYLOADS["hash_match"]["payload"])
    match = match.model_copy(update={"lineage_id": "lineage", "fix_boundary_id": "fix-a", "match_type": "abstracted"})
    result = build_hash_result([match.model_copy(update={"side": side})
                               for side in ("vulnerable", "patched")], "candidate")
    state = result.vulnerability_states[0]
    assert state.status == "uncertain"
    assert state.abstention_reason == "HASH_SIDE_AMBIGUOUS"
    assert not state.support.contradictions
    assert result.priority == "manual_review"


@pytest.mark.parametrize("score,expected", [
    (0.549, "none"), (0.55, "low"), (0.679, "low"),
    (0.68, "medium"), (0.819, "medium"), (0.82, "high"),
])
def test_lineage_confidence_preserves_threshold_boundaries(score, expected):
    assert lineage_confidence(score) == expected
