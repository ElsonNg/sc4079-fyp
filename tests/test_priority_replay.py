import json
from pathlib import Path

import pytest

from eval.ablation.priority_policy import experimental_priority
from eval.ablation.run_priority_replay import replay_row, transition_counts
from provtrail.pipeline.detection.priority import derive_priority
from provtrail.pipeline.models.boundary import (
    BoundaryIdentity, BoundaryEditEvidence, BoundarySupport, VerificationGates, VulnerabilityState,
)
from provtrail.pipeline.models.hashing import HashMatch
from provtrail.pipeline.models.lineage import LineageAttribution
from provtrail.pipeline.models.result import RegionDetectionResult


def state(status="uncertain", **kwargs):
    return VulnerabilityState(status=status, boundary=BoundaryIdentity(
        lineage_id="family", fix_boundary_id=status, fix_commit_sha="fix"), **kwargs)


def result(*states):
    value = RegionDetectionResult(candidate_region_count=2, retrieval_match_count=2,
        lineages=[LineageAttribution(lineage_id="family", confidence="high", score=.9,
                                   repo="fixture/repo", file_path="fixture.js")],
        vulnerability_states=list(states))
    value.priority = derive_priority(value.lineages, value.vulnerability_states, [])
    return value


def test_general_correspondence_cannot_obscure_verified_patch_and_states_stay_intact():
    value = result(state("patched"), state(abstention_reason="E_SIDE_WEAK",
                   gates=VerificationGates(token_gate_passed=True),
                   edit=BoundaryEditEvidence(vulnerable=.5, patched=.4)))
    before = value.model_dump(mode="json")
    assert value.priority == "manual_review"
    assert experimental_priority(value, .9) == "informational_lineage"
    assert value.model_dump(mode="json") == before


@pytest.mark.parametrize("identity,score,expected", [
    (True, .9, "manual_review"), (True, .899, "informational_lineage"),
    (False, 1., "informational_lineage"), (None, 1., "informational_lineage"),
])
def test_patch_anchor_requires_positive_identity_and_existing_threshold(identity, score, expected):
    value = result(state("patched"), state(abstention_reason="E_MARGIN_AMBIGUOUS",
        gates=VerificationGates(token_gate_passed=True, function_identity_state="unknown"),
        edit=BoundaryEditEvidence(patched=score, vulnerable=.92, patched_anchor_has_identity=identity)))
    assert experimental_priority(value, .9) == expected


@pytest.mark.parametrize("reason", ["CONTRADICTORY_EVIDENCE", "CONTRASTIVE_CONFLICT", "HASH_SIDE_AMBIGUOUS"])
def test_conflicts_still_require_review(reason):
    value = result(state("patched"), state(abstention_reason=reason,
        gates=VerificationGates(token_gate_passed=True)))
    assert experimental_priority(value, .9) == "manual_review"


def test_actual_contradiction_is_preserved_without_reason_code():
    value = result(state("patched"), state(gates=VerificationGates(token_gate_passed=True),
        support=BoundarySupport(contradictions=["conflicting verified sides"])))
    assert experimental_priority(value, .9) == "manual_review"


def test_verified_vulnerable_finding_wins_over_patch_and_uncertainty():
    value = result(state("patched"), state("vulnerable"), state())
    assert experimental_priority(value, .9) == "automatic_vulnerability"


def test_without_verified_patch_uncertain_case_remains_review():
    value = result(state(gates=VerificationGates(token_gate_passed=True)))
    assert experimental_priority(value, .9) == "manual_review"


def test_hash_aggregation_keeps_existing_decision():
    payloads = json.loads((Path(__file__).parent / "fixtures/region_model_contracts.json").read_text(encoding="utf-8"))["payloads"]
    value = result(state("patched"), state(gates=VerificationGates(token_gate_passed=True)))
    value.hash_matches = [HashMatch.from_record(payloads["hash_match"]["payload"])]
    assert value.priority == "manual_review"
    assert experimental_priority(value, .9) == "manual_review"


def test_replay_counts_vulnerable_release_as_risk_even_with_unchanged_recall():
    value = result(state("patched"), state(gates=VerificationGates(token_gate_passed=True)))
    row = dict(result=value.model_dump(mode="json"), priority=value.priority, abstained=True,
               hash_path=False, expected_status="flagged", correct_origin_automatic=False,
               patched_false_positive=False)
    new, protected = replay_row(row, .9)
    assert new["correct_origin_automatic"] is False
    assert new["priority"] == "informational_lineage"
    assert row["priority"] == "manual_review"
    assert transition_counts([(row, new, protected)])["vulnerable_released"] == 1
