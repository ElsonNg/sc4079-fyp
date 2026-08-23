from pipeline.controller.evaluation import vulnerable_origin_stages, vulnerable_origin_summary
from eval.metrics import classification_outcome, retrieval_metrics, verification_metrics


EXPECTED = ("GHSA-test", "fix-test", "lib/request.js", "request")


def test_vulnerable_origin_metrics_track_each_evidence_stage():
    pairs = {
        "pair-test": {
            "ghsa_id": "GHSA-test", "fix_commit_sha": "fix-test",
            "file_path": "lib/request.js", "function_name": "request",
            "lineage_id": "lineage-test", "fix_boundary_id": "boundary-test",
        }
    }
    result = {
        "priority": "automatic_vulnerability",
        "aggregates": [{"pair_id": "pair-test"}],
        "evidence": [{"pair_id": "pair-test"}],
        "lineages": [{"lineage_id": "lineage-test", "confidence": "low", "score": 0.6}],
        "vulnerability_states": [{
            "lineage_id": "lineage-test", "fix_boundary_id": "boundary-test",
            "status": "vulnerable",
        }],
    }

    stages = vulnerable_origin_stages(result, expected=EXPECTED, pairs=pairs)

    assert stages == {
        "expected_aggregate_rank": 1,
        "origin_shortlisted": True,
        "origin_verified": True,
        "origin_retained": True,
        "origin_visible": True,
        "origin_primary": True,
        "origin_automatically_flagged": True,
    }


def test_vulnerable_origin_summary_keeps_counts_and_rates_separate():
    summary = vulnerable_origin_summary([
        {"origin_shortlisted": True, "origin_verified": True, "origin_retained": True,
         "origin_visible": True, "origin_primary": False, "origin_automatically_flagged": False},
        {"origin_shortlisted": False, "origin_verified": False, "origin_retained": False,
         "origin_visible": False, "origin_primary": False, "origin_automatically_flagged": False},
    ])

    assert summary["origin_candidate_count"] == 2
    assert summary["origin_shortlisted_count"] == 1
    assert summary["origin_visible_rate"] == 0.5
    assert summary["origin_primary_rate"] == 0.0


def test_vulnerable_origin_accepts_expected_advisory_alias_on_same_boundary():
    pairs = {
        "pair-1": {
            "ghsa_id": "GHSA-representative", "fix_commit_sha": EXPECTED[1],
            "file_path": EXPECTED[2], "function_name": EXPECTED[3],
            "lineage_id": "lineage-1", "fix_boundary_id": "boundary-1",
            "advisories": [{"ghsa_id": EXPECTED[0]}],
        }
    }
    result = {
        "priority": "manual_review",
        "aggregates": [{"pair_id": "pair-1"}],
        "evidence": [{"pair_id": "pair-1"}],
        "lineages": [{"lineage_id": "lineage-1", "confidence": "low", "score": 0.6}],
        "vulnerability_states": [],
    }

    stages = vulnerable_origin_stages(result, expected=EXPECTED, pairs=pairs)

    assert stages["origin_shortlisted"] is True
    assert stages["origin_verified"] is True
    assert stages["origin_visible"] is True


def test_shared_metrics_compute_ranked_retrieval_and_verification_rates():
    rows = [
        {"expected_status": "flagged", "outcome": "true_positive", "retrieval_rank": 1},
        {"expected_status": "flagged", "outcome": "abstained_positive", "retrieval_rank": 6},
        {"expected_status": "cleared", "outcome": "false_positive", "retrieval_rank": None},
        {"expected_status": "cleared", "outcome": "true_negative", "retrieval_rank": 3},
    ]
    retrieval = retrieval_metrics(rows)
    verification = verification_metrics(rows)
    assert retrieval["recall_at_1"] == 0.25
    assert retrieval["recall_at_5"] == 0.5
    assert retrieval["mrr"] == (1.0 + 1 / 6 + 1 / 3) / 4
    assert verification["vulnerable_recall"] == 0.5
    assert verification["vulnerable_recall_including_abstain"] == 1.0
    assert verification["patched_false_positive_rate"] == 0.5
    assert verification["abstention_rate"] == 0.25


def test_shared_outcome_mapping_keeps_abstentions_explicit():
    assert classification_outcome("flagged", "manual_review") == "abstained_positive"
    assert classification_outcome("cleared", "automatic_vulnerability") == "false_positive"
