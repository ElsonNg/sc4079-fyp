from pipeline.controller.evaluation import vulnerable_origin_stages, vulnerable_origin_summary


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
