"""Verification evidence contract shared by region detection modules."""

from provtrail.pipeline.detection.verification import edit_distance
from provtrail.pipeline.models.evidence import EditDistanceEvidence


def test_edit_scoring_uses_the_shared_evidence_contract():
    assert edit_distance.EditDistanceEvidence is EditDistanceEvidence
