"""Import compatibility and optional alignment behavior after verification extraction."""

import json
from pathlib import Path

import pytest

from pipeline.controller import edit_distance as legacy_edit
from pipeline.controller import region_verification as legacy_verification
from pipeline.detection.config import RegionVerifierConfig
from pipeline.detection.verification import aggregation, classification, edit_distance, sequences, verifier
from pipeline.models.boundary import VulnerableRegionPair
from pipeline.models.evidence import EditDistanceEvidence


def test_old_import_paths_reexport_the_canonical_implementations():
    assert legacy_verification.verify_region_pair is verifier.verify_region_pair
    assert legacy_verification.classify_boundary is classification.classify_boundary
    assert legacy_verification.classify_evidence is classification.classify_evidence
    assert legacy_verification.deduplicate_evidence is aggregation.deduplicate_evidence
    assert legacy_verification._ratio is sequences.sequence_similarity
    assert legacy_edit.score_edit_distance is edit_distance.score_edit_distance
    assert legacy_edit.EditDistanceEvidence is EditDistanceEvidence
    assert edit_distance.EditDistanceEvidence is EditDistanceEvidence


@pytest.mark.parametrize("alignment", ["success", "error", "disabled", "not_requested"])
def test_optional_alignment_preserves_attempts_and_error_fallback(monkeypatch, alignment):
    records = json.loads(
        (Path(__file__).parent / "fixtures/region_model_contracts.json").read_text(encoding="utf-8")
    )
    pair = VulnerableRegionPair.from_record(records["payloads"]["region_pair"]["payload"])
    calls = []

    def align(candidate, reference, model_id):
        calls.append(reference.region_id)
        if alignment == "error":
            raise RuntimeError("alignment unavailable")
        return 0.35

    monkeypatch.setattr(verifier, "embedding_local_line_score", align)
    evidence = verifier.verify_region_pair(
        pair.vulnerable_region, pair, retrieval_similarity=0.9,
        config=RegionVerifierConfig(
            include_local_alignment=alignment != "disabled",
            local_alignment_trigger=1.1,
            include_containment_fallback=False,
        ),
        model_id="test-model",
        use_embedding_alignment=alignment != "not_requested",
    )
    attempted = alignment in {"success", "error"}
    assert len(calls) == (2 if attempted else 0)
    assert evidence.comparison.alignment_fallback_used is attempted
    expected_local = None if alignment == "disabled" else 0.35 if alignment == "success" else 1.0
    assert evidence.vulnerable.local_alignment == expected_local
    assert evidence.vulnerable.score == (0.35 if alignment == "success" else 1.0)
    assert evidence.vulnerable.containment_structural == 0.0
    assert evidence.vulnerable.containment_attempted is False
    assert evidence.vulnerable.containment_used is False
