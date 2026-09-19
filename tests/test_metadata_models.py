"""Compatibility and invariants for shared metadata and derived evidence."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from corpus.models.corpus import CorpusEntry
from pipeline.models.boundary import BoundaryEditEvidence, VerificationGates
from pipeline.models.region_retrieval import RegionAggregate, RegionRetrievalMatch
from pipeline.models.retrieval import RetrievalMatch
from pipeline.models.verification import VerificationResult
from shared.metadata import CWE


RECORDS = json.loads((Path(__file__).parent / "fixtures/metadata_records.json").read_text())
MODELS = [CorpusEntry, RetrievalMatch, RegionRetrievalMatch, VerificationResult]


@pytest.mark.parametrize("model", MODELS)
def test_flat_metadata_records_round_trip(model):
    record = RECORDS[model.__name__]
    value = model.model_validate_json(json.dumps(record))
    assert value.advisory.ghsa_id == record["ghsa_id"]
    assert value.origin.file_path == record["file_path"]
    assert value.model_dump(mode="json") == record
    assert json.loads(value.model_dump_json()) == record

    grouped = {
        name: getattr(value, name) for name in model.model_fields
    }
    assert model(**grouped).model_dump(mode="json") == record
    grouped["advisory"] = value.advisory.model_dump()
    grouped["origin"] = value.origin.model_dump()
    assert model(**grouped).model_dump(mode="json") == record


@pytest.mark.parametrize("model", MODELS)
def test_metadata_keeps_required_fields_and_independent_defaults(model):
    record = RECORDS[model.__name__]
    required = ["ghsa_id", "fix_commit_sha", "file_path"]
    if model is CorpusEntry:
        required += ["package_name", "ecosystem", "repo"]
    for field in required:
        with pytest.raises(ValidationError):
            model.model_validate({key: value for key, value in record.items() if key != field})

    first = model.model_validate(record)
    second = model.model_validate(record)
    first.advisory.cwes.append(CWE(cwe_id="CWE-79", name="Cross-site scripting"))
    assert second.advisory.cwes == []
    first.advisory.cve_id = "CVE-changed"
    assert second.advisory.cve_id == record["cve_id"]


def test_derived_values_follow_their_source_after_updates():
    gates = VerificationGates(boundary_identity_gate_passed=True, boundary_rejected=True)
    assert gates.boundary_rejected is False
    gates.boundary_identity_gate_passed = False
    assert gates.model_dump()["boundary_rejected"] is True

    edit = BoundaryEditEvidence(strategy="raw", contrastive_used=True)
    assert edit.contrastive_used is False
    edit.strategy = "contrastive"
    assert edit.model_dump()["contrastive_used"] is True

    aggregate = RegionAggregate(
        pair_id="pair-1", best_similarity=0.9,
        candidate_region_ids=["candidate-1"], support_count=99,
    )
    assert aggregate.support_count == 1
    aggregate.candidate_region_ids.append("candidate-2")
    assert aggregate.model_dump()["support_count"] == 2

    for value, name in [(gates, "boundary_rejected"), (edit, "contrastive_used"),
                        (aggregate, "support_count")]:
        with pytest.raises(AttributeError):
            setattr(value, name, 0)
