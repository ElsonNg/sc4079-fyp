"""Compatibility checks against contracts captured before the model split."""

import dataclasses
import hashlib
import importlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from provtrail.pipeline.scanning.cache import fingerprint_config
from provtrail.pipeline.detection.config import RegionDetectorConfig, RegionVerifierConfig
from provtrail.pipeline.models.boundary import VulnerabilityState
from provtrail.pipeline.models.result import RegionDetectionResult
from provtrail.pipeline.models.records import FlatRecordModel

CONTRACTS = json.loads(
    (Path(__file__).parent / "fixtures" / "region_model_contracts.json").read_text(encoding="utf-8")
)
MODEL_MODULES = {
    "region": ("RegionGranularity", "RegionChangeKind", "SourceSpan", "AstRegion", "CandidateRegion"),
    "boundary": (
        "VulnerabilityStatus", "AbstentionReason", "EditStrategy", "SignatureEvidenceState",
        "FunctionIdentityState", "VulnerableRegionPair", "VulnerabilityState",
    ),
    "region_retrieval": ("RegionRetrievalMatch", "RegionAggregate"),
    "evidence": ("ApplicabilityStatus", "RegionVerificationEvidence", "ApplicabilityEvidence", "PackageApplicability"),
    "lineage": ("LineageConfidence", "LineageAttribution"),
    "result": ("FindingPriority", "RegionDetectionResult"),
}
MODELS = {
    name: getattr(importlib.import_module(f"provtrail.pipeline.models.{module}"), name)
    for module, names in MODEL_MODULES.items()
    for name in names
}
MODELS["HashMatch"] = importlib.import_module("provtrail.pipeline.models.hashing").HashMatch


@pytest.mark.parametrize("name,expected", [
    (name, expected) for name, expected in CONTRACTS["schema_hashes"].items()
    if name not in {"VulnerabilityState", "RegionDetectionResult", "VulnerableRegionPair", "RegionVerificationEvidence", "RegionRetrievalMatch", "RegionAggregate"}
])
def test_model_schemas_match_before_refactor(name, expected):
    schema = MODELS[name].model_json_schema()
    encoded = json.dumps(schema, sort_keys=True, separators=(",", ":"))
    assert hashlib.sha256(encoded.encode()).hexdigest() == expected


@pytest.mark.parametrize("case", CONTRACTS["payloads"].values(), ids=CONTRACTS["payloads"])
def test_saved_payloads_deserialize_without_changes(case):
    model = MODELS[case["model"]]
    payload = json.loads(json.dumps(case["payload"]))
    # Older synthetic fixtures supplied counts without their candidate IDs.
    for aggregate in payload.get("aggregates", []):
        aggregate["support_count"] = len(aggregate["candidate_region_ids"])
    if issubclass(model, FlatRecordModel):
        value = model.from_record(payload)
        assert value.to_record() == payload
    else:
        value = model.model_validate_json(json.dumps(payload))
        assert value.model_dump(mode="json") == payload
        assert json.loads(value.model_dump_json()) == payload


def test_configuration_defaults_and_imports_preserve_active_settings():
    from provtrail.pipeline.controller import region_detection, region_retrieval
    from provtrail.pipeline.detection import config
    from provtrail.pipeline.integrations import embedding

    assert region_detection.RegionDetectorConfig is RegionDetectorConfig
    assert region_detection.RegionVerifierConfig is RegionVerifierConfig
    assert embedding.DEFAULT_MODEL_ID == config.DEFAULT_MODEL_ID
    assert region_detection.DEFAULT_MODEL_ID == config.DEFAULT_MODEL_ID
    assert region_retrieval.DEFAULT_REGION_TOP_K == config.DEFAULT_REGION_TOP_K
    assert region_retrieval.DEFAULT_REGION_THRESHOLD == config.DEFAULT_REGION_THRESHOLD
    defaults = dataclasses.asdict(RegionDetectorConfig())
    legacy_defaults = CONTRACTS["detector_defaults"]
    current_defaults = {
        key: value for key, value in legacy_defaults.items()
        if key not in {"same_language_only", "use_embedding_alignment_fallback"}
    }
    current_verifier_defaults = {
        key: value for key, value in CONTRACTS["verifier_defaults"].items()
        if key not in {"include_local_alignment", "local_alignment_trigger"}
    }
    current_defaults["verifier"] = current_verifier_defaults
    assert defaults == current_defaults
    assert dataclasses.asdict(RegionVerifierConfig()) == current_verifier_defaults
    assert fingerprint_config(legacy_defaults) == CONTRACTS["config_fingerprint"]
    assert fingerprint_config(RegionDetectorConfig()) != CONTRACTS["config_fingerprint"]
    for instance, field in [(RegionDetectorConfig(), "model_id"), (RegionVerifierConfig(), "minimum_token_score")]:
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(instance, field, None)


def test_contract_imports_do_not_load_implementations_or_compatibility_facade():
    modules = ["provtrail.pipeline.detection.config", *(f"provtrail.pipeline.models.{name}" for name in MODEL_MODULES)]
    script = (
        "import importlib, sys\n"
        f"for name in {modules!r}: importlib.import_module(name)\n"
        "assert 'provtrail.pipeline.models.regions' not in sys.modules\n"
        "assert not any(name.startswith(('provtrail.pipeline.controller', 'provtrail.corpus.controller')) for name in sys.modules)\n"
        "assert not any(name in sys.modules for name in ('torch', 'faiss', 'sentence_transformers'))\n"
    )
    subprocess.run([sys.executable, "-c", script], check=True, capture_output=True, text=True)


def test_validation_and_mutable_defaults_remain_independent():
    payload = CONTRACTS["payloads"]["uncertain"]["payload"]
    state = dict(payload["vulnerability_states"][0], status="invalid")
    with pytest.raises(ValidationError):
        VulnerabilityState.from_record(state)
    with pytest.raises(ValidationError):
        RegionDetectionResult.model_validate({"priority": "none"})
    first = RegionDetectionResult(candidate_region_count=0, retrieval_match_count=0)
    second = RegionDetectionResult(candidate_region_count=0, retrieval_match_count=0)
    first.hash_match_types.append("exact")
    assert second.hash_match_types == []


@pytest.mark.parametrize("model,fixture,group,field,legacy,value", [
    (MODELS["VulnerableRegionPair"], "region_pair", "advisory", "cve_id", "cve_id", "CVE-2025-12345"),
    (MODELS["HashMatch"], "hash_match", "origin", "file_path", "file_path", "src/renamed.js"),
    (MODELS["VulnerabilityState"], "vulnerable", "gates", "token_gate_passed", "token_gate_passed", True),
    (MODELS["RegionVerificationEvidence"], "vulnerable", "vulnerable", "score", "vulnerable_score", 0.75),
])
def test_grouped_updates_preserve_the_saved_record_contract(model, fixture, group, field, legacy, value):
    record = CONTRACTS["payloads"][fixture]["payload"]
    if model is MODELS["VulnerabilityState"]:
        record = record["vulnerability_states"][0]
    elif model is MODELS["RegionVerificationEvidence"]:
        record = record["evidence"][0]
    original = model.from_record(record)
    changed = original.model_copy(update={
        group: getattr(original, group).model_copy(update={field: value}),
    })
    assert changed.to_record() == {**record, legacy: value}
    assert original.to_record() == record
    assert model.from_record(changed.to_record()) == changed


@pytest.mark.parametrize("field", ["hash_matches", "evidence", "vulnerability_states"])
def test_invalid_result_collections_raise_validation_errors(field):
    with pytest.raises(ValidationError):
        RegionDetectionResult(candidate_region_count=0, retrieval_match_count=0, **{field: None})
