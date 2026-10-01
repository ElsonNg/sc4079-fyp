"""Production wiring, cache compatibility, and revision-aware reporting controls."""
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from provtrail.cli.main import build_parser
from provtrail.cli.commands import scan
from provtrail.pipeline.controller import correspondence_verification as verifier
from provtrail.pipeline.controller.region_detection import RegionDetector
from provtrail.pipeline.controller.hashing import build_hash_index
from provtrail.pipeline.controller.region_extraction import extract_corpus_region_pairs
from provtrail.pipeline.detection.config import RegionDetectorConfig, RegionVerifierConfig
from provtrail.pipeline.detection.revision_relationships import RevisionRelationships, derive_revision_priority
from provtrail.pipeline.models.result import RegionDetectionResult
from provtrail.pipeline.scanning.cache import fingerprint_config
from provtrail.pipeline.scanning.project_context import ProjectEvidenceIndex
from tests.test_priority_relationships import entry, result, state
from tests.test_targeted_correspondence import fixture, CP, CV, V, P


@pytest.mark.parametrize("source,status,priority", [
    (CP, "patched", "informational_lineage"),
    (CV, "vulnerable", "automatic_vulnerability"),
])
def test_default_detector_resolves_saved_uncertainty(source, status, priority):
    value, pairs, _ = fixture(source)
    e = entry(V, P, "guard")
    index = SimpleNamespace(pairs=list(pairs.values()))
    detector = RegionDetector([e], index, build_hash_index([]))
    with patch.object(detector, "_verify_regions", return_value=value.evidence):
        updated = detector.detect(source, "candidate.js", _matches=[])
    assert updated.priority == priority
    assert updated.decision_policy == "expanded_ast_v1"
    assert updated.vulnerability_states[0].status == status
    assert updated.vulnerability_states[0].boundary == value.vulnerability_states[0].boundary
    baseline = RegionDetector([e], index, build_hash_index([]),
        RegionDetectorConfig(include_expanded_correspondence_fallback=False))
    with patch.object(baseline, "_verify_regions", return_value=value.evidence):
        old = baseline.detect(source, "candidate.js", _matches=[])
    assert old.priority == "manual_review" and old.decision_policy == "baseline"


def test_connected_weak_alternative_survives_context_and_json_cache(tmp_path):
    a, b = entry("v0", "v1", "a"), entry("v1", "v2", "b")
    value = result(state(a, "patched"), state(b, "uncertain", abstention_reason="S_FAILED"))
    assert value.priority == "informational_lineage"
    value.decision_policy = "expanded_ast_v1"
    value.priority = derive_revision_priority(value, RevisionRelationships.from_entries([a, b]))
    cached = RegionDetectionResult.model_validate_json(value.model_dump_json())
    assessed = ProjectEvidenceIndex(root=tmp_path).assess(cached, "candidate.js")
    assert assessed.priority == "manual_review"
    assert assessed.vulnerability_states == value.vulnerability_states


@pytest.mark.parametrize("reason", ["CONTRADICTORY_EVIDENCE", "CONTRASTIVE_CONFLICT", "HASH_SIDE_AMBIGUOUS"])
def test_production_fallback_preserves_protected_conflicts(reason):
    value, pairs, graph = fixture()
    value.vulnerability_states[0].abstention_reason = reason
    with patch.object(verifier, "compare_ast") as compare:
        updated, _ = verifier.verify_uncertain_boundaries(value, CP, "javascript", pairs, graph, RegionVerifierConfig())
    compare.assert_not_called()
    assert updated.priority == "manual_review"
    assert updated.vulnerability_states == value.vulnerability_states


def test_hash_path_returns_before_correspondence():
    e = entry(V, P, "guard")
    index = SimpleNamespace(pairs=extract_corpus_region_pairs([e]))
    detector = RegionDetector([e], index, build_hash_index([e]))
    with patch("provtrail.pipeline.controller.region_detection.verify_uncertain_boundaries") as fallback:
        updated = detector.detect(P, "candidate.js")
    fallback.assert_not_called()
    assert updated.hash_matches and updated.decision_policy == "baseline"


def test_expanded_verifier_respects_edit_size_limit():
    value, pairs, _ = fixture(CP)
    e = entry(V, P, "guard")
    detector = RegionDetector([e], SimpleNamespace(pairs=list(pairs.values())),
        build_hash_index([]), RegionDetectorConfig(max_edit_candidate_chars=1))
    with patch.object(detector, "_verify_regions", return_value=value.evidence), \
         patch("provtrail.pipeline.controller.region_detection.verify_uncertain_boundaries") as fallback:
        updated = detector.detect(CP, "candidate.js", _matches=[])
    fallback.assert_not_called()
    assert updated.priority == "manual_review"
    assert updated.vulnerability_states[0].edit.strategy == "not_run"


def test_config_switch_invalidates_cache_identity():
    default = RegionDetectorConfig()
    baseline = replace(default, include_expanded_correspondence_fallback=False)
    assert fingerprint_config(default) != fingerprint_config(baseline)
    assert default.verifier == baseline.verifier


@pytest.mark.parametrize("flags,expanded,legacy", [
    ([], True, False), (["--no-expanded-correspondence"], False, False),
    (["--experimental-local-correspondence"], False, True),
])
def test_cli_selects_verifier_without_loading_model(tmp_path, flags, expanded, legacy):
    args = build_parser().parse_args(["scan", str(tmp_path), *flags])
    class StopBeforeScan(Exception):
        pass
    def capture(entries, config):
        assert config.include_expanded_correspondence_fallback is expanded
        assert config.include_local_correspondence_fallback is legacy
        assert config.verifier.minimum_edit_side_score == .90
        raise StopBeforeScan
    with patch.object(scan, "load_entries", return_value=[]), \
         patch.object(scan, "build_default_detector_factory", side_effect=capture), \
         pytest.raises(StopBeforeScan):
        scan.run(args)
