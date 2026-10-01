import argparse
import json
from pathlib import Path

import pytest

from eval.ablation.priority_relationships import RevisionRelationships, experimental_priority
from provtrail.corpus.models.corpus import CorpusEntry
from provtrail.pipeline.controller.provenance import fix_boundary_id, provenance_lineage_id
from provtrail.pipeline.detection.priority import derive_priority
from provtrail.pipeline.models.boundary import BoundaryIdentity, BoundaryEditEvidence, VerificationGates, VulnerabilityState
from provtrail.pipeline.models.lineage import LineageAttribution
from provtrail.pipeline.models.result import RegionDetectionResult
from provtrail.shared.metadata import CorpusAdvisory, SourceReference
from eval.ablation.common import file_hash, seal
from eval.ablation import run_priority_relationships as adapter


def entry(before, after, commit, function="check", path="check.js"):
    return CorpusEntry(advisory=CorpusAdvisory(ghsa_id="GHSA-" + commit, package_name="fixture", ecosystem="npm"),
        origin=SourceReference(repo="fixture/repo", fix_commit_sha=commit, file_path=path, function_name=function),
        vulnerable_function=before, patched_function=after)


def state(e, status, **kwargs):
    return VulnerabilityState(status=status, boundary=BoundaryIdentity(lineage_id=provenance_lineage_id(e),
        fix_boundary_id=fix_boundary_id(e), fix_commit_sha=e.origin.fix_commit_sha), **kwargs)


def result(*states):
    lineages = {s.boundary.lineage_id for s in states}
    value = RegionDetectionResult(candidate_region_count=2, retrieval_match_count=2,
        vulnerability_states=list(states), lineages=[LineageAttribution(lineage_id=l, confidence="high",
        score=.9, repo="fixture/repo", file_path="fixture.js") for l in lineages])
    value.priority = derive_priority(value.lineages, value.vulnerability_states, [])
    return value


def weak(e, **updates):
    gates = dict(token_gate_passed=True, function_identity_state="unknown", context_correspondence_passed=True)
    gates.update(updates)
    return state(e, "uncertain", abstention_reason="E_SIDE_WEAK", gates=VerificationGates(**gates),
                 edit=BoundaryEditEvidence(vulnerable=.786, patched=.4,
                                           vulnerable_anchor_has_identity=False, patched_anchor_has_identity=False))


def test_connected_later_fix_keeps_review_below_edit_threshold_without_mutating_verdicts():
    a, b = entry("v0", "v1", "a"), entry("v1", "v2", "b")
    graph = RevisionRelationships.from_entries([a, b])
    value = result(state(a, "patched"), weak(b))
    before = value.model_dump(mode="json")
    assert graph.relation(value.vulnerability_states[1], [fix_boundary_id(a)]) == "connected_revision"
    assert experimental_priority(value, graph) == "manual_review"
    assert value.model_dump(mode="json") == before


def test_links_are_transitive_and_do_not_depend_on_commit_sort_order():
    a, b, c = entry("v0", "v1", "z"), entry("v1", "v2", "a"), entry("v2", "v3", "m")
    graph = RevisionRelationships.from_entries([c, a, b])
    assert len(graph.links) == 2
    assert graph.relation(weak(c), [fix_boundary_id(a)]) == "connected_revision"


def test_equal_source_in_another_repository_is_not_a_revision_connection():
    a, b = entry("v0", "v1", "a"), entry("v1", "v2", "b")
    b.origin.repo = "different/repo"
    graph = RevisionRelationships.from_entries([a, b])
    assert not graph.links
    assert graph.relation(weak(b), [fix_boundary_id(a)]) == "unknown"


def test_different_paths_and_missing_edges_alone_do_not_release_review():
    a, b = entry("v0", "v1", "a"), entry("other0", "other1", "b", "other", "other.js")
    graph = RevisionRelationships.from_entries([a, b])
    assert experimental_priority(result(state(a, "patched"), weak(b)), graph) == "manual_review"


def test_positive_identity_conflict_can_release_generic_alternative():
    a, b = entry("v0", "v1", "a"), entry("other0", "other1", "b", "other", "other.js")
    graph = RevisionRelationships.from_entries([a, b])
    alternate = weak(b, function_identity_state="conflict", context_correspondence_passed=False)
    assert graph.relation(alternate, [fix_boundary_id(a)]) == "identity_incompatible"
    assert experimental_priority(result(state(a, "patched"), alternate), graph) == "informational_lineage"


@pytest.mark.parametrize("missing", ["name", "broader_context", "anchor_unknown", "anchor_identifying", "metadata"])
def test_partial_identity_conflict_does_not_establish_incompatibility(missing):
    a, b = entry("v0", "v1", "a"), entry("other0", "other1", "b", "other", "other.js")
    graph = RevisionRelationships.from_entries([a, b])
    alternate = weak(b, function_identity_state="conflict", context_correspondence_passed=False)
    if missing == "name": alternate.gates.function_identity_state = "unknown"
    elif missing == "broader_context": alternate.gates.context_correspondence_passed = True
    elif missing == "anchor_unknown": alternate.edit.vulnerable_anchor_has_identity = None
    elif missing == "anchor_identifying": alternate.edit.vulnerable_anchor_has_identity = True
    else: graph.components.pop(fix_boundary_id(b))
    assert experimental_priority(result(state(a, "patched"), alternate), graph) == "manual_review"


def test_disconnected_fixes_within_same_family_stay_unknown():
    a, b = entry("v0", "v1", "a"), entry("other0", "other1", "b")
    graph = RevisionRelationships.from_entries([a, b])
    alternate = weak(b, function_identity_state="conflict", context_correspondence_passed=False)
    assert graph.relation(alternate, [fix_boundary_id(a)]) == "unknown"
    assert experimental_priority(result(state(a, "patched"), alternate), graph) == "manual_review"


def test_connected_uncertainty_is_preserved_even_when_structure_gate_failed():
    a, b = entry("v0", "v1", "a"), entry("v1", "v2", "b")
    graph = RevisionRelationships.from_entries([a, b])
    alternate = state(b, "uncertain", abstention_reason="S_FAILED")
    value = result(state(a, "patched"), alternate)
    assert value.priority == "informational_lineage"
    assert experimental_priority(value, graph) == "manual_review"


@pytest.mark.parametrize("reason", ["CONTRADICTORY_EVIDENCE", "CONTRASTIVE_CONFLICT", "HASH_SIDE_AMBIGUOUS"])
def test_conflict_overrides_generic_identity_rejection(reason):
    a, b = entry("v0", "v1", "a"), entry("other0", "other1", "b", "other", "other.js")
    alternate = weak(b, function_identity_state="conflict", context_correspondence_passed=False)
    alternate.abstention_reason = reason
    assert experimental_priority(result(state(a, "patched"), alternate), RevisionRelationships.from_entries([a, b])) == "manual_review"


def test_verified_vulnerable_finding_and_no_patch_cases_keep_baseline():
    a, b = entry("v0", "v1", "a"), entry("v1", "v2", "b")
    graph = RevisionRelationships.from_entries([a, b])
    assert experimental_priority(result(state(a, "patched"), state(b, "vulnerable")), graph) == "automatic_vulnerability"
    assert experimental_priority(result(weak(b)), graph) == "manual_review"


def test_adapter_exports_to_fresh_directory_and_restores_v1_reader(tmp_path, monkeypatch):
    a, b = entry("v0", "v1", "a"), entry("v1", "v2", "b")
    source = tmp_path / "source"
    source.mkdir()
    corpus = tmp_path / "corpus.db"
    corpus.write_bytes(b"fixture")
    spec = {"path": str(corpus), "sha256": file_hash(corpus)}
    (source / "study-lock.json").write_text(json.dumps(seal({"inputs": {"reference": spec}})), encoding="utf-8")
    monkeypatch.setattr(adapter, "load_entries", lambda path: [a, b])
    output = tmp_path / "fresh-output"
    value = result(state(a, "patched"), weak(b))
    row = dict(arm="block_function", candidate_id="fixture", tier="tier2", split="evaluation",
               expected_status="flagged", result=value.model_dump(mode="json"), priority=value.priority,
               abstained=True, hash_path=False, patched_false_positive=False)

    def fake_main(argv):
        parser = argparse.ArgumentParser()
        parser.add_argument("--source")
        parser.add_argument("--output", type=Path)
        args = parser.parse_args(argv)
        replayed, _ = adapter.runner.replay_row(row, .9)
        assert replayed["priority"] == "manual_review"
        adapter.runner.write_json(args.output / "summary.json", {"policy": adapter.runner.POLICY, "scopes": []})
        adapter.runner.write_json(args.output / "case-changes.json", {"changes": []})
        (args.output / "tables.md").write_text("# Fixture\n\nOnly when a verified patched boundary exists: old description\n", encoding="utf-8")

    monkeypatch.setattr(adapter.runner, "main", fake_main)
    previous = (adapter.runner.POLICY, adapter.runner.replay_row, adapter.runner.experimental_priority)
    adapter.main(["--source", str(source), "--output", str(output)])
    assert previous == (adapter.runner.POLICY, adapter.runner.replay_row, adapter.runner.experimental_priority)
    report = json.loads((output / "summary.json").read_text(encoding="utf-8"))
    assert len(report["revision_links"]) == 1
    traces = json.loads((output / "relationship-traces.json").read_text(encoding="utf-8"))
    assert traces["cases"][0]["alternatives"][0]["relationship"] == "connected_revision"
    assert "connected revisions retain review" in (output / "tables.md").read_text(encoding="utf-8")
