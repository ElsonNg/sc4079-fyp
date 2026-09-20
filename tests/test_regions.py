import faiss
import numpy as np
import pytest

from provtrail.corpus.models.corpus import CorpusEntry, DiagnosticLine
from provtrail.pipeline.detection.verification.edit_distance import score_edit_distance
from provtrail.pipeline.controller.hashing import HashIndex, build_hash_index
from provtrail.pipeline.controller.region_detection import RegionDetector, RegionDetectorConfig, derive_priority
from provtrail.pipeline.controller.region_extraction import (
    candidate_region_is_informative,
    enumerate_candidate_regions,
    extract_corpus_region_pairs,
    extract_vulnerability_regions,
    source_is_supported,
)
from provtrail.pipeline.controller.region_retrieval import aggregate_region_hits
from provtrail.pipeline.controller.region_retrieval import RegionRetrievalIndex
from provtrail.pipeline.detection.verification.aggregation import deduplicate_evidence
from provtrail.pipeline.detection.verification.classification import classify_boundary, classify_evidence
from provtrail.pipeline.detection.verification.verifier import verify_region_pair
from provtrail.pipeline.models.boundary import BoundaryIdentity, VerificationGates
from provtrail.pipeline.models.evidence import (
    CandidateEvidenceReference,
    EditDistanceEvidence,
    PairedEvidenceReference,
    ReferenceSideEvidence,
    RegionComparison,
    RegionVerificationEvidence,
)
from provtrail.pipeline.models.boundary import VulnerabilityState
from provtrail.pipeline.models.lineage import LineageAttribution
from provtrail.pipeline.models.region_retrieval import RegionAggregate, RegionRetrievalMatch


def _entry(vulnerable: str, patched: str, diagnostics: list[DiagnosticLine]) -> CorpusEntry:
    return CorpusEntry(
        ghsa_id="GHSA-test-region",
        cve_id="CVE-TEST-REGION",
        package_name="test-package",
        ecosystem="npm",
        repo="test/repo",
        fix_commit_sha="deadbeef",
        file_path="lib/test.js",
        function_name="checkValue",
        vulnerable_function=vulnerable,
        patched_function=patched,
        diagnostic_lines=diagnostics,
    )


def test_extracts_paired_multiresolution_regions_with_source_coordinates():
    vulnerable = """function checkValue(value) {
  if (value) {
    return value;
  }
  return null;
}"""
    patched = """function checkValue(value) {
  if (value && typeof value === 'string') {
    return value;
  }
  return null;
}"""
    entry = _entry(
        vulnerable,
        patched,
        [
            DiagnosticLine(kind="removed", vulnerable_line=1, text="  if (value) {"),
            DiagnosticLine(kind="added", patched_line=1, text="  if (value && typeof value === 'string') {"),
        ],
    )

    pairs = extract_vulnerability_regions(entry)

    assert [pair.vulnerable_region.granularity for pair in pairs] == [
        "changed", "block", "context", "function"
    ]
    assert all(pair.vulnerable_region.span.start_line >= 0 for pair in pairs)
    assert all(pair.patched_region.span.end_byte <= len(patched.encode("utf-8")) for pair in pairs)
    assert all(pair.change.change_kind == "replacement" for pair in pairs)
    assert all(pair.pair_id in pair.vulnerable_region.region_id for pair in pairs)


def test_corpus_region_pairs_deduplicate_shared_code_lineages_and_keep_aliases():
    vulnerable = "function checkValue(value) { if (value) return value; return null; }"
    patched = "function checkValue(value) { if (typeof value === 'string') return value; return null; }"
    original = _entry(
        vulnerable,
        patched,
        [DiagnosticLine(kind="replacement", vulnerable_line=0, patched_line=0, text="guard")],
    )
    alias = original.model_copy(
        update={'advisory': original.advisory.model_copy(update={'ghsa_id': "GHSA-alias", 'cve_id': "CVE-ALIAS", 'package_name': "test-package-fork"})}
    )

    pairs = extract_corpus_region_pairs([original, alias])

    assert len(pairs) == 4
    assert len({pair.lineage_id for pair in pairs}) == 1
    assert {
        advisory.ghsa_id for advisory in pairs[0].advisories
    } == {"GHSA-test-region", "GHSA-alias"}
    assert {
        advisory.package_name for advisory in pairs[0].advisories
    } == {"test-package", "test-package-fork"}


def test_pure_patch_insertion_still_produces_a_paired_vulnerable_region():
    vulnerable = "function checkValue(value) {\n  return value;\n}"
    patched = "function checkValue(value) {\n  if (!value) return null;\n  return value;\n}"
    entry = _entry(
        vulnerable,
        patched,
        [DiagnosticLine(kind="added", patched_line=1, text="  if (!value) return null;")],
    )

    pairs = extract_vulnerability_regions(entry)

    assert pairs
    assert all(pair.change.change_kind == "insertion" for pair in pairs)
    assert all(pair.vulnerable_region.source for pair in pairs)
    assert all(pair.patched_region.source for pair in pairs)


def test_patchless_entry_is_not_used_for_paired_region_verification():
    entry = _entry(
        "function vulnerable(value) { return value; }",
        "",
        [DiagnosticLine(kind="removed", vulnerable_line=0, text="return value;")],
    )

    assert extract_vulnerability_regions(entry) == []


def test_method_snippets_are_wrapped_without_leaking_wrapper_coordinates():
    source = """constructor(message) {
  this.message = message;
  return this;
}"""
    regions = enumerate_candidate_regions(source, candidate_id="C-method")

    assert regions
    function_region = next(item.region for item in regions if item.region.granularity == "function")
    assert function_region.span.start_line == 0
    assert function_region.source.startswith("constructor")
    assert "__CodexRegionWrapper" not in function_region.source


def test_candidate_generation_has_prioritized_granularities_and_unique_spans():
    source = """function checkValue(value) {
  if (value) {
    return value + 1;
  }
  return 0;
}"""
    regions = enumerate_candidate_regions(source, candidate_id="C01")
    keys = {(item.region.span.start_byte, item.region.span.end_byte, item.region.granularity) for item in regions}

    assert len(regions) == len(keys)
    assert {item.region.granularity for item in regions} == {"changed", "block", "context", "function"}
    assert regions[-1].region.granularity == "function"


def test_candidate_generation_rejects_tiny_syntax_only_regions():
    source = """function passthrough(value) {
  var temporary;
  if (value) return value;
  return;
}"""

    regions = enumerate_candidate_regions(source, candidate_id="C-noise")
    changed_sources = {
        item.region.source.strip()
        for item in regions
        if item.region.granularity == "changed"
    }

    assert "var temporary;" not in changed_sources
    assert "return value;" not in changed_sources
    assert "return;" not in changed_sources
    assert all(candidate_region_is_informative(item.region) for item in regions)


def test_candidate_generation_keeps_short_regions_with_concrete_affiliation():
    source = """function render(value, stream) {
  stream.destroy();
  return escapeHtml(value);
}"""

    regions = enumerate_candidate_regions(source, candidate_id="C-anchors")
    changed_sources = {
        item.region.source.strip()
        for item in regions
        if item.region.granularity == "changed"
    }

    assert "stream.destroy();" in changed_sources
    assert "return escapeHtml(value);" in changed_sources


def test_region_verification_prefers_vulnerable_shape_over_patched_shape():
    vulnerable = """function checkValue(value) {
  if (value) {
    return value;
  }
  return null;
}"""
    patched = """function checkValue(value) {
  if (value && typeof value === 'string') {
    return value;
  }
  return null;
}"""
    entry = _entry(
        vulnerable,
        patched,
        [DiagnosticLine(kind="replacement", vulnerable_line=1, patched_line=1, text="guard")],
    )
    pair = next(pair for pair in extract_vulnerability_regions(entry) if pair.vulnerable_region.granularity == "changed")
    candidate = next(
        item.region
        for item in enumerate_candidate_regions(vulnerable, candidate_id="C01")
        if item.region.granularity == "changed"
        and item.region.source == pair.vulnerable_region.source
    )

    evidence = verify_region_pair(candidate, pair, retrieval_similarity=0.9)

    assert evidence.vulnerable.score > evidence.patched.score
    assert evidence.comparison.margin > 0
    assert evidence.comparison.ast_coverage > 0
    assert evidence.comparison.alignment_fallback_used is False
    assert evidence.vulnerable.score == pytest.approx(
        min(evidence.vulnerable.structural, evidence.vulnerable.token)
    )


def test_empty_api_anchor_features_are_unavailable_instead_of_perfect_similarity():
    vulnerable = "function checkValue(value) { if (value) return value; return null; }"
    patched = "function checkValue(value) { if (value === true) return value; return null; }"
    entry = _entry(
        vulnerable,
        patched,
        [DiagnosticLine(kind="replacement", vulnerable_line=0, patched_line=0, text="guard")],
    )
    pair = next(pair for pair in extract_vulnerability_regions(entry) if pair.vulnerable_region.granularity == "changed")
    candidate = pair.vulnerable_region.model_copy(update={"region_id": "C-empty-semantics"})

    evidence = verify_region_pair(candidate, pair, retrieval_similarity=0.9)

    assert evidence.vulnerable.api_anchor is None
    assert evidence.patched.api_anchor is None
    assert evidence.vulnerable.score == pytest.approx(
        min(evidence.vulnerable.structural, evidence.vulnerable.token)
    )


def test_regex_fix_remains_visible_to_token_and_edit_scores():
    vulnerable = r"function clean(value) { return value.replace(/\([^)]*\)/g, ' '); }"
    patched = r"function clean(value) { return value.replace(/\([^()]*\)/g, ' '); }"
    entry = _entry(
        vulnerable,
        patched,
        [DiagnosticLine(kind="replacement", vulnerable_line=0, patched_line=0, text="regex")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "function"
    )

    patched_evidence = verify_region_pair(
        pair.patched_region,
        pair,
        retrieval_similarity=0.9,
    )

    assert patched_evidence.patched.token == 1.0
    assert patched_evidence.vulnerable.token < patched_evidence.patched.token
    edit = score_edit_distance(
        patched,
        [
            DiagnosticLine(kind="removed", vulnerable_line=0, text=vulnerable),
            DiagnosticLine(kind="added", patched_line=0, text=patched),
        ],
    )
    assert edit.patched == 1.0
    assert edit.vulnerable < edit.patched
    assert edit.vulnerable_anchor_has_identity is True
    assert edit.patched_anchor_has_identity is True


def test_generic_edit_anchor_has_no_boundary_identity():
    edit = score_edit_distance(
        "function loadLocale(name) { return locales[name]; }",
        [
            DiagnosticLine(kind="removed", vulnerable_line=0, text="return obj[name];"),
            DiagnosticLine(kind="added", patched_line=0, text="return safeLookup(obj, name);"),
        ],
    )

    assert edit.vulnerable == 1.0
    assert edit.vulnerable_anchor_has_identity is False
    assert edit.patched_anchor_has_identity is True


def test_contrastive_edit_anchors_ignore_statement_shared_by_both_sides():
    diagnostics = [
        DiagnosticLine(
            kind="removed", vulnerable_line=0, text="proxy = new URL(proxyUrl);"
        ),
        DiagnosticLine(
            kind="added", patched_line=0, text="if (!shouldBypassProxy(location)) {"
        ),
        DiagnosticLine(
            kind="added", patched_line=1, text="proxy = new URL(proxyUrl);"
        ),
        DiagnosticLine(kind="added", patched_line=2, text="}"),
    ]

    vulnerable = score_edit_distance("proxy = new URL(proxyUrl);", diagnostics)
    patched = score_edit_distance(
        "if (!shouldBypassProxy(location)) { proxy = new URL(proxyUrl); }",
        diagnostics,
    )

    assert vulnerable.raw_vulnerable == 1.0
    assert patched.raw_vulnerable == 1.0
    assert vulnerable.contrastive_used is True
    assert vulnerable.vulnerable == 1.0
    assert vulnerable.patched < 0.90
    assert patched.patched == 1.0
    assert patched.vulnerable == 0.0


def test_containment_fallback_recovers_type3_region_with_extra_code():
    entry = _entry(
        "function checkValue(value) { return unsafe(value); }",
        "function checkValue(value) { return safe(value); }",
        [DiagnosticLine(kind="removed", vulnerable_line=0, text="return unsafe(value);")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "function"
    )
    reference = pair.vulnerable_region
    candidate = reference.model_copy(update={
        "region_id": "type3-extra-code",
        "ast_shape": reference.ast_shape + ["extra_node"] * len(reference.ast_shape),
        "ast_path": reference.ast_path + ["extra/path"] * len(reference.ast_path),
        "normalized_tokens": (
            reference.normalized_tokens + [";"] * len(reference.normalized_tokens)
        ),
    })

    evidence = verify_region_pair(candidate, pair, retrieval_similarity=0.9)

    assert evidence.vulnerable.structural < 0.70
    assert evidence.vulnerable.containment_used is True
    assert evidence.vulnerable.containment_coverage == pytest.approx(0.50)
    assert evidence.vulnerable.score >= 0.70


def test_renamed_api_anchor_receivers_preserve_operation_similarity():
    vulnerable = "function checkValue(value) { service.accept(value); return service.result; }"
    patched = "function checkValue(value) { service.reject(value); return service.error; }"
    entry = _entry(
        vulnerable,
        patched,
        [DiagnosticLine(kind="replacement", vulnerable_line=0, patched_line=0, text="operation")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "function"
    )
    candidate = pair.vulnerable_region.model_copy(
        update={
            "region_id": "C-renamed-semantics",
            "calls": ["renamed.accept"],
            "member_accesses": ["renamed.accept", "renamed.result"],
        }
    )

    evidence = verify_region_pair(candidate, pair, retrieval_similarity=0.9)

    assert evidence.vulnerable.structural == 1.0
    assert evidence.vulnerable.token == 1.0
    assert evidence.vulnerable.api_anchor == 1.0
    assert evidence.comparison.correspondence_score == pytest.approx(
        max(evidence.vulnerable.score, evidence.patched.score)
    )
    assert evidence.vulnerable.score == pytest.approx(1.0)
    assert evidence.vulnerable.score >= 0.75

    different_operation = candidate.model_copy(
        update={
            "region_id": "C-different-api-operation",
            "calls": ["renamed.reject"],
            "member_accesses": ["renamed.reject", "renamed.error"],
        }
    )
    different_evidence = verify_region_pair(different_operation, pair, retrieval_similarity=0.9)

    assert different_evidence.vulnerable.api_anchor == 0.0

    weak_token_candidate = candidate.model_copy(
        update={
            "region_id": "C-same-shape-weak-tokens",
            "normalized_tokens": ["while"],
        }
    )
    weak_evidence = verify_region_pair(weak_token_candidate, pair, retrieval_similarity=0.9)

    assert weak_evidence.vulnerable.structural == 1.0
    assert weak_evidence.vulnerable.token < 0.95
    assert weak_evidence.vulnerable.score == pytest.approx(
        min(weak_evidence.vulnerable.structural, weak_evidence.vulnerable.token)
    )


def _with_evidence_updates(evidence, **changes):
    return RegionVerificationEvidence.from_record({**evidence.to_record(), **changes})


def _evidence(pair_id: str, vulnerable_score: float, margin: float) -> RegionVerificationEvidence:
    return RegionVerificationEvidence(
        pair_id=pair_id,
        retrieval_similarity=0.9,
        candidate=CandidateEvidenceReference(
            region_id=f'candidate:{pair_id}',
        ),
        reference=PairedEvidenceReference(
            vulnerable_region_id=f'{pair_id}:vulnerable',
            patched_region_id=f'{pair_id}:patched',
        ),
        vulnerable=ReferenceSideEvidence(
            structural=vulnerable_score,
            token=vulnerable_score,
            score=vulnerable_score,
        ),
        patched=ReferenceSideEvidence(
            structural=vulnerable_score - margin,
            token=vulnerable_score - margin,
            score=vulnerable_score - margin,
        ),
        comparison=RegionComparison(
            margin=margin,
            ast_coverage=1.0,
        ),
    )


def test_classification_does_not_let_a_low_score_large_margin_hide_passing_evidence():
    low_score = _evidence("pair-low", vulnerable_score=0.72, margin=0.60)
    passing = _evidence("pair-pass", vulnerable_score=0.90, margin=0.20)
    corroborating = _evidence("pair-corroborating", vulnerable_score=0.86, margin=0.16)
    aggregates = [
        RegionAggregate(pair_id="pair-low", best_similarity=0.9, candidate_region_ids=["candidate-1"]),
        RegionAggregate(pair_id="pair-pass", best_similarity=0.9, candidate_region_ids=["candidate-1"]),
        RegionAggregate(pair_id="pair-corroborating", best_similarity=0.9, candidate_region_ids=["candidate-1"]),
    ]

    status, _ = classify_evidence([low_score, passing, corroborating], aggregates)

    assert status == "flagged"


def test_both_signatures_are_neutral_when_side_scores_favor_vulnerable():
    entry = _entry(
        "function checkValue(value) { return unsafe(value); }",
        "function checkValue(value) { return safe(value); }",
        [DiagnosticLine(kind="replacement", vulnerable_line=0, patched_line=0, text="call")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "function"
    )
    evidence = _with_evidence_updates(_evidence(pair.pair_id, vulnerable_score=0.95, margin=0.15), **{"fix_signature_coverage": 0.9, "vulnerable_signature_coverage": 0.9})

    state = classify_boundary(
        [evidence],
        pair,
        edit=EditDistanceEvidence(vulnerable=0.95, patched=0.80),
    )

    assert state.status == "vulnerable"
    assert state.support.signature_evidence_state == "both"
    assert state.support.independent_region_count == 1
    assert state.support.vulnerable_support_count == 1
    assert state.support.patched_support_count == 0
    assert state.support.side_consensus_ratio == 1.0


def test_staged_boundary_requires_structure_and_tokens_on_the_same_side():
    entry = _entry(
        "function checkValue(value) { return unsafe(value); }",
        "function checkValue(value) { return safe(value); }",
        [DiagnosticLine(kind="replacement", vulnerable_line=0, patched_line=0, text="call")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "function"
    )
    evidence = _with_evidence_updates(_evidence(pair.pair_id, vulnerable_score=0.95, margin=0.15), **{
            "structural_vulnerable": 0.80,
            "token_vulnerable": 0.69,
            "structural_patched": 0.69,
            "token_patched": 0.80,
        })

    state = classify_boundary(
        [evidence],
        pair,
        edit=EditDistanceEvidence(vulnerable=1.0, patched=0.60),
    )

    assert state.gates.structure_gate_passed is True
    assert state.gates.token_gate_passed is False
    assert state.status == "uncertain"


@pytest.mark.parametrize(
    ("structural", "token", "edit", "expected_reason"),
    [
        (0.60, 0.90, None, "S_FAILED"),
        (0.90, 0.60, None, "T_FAILED"),
        (0.90, 0.90, EditDistanceEvidence(vulnerable=0.95, patched=0.90),
         "E_MARGIN_AMBIGUOUS"),
        (0.90, 0.90, EditDistanceEvidence(vulnerable=0.85, patched=0.60),
         "E_SIDE_WEAK"),
        (0.90, 0.90, EditDistanceEvidence(vulnerable=0.80, patched=0.75),
         "E_SIDE_AND_MARGIN_WEAK"),
    ],
)
def test_uncertain_boundary_records_one_terminal_reason(
    structural, token, edit, expected_reason,
):
    entry = _entry(
        "function checkValue(value) { return unsafe(value); }",
        "function checkValue(value) { return safe(value); }",
        [DiagnosticLine(kind="removed", vulnerable_line=0, text="return unsafe(value);")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "changed"
    )
    evidence = _with_evidence_updates(_evidence(pair.pair_id, vulnerable_score=structural, margin=0.0), **{
            "structural_vulnerable": structural,
            "structural_patched": structural,
            "token_vulnerable": token,
            "token_patched": token,
        })

    state = classify_boundary([evidence], pair, edit=edit)

    assert state.status == "uncertain"
    assert state.abstention_reason == expected_reason


def test_staged_boundary_uses_edit_distance_only_after_correspondence():
    entry = _entry(
        "function checkValue(value) { return unsafe(value); }",
        "function checkValue(value) { return safe(value); }",
        [DiagnosticLine(kind="replacement", vulnerable_line=0, patched_line=0, text="call")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "function"
    )
    evidence = _evidence(pair.pair_id, vulnerable_score=0.70, margin=0.0)

    state = classify_boundary(
        [evidence],
        pair,
        edit=EditDistanceEvidence(vulnerable=1.0, patched=0.60),
    )

    assert state.gates.structure_gate_passed is True
    assert state.gates.token_gate_passed is True
    assert state.status == "vulnerable"
    assert state.scores.vulnerable_score == 1.0
    assert state.scores.contrast_score == pytest.approx(0.40)


def test_overlapping_alignment_keeps_strongest_coherent_correspondence():
    exact = _with_evidence_updates(_evidence("boundary:changed", vulnerable_score=1.0, margin=0.23), **{
            "candidate_region_id": "same-candidate-span",
            "candidate_granularity": "changed",
            "reference_granularity": "changed",
            "structural_vulnerable": 1.0,
            "token_vulnerable": 1.0,
            "structural_patched": 0.875,
            "token_patched": 0.769,
        })
    decisive_mismatch = _with_evidence_updates(exact, **{
            "pair_id": "boundary:context",
            "reference_granularity": "context",
            "token_vulnerable": 0.526,
            "vulnerable_score": 0.526,
            "patched_score": 0.769,
            "vulnerable_minus_patched": -0.243,
        })

    selected = deduplicate_evidence(
        [decisive_mismatch, exact],
        side="vulnerable",
    )

    assert selected == [exact]


def test_boundary_gate_uses_structure_and_tokens_from_one_best_row():
    entry = _entry(
        "function checkValue(value) { return unsafe(value); }",
        "function checkValue(value) { return safe(value); }",
        [DiagnosticLine(kind="removed", vulnerable_line=0, text="return unsafe(value);")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "changed"
    )
    exact = _with_evidence_updates(_evidence(pair.pair_id, vulnerable_score=1.0, margin=0.23), **{
            "candidate_region_id": "same-candidate-span",
            "candidate_granularity": "changed",
            "reference_granularity": "changed",
            "structural_vulnerable": 1.0,
            "token_vulnerable": 1.0,
            "structural_patched": 0.875,
            "token_patched": 0.769,
        })
    mismatch = _with_evidence_updates(exact, **{
            "pair_id": f"{pair.fix_boundary_id}:context",
            "reference_granularity": "context",
            "token_vulnerable": 0.526,
            "vulnerable_score": 0.526,
            "patched_score": 0.769,
            "vulnerable_minus_patched": -0.243,
        })

    state = classify_boundary(
        [mismatch, exact],
        pair,
        edit=EditDistanceEvidence(
            vulnerable=1.0,
            patched=0.804,
            vulnerable_anchor_has_identity=True,
        ),
    )

    assert state.status == "vulnerable"
    assert state.scores.structural_vulnerable == 1.0
    assert state.scores.token_vulnerable == 1.0


def test_decisive_raw_edit_result_is_not_overturned_by_contrastive_fallback():
    entry = _entry(
        "function checkValue(value) { return unsafe(value); }",
        "function checkValue(value) { return safe(value); }",
        [DiagnosticLine(kind="removed", vulnerable_line=0, text="return unsafe(value);")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "changed"
    )
    evidence = _evidence(pair.pair_id, vulnerable_score=0.95, margin=0.15)

    state = classify_boundary(
        [evidence],
        pair,
        edit=EditDistanceEvidence(
            vulnerable=0.0,
            patched=1.0,
            raw_vulnerable=1.0,
            raw_patched=0.70,
            contrastive_vulnerable=0.0,
            contrastive_patched=1.0,
            contrastive_used=True,
            raw_vulnerable_anchor_has_identity=True,
            raw_patched_anchor_has_identity=True,
            contrastive_vulnerable_anchor_has_identity=False,
            contrastive_patched_anchor_has_identity=False,
        ),
    )

    assert state.status == "vulnerable"
    assert state.edit.vulnerable == 1.0
    assert state.edit.patched == 0.70
    assert state.edit.contrastive_used is False


def test_verified_vulnerable_boundary_overrides_low_lineage_confidence():
    lineages = [LineageAttribution(
        lineage_id="lineage-a", confidence="low", score=0.6,
        repo="test/repo", file_path="test.js",
    )]
    states = [VulnerabilityState(
        status='vulnerable',
        boundary=BoundaryIdentity(
            lineage_id='lineage-a',
            fix_boundary_id='boundary-a',
            fix_commit_sha='deadbeef',
        ),
        gates=VerificationGates(
            token_gate_passed=True,
        ),
    )]

    assert derive_priority(lineages, states, []) == "automatic_vulnerability"


def test_patched_boundary_overrides_only_weak_unrelated_uncertainty():
    lineages = [
        LineageAttribution(
            lineage_id="patched-lineage", confidence="medium", score=0.8,
            repo="test/repo", file_path="patched.js",
        ),
        LineageAttribution(
            lineage_id="noise-lineage", confidence="medium", score=0.8,
            repo="test/repo", file_path="noise.js",
        ),
    ]
    patched = VulnerabilityState(
        status='patched',
        boundary=BoundaryIdentity(
            lineage_id='patched-lineage',
            fix_boundary_id='patched-boundary',
            fix_commit_sha='patched',
        ),
        gates=VerificationGates(
            token_gate_passed=True,
        ),
    )
    weak = VulnerabilityState(
        status='uncertain',
        boundary=BoundaryIdentity(
            lineage_id='noise-lineage',
            fix_boundary_id='noise-boundary',
            fix_commit_sha='noise',
        ),
        gates=VerificationGates(
            token_gate_passed=False,
        ),
    )

    assert derive_priority(lineages, [patched, weak], []) == "informational_lineage"

    strong = weak.model_copy(update={"gates": weak.gates.model_copy(update={"token_gate_passed": True})})
    assert derive_priority(lineages, [patched, strong], []) == "manual_review"


def test_boundary_identity_gate_abstains_on_generic_changed_only_function_conflict():
    entry = _entry(
        "function checkValue(obj, name) { return obj[name]; }",
        "function checkValue(obj, name) { return safeLookup(obj, name); }",
        [DiagnosticLine(kind="removed", vulnerable_line=0, text="return obj[name];")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "changed"
    )
    evidence = _with_evidence_updates(_evidence(pair.pair_id, vulnerable_score=0.95, margin=0.15), **{
            "candidate_granularity": "changed",
            "candidate_function_name": "unrelatedFunction",
        })

    state = classify_boundary(
        [evidence],
        pair,
        edit=EditDistanceEvidence(
            vulnerable=1.0,
            patched=0.5,
            vulnerable_anchor_has_identity=False,
            patched_anchor_has_identity=True,
        ),
    )

    assert state.status == "uncertain"
    assert state.gates.function_identity_state == "conflict"
    assert state.gates.context_correspondence_passed is False
    assert state.gates.edit_anchor_has_identity is False
    assert state.gates.boundary_identity_gate_passed is False
    assert state.gates.boundary_rejected is True
    assert state.abstention_reason == "IDENTITY_REJECTED"


def test_rejected_identity_mismatch_does_not_override_verified_patch():
    lineages = [LineageAttribution(
        lineage_id="lineage-a", confidence="medium", score=0.8,
        repo="test/repo", file_path="test.js",
    )]
    patched = VulnerabilityState(
        status='patched',
        boundary=BoundaryIdentity(
            lineage_id='lineage-a',
            fix_boundary_id='patched',
            fix_commit_sha='patched',
        ),
        gates=VerificationGates(
            token_gate_passed=True,
        ),
    )
    rejected = VulnerabilityState(
        status='uncertain',
        boundary=BoundaryIdentity(
            lineage_id='lineage-a',
            fix_boundary_id='unrelated',
            fix_commit_sha='unrelated',
        ),
        gates=VerificationGates(
            token_gate_passed=True,
            boundary_identity_gate_passed=False,
        ),
    )

    assert derive_priority(lineages, [patched, rejected], []) == "informational_lineage"


def test_boundary_identity_gate_keeps_named_edit_anchor_despite_function_rename():
    entry = _entry(
        "function checkValue(value) { return unsafe(value); }",
        "function checkValue(value) { return safe(value); }",
        [DiagnosticLine(kind="removed", vulnerable_line=0, text="return unsafe(value);")],
    )
    pair = next(
        pair for pair in extract_vulnerability_regions(entry)
        if pair.vulnerable_region.granularity == "changed"
    )
    evidence = _with_evidence_updates(_evidence(pair.pair_id, vulnerable_score=0.95, margin=0.15), **{
            "candidate_granularity": "changed",
            "candidate_function_name": "renamedFunction",
        })

    state = classify_boundary(
        [evidence],
        pair,
        edit=EditDistanceEvidence(
            vulnerable=1.0,
            patched=0.5,
            vulnerable_anchor_has_identity=True,
            patched_anchor_has_identity=True,
        ),
    )

    assert state.status == "vulnerable"
    assert state.gates.function_identity_state == "conflict"
    assert state.gates.boundary_identity_gate_passed is True


def test_classification_does_not_flag_from_one_supporting_region():
    passing = _evidence("pair-pass", vulnerable_score=0.90, margin=0.20)
    aggregates = [RegionAggregate(pair_id="pair-pass", best_similarity=0.9, candidate_region_ids=["candidate-1", "candidate-2", "candidate-3", "candidate-4"])]

    status, _ = classify_evidence([passing], aggregates)

    assert status == "manual_review"


def test_classification_downgrades_when_patched_contradiction_is_as_strong():
    first = _evidence("pair-first", vulnerable_score=0.90, margin=0.20)
    second = _evidence("pair-second", vulnerable_score=0.86, margin=0.16)
    contradiction = _evidence("pair-patched", vulnerable_score=0.55, margin=-0.25)
    aggregates = [
        RegionAggregate(pair_id=item.pair_id, best_similarity=0.9, candidate_region_ids=["candidate-1"])
        for item in (first, second, contradiction)
    ]

    status, _ = classify_evidence([first, second, contradiction], aggregates)

    assert status == "manual_review"


def test_region_hit_aggregation_counts_supporting_candidate_regions():
    common = dict(
        pair_id="pair-a",
        ghsa_id="GHSA-a",
        cve_id="CVE-a",
        fix_commit_sha="fix-a",
        file_path="a.js",
        function_name="a",
    )
    matches = [
        RegionRetrievalMatch(**common, similarity=0.8, rank=1, candidate_region_id="c1", candidate_granularity="changed", corpus_granularity="changed"),
        RegionRetrievalMatch(**common, similarity=0.75, rank=2, candidate_region_id="c2", candidate_granularity="block", corpus_granularity="block"),
        RegionRetrievalMatch(**{**common, "pair_id": "pair-b", "ghsa_id": "GHSA-b", "cve_id": "CVE-b", "fix_commit_sha": "fix-b", "file_path": "b.js", "function_name": "b"}, similarity=0.85, rank=1, candidate_region_id="c3", candidate_granularity="changed", corpus_granularity="changed"),
    ]

    grouped = aggregate_region_hits(matches)

    assert grouped[0][0] == "pair-b"
    assert grouped[1][0] == "pair-a"
    assert len(grouped[1][1]) == 2


def test_region_detector_uses_region_path_when_hash_path_is_empty(monkeypatch):
    vulnerable = """function checkValue(value) {
  if (value) {
    return value;
  }
  return null;
}"""
    patched = """function checkValue(value) {
  if (value && typeof value === 'string') {
    return value;
  }
  return null;
}"""
    entry = _entry(
        vulnerable,
        patched,
        [DiagnosticLine(kind="replacement", vulnerable_line=1, patched_line=1, text="guard")],
    )
    pairs = extract_vulnerability_regions(entry)

    def fake_encode(_model_id, texts, batch_size=32):
        vectors = np.ones((len(texts), 8), dtype=np.float32)
        return vectors / np.linalg.norm(vectors, axis=1, keepdims=True)

    monkeypatch.setattr("provtrail.pipeline.integrations.embedding.encode", fake_encode)
    index = faiss.IndexFlatIP(8)
    index.add(np.ones((len(pairs), 8), dtype=np.float32) / np.sqrt(8))
    detector = RegionDetector(
        [entry],
        RegionRetrievalIndex(model_id="fake", index=index, pairs=pairs, fingerprint="test"),
        HashIndex(),
        RegionDetectorConfig(model_id="fake", retrieval_top_k=4, max_candidate_regions=24),
    )

    result = detector.detect(vulnerable, candidate_id="C-region")

    assert result.priority == "automatic_vulnerability"
    assert result.candidate_region_count > 0
    assert result.retrieval_match_count > 0
    assert result.evidence
    assert len(result.lineages) == 1
    assert result.lineages[0].associated_advisories[0].ghsa_id == entry.advisory.ghsa_id


@pytest.mark.parametrize("enabled,local_status", [(False, "patched"), (True, "patched"), (True, "uncertain")])
def test_grouped_fallback_evidence_preserves_opt_in_and_saved_verdict(monkeypatch, enabled, local_status):
    from provtrail.pipeline.models.region import CandidateRegion

    vulnerable = "function checkValue(value) { if (value) { return value; } return null; }"
    patched = "function checkValue(value) { if (value && typeof value === 'string') { return value; } return null; }"
    entry = _entry(vulnerable, patched, [])
    pair = next(pair for pair in extract_vulnerability_regions(entry)
                if pair.vulnerable_region.granularity == "function")
    candidate = CandidateRegion(region=pair.vulnerable_region, function_name="checkValue")
    match = RegionRetrievalMatch(
        pair_id=pair.pair_id, similarity=1.0, rank=1,
        candidate_region_id=candidate.region.region_id,
        candidate_granularity="function", corpus_granularity="function",
        ghsa_id=entry.advisory.ghsa_id, fix_commit_sha=entry.origin.fix_commit_sha, file_path=entry.origin.file_path,
    )
    calls = []

    def local_check(*args, **kwargs):
        calls.append(True)
        return {"status": local_status, "decisive": {"fixture_method": True}, "reason": "fixture reason"}

    monkeypatch.setattr("provtrail.pipeline.controller.region_detection.decide_local_correspondence", local_check)
    monkeypatch.setattr("provtrail.pipeline.controller.region_detection.score_edit_distance",
                        lambda *args: EditDistanceEvidence(vulnerable=0.95, patched=0.93))
    detector = RegionDetector(
        [entry], RegionRetrievalIndex(model_id="fake", index=None, pairs=[pair]), HashIndex(),
        RegionDetectorConfig(include_local_correspondence_fallback=enabled),
    )
    result = detector.detect(vulnerable, _candidate_regions=[candidate], _matches=[match])
    state = result.vulnerability_states[0]
    record = result.model_dump(mode="json")["vulnerability_states"][0]
    resolved = enabled and local_status == "patched"

    assert bool(calls) is enabled
    assert state.fallbacks.local_correspondence_attempted is enabled
    assert state.fallbacks.local_correspondence_used is resolved
    assert state.status == ("patched" if resolved else "uncertain")
    assert record["local_correspondence_used"] is resolved
    assert record["local_correspondence_prior_abstention_reason"] == ("E_MARGIN_AMBIGUOUS" if enabled else None)
    assert record["fix_evidence"] == state.support.fix_evidence
    if resolved:
        assert any("Experimental local correspondence" in note for note in state.support.fix_evidence)


def test_same_language_scope_excludes_cross_language_region_matches(monkeypatch):
    vulnerable = """function checkValue(value) {
  if (value) {
    return value;
  }
  return null;
}"""
    patched = """function checkValue(value) {
  if (value && typeof value === 'string') {
    return value;
  }
  return null;
}"""
    diagnostics = [DiagnosticLine(kind="replacement", vulnerable_line=1, patched_line=1, text="guard")]
    javascript_entry = _entry(vulnerable, patched, diagnostics)
    typescript_entry = javascript_entry.model_copy(update={'advisory': javascript_entry.advisory.model_copy(update={'ghsa_id': "GHSA-test-typescript"}), 'origin': javascript_entry.origin.model_copy(update={'source_language': "typescript", 'file_path': "lib/test.ts"})})
    pairs = extract_vulnerability_regions(javascript_entry) + extract_vulnerability_regions(typescript_entry)

    def fake_encode(_model_id, texts, batch_size=32):
        vectors = np.ones((len(texts), 8), dtype=np.float32)
        return vectors / np.linalg.norm(vectors, axis=1, keepdims=True)

    monkeypatch.setattr("provtrail.pipeline.integrations.embedding.encode", fake_encode)
    index = faiss.IndexFlatIP(8)
    index.add(np.ones((len(pairs), 8), dtype=np.float32) / np.sqrt(8))
    detector = RegionDetector(
        [javascript_entry, typescript_entry],
        RegionRetrievalIndex(model_id="fake", index=index, pairs=pairs, fingerprint="test"),
        HashIndex(),
        RegionDetectorConfig(
            model_id="fake",
            retrieval_top_k=8,
            max_candidate_regions=24,
        ),
    )

    result = detector.detect(
        vulnerable.replace("function checkValue(value)", "function checkValue(value: string)"),
        candidate_id="C-ts.ts",
        language="typescript",
    )

    matches = [match for aggregate in result.aggregates for match in aggregate.top_matches]
    assert matches
    assert all(match.origin.source_language == "typescript" for match in matches)


def test_hash_verdicts_are_scoped_and_exact_patch_beats_same_identity_region_path():
    patched_snapshot = """
function transfer(sender, receiver, amount) {
    if (amount <= 0) { throw new Error('invalid'); }
    sender.balance = sender.balance - amount;
    receiver.balance = receiver.balance + amount;
    return receiver.balance;
}
"""
    earlier = CorpusEntry(
        ghsa_id="GHSA-earlier",
        cve_id="CVE-EARLIER",
        package_name="pkg",
        ecosystem="npm",
        repo="owner/pkg",
        fix_commit_sha="fix-earlier",
        file_path="index.js",
        function_name="transfer",
        vulnerable_function=patched_snapshot.replace("amount <= 0", "amount < 0"),
        patched_function=patched_snapshot,
    )
    later = CorpusEntry(
        ghsa_id="GHSA-later",
        cve_id="CVE-LATER",
        package_name="pkg",
        ecosystem="npm",
        repo="owner/pkg",
        fix_commit_sha="fix-later",
        file_path="index.js",
        function_name="transfer",
        vulnerable_function=patched_snapshot,
        patched_function=patched_snapshot.replace(
            "return receiver.balance;",
            "auditTransfer(sender, receiver, amount);\n    return receiver.balance;",
        ),
    )
    detector = RegionDetector(
        [earlier, later],
        RegionRetrievalIndex(
            model_id="unused",
            index=faiss.IndexFlatIP(1),
            pairs=[],
            fingerprint="test",
        ),
        build_hash_index([earlier, later]),
    )

    result = detector.detect(patched_snapshot, candidate_id="mixed-history")

    assert result.priority == "automatic_vulnerability"
    assert result.candidate_region_count == 0
    assert {
        (state.advisories[0].ghsa_id, state.status)
        for state in result.vulnerability_states
    } == {
        ("GHSA-earlier", "patched"),
        ("GHSA-later", "vulnerable"),
    }


def test_unsupported_syntax_is_explicitly_reported():
    assert source_is_supported("function valid(value) { return value; }")
    assert not source_is_supported("function invalid(value { return value; }")
