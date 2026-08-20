import faiss
import numpy as np
import pytest

from corpus.models.corpus import CorpusEntry, DiagnosticLine
from pipeline.controller.region_extraction import (
    candidate_region_is_informative,
    enumerate_candidate_regions,
    extract_corpus_region_pairs,
    extract_vulnerability_regions,
    source_is_supported,
)
from pipeline.controller.region_retrieval import aggregate_region_hits
from pipeline.controller.hashing import HashIndex, build_hash_index
from pipeline.controller.region_detection import RegionDetector, RegionDetectorConfig
from pipeline.controller.region_retrieval import RegionRetrievalIndex
from pipeline.controller.region_verification import classify_evidence, verify_region_pair
from pipeline.models.regions import RegionAggregate, RegionRetrievalMatch, RegionVerificationEvidence


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
    assert all(pair.change_kind == "replacement" for pair in pairs)
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
        update={
            "ghsa_id": "GHSA-alias",
            "cve_id": "CVE-ALIAS",
            "package_name": "test-package-fork",
        }
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
    assert all(pair.change_kind == "insertion" for pair in pairs)
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

    assert evidence.vulnerable_score > evidence.patched_score
    assert evidence.vulnerable_minus_patched > 0
    assert evidence.ast_coverage > 0
    assert evidence.local_alignment_vulnerable is None
    assert evidence.local_alignment_patched is None
    assert evidence.fallback_used is False
    available = [evidence.structural_vulnerable, evidence.token_vulnerable]
    if evidence.semantic_vulnerable is not None:
        available.append(evidence.semantic_vulnerable)
    assert evidence.vulnerable_score == pytest.approx(sum(available) / len(available))


def test_empty_semantic_features_are_unavailable_instead_of_perfect_similarity():
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

    assert evidence.semantic_vulnerable is None
    assert evidence.semantic_patched is None
    assert evidence.vulnerable_score == pytest.approx(
        (evidence.structural_vulnerable + evidence.token_vulnerable) / 2
    )


def _evidence(pair_id: str, vulnerable_score: float, margin: float) -> RegionVerificationEvidence:
    return RegionVerificationEvidence(
        pair_id=pair_id,
        candidate_region_id=f"candidate:{pair_id}",
        vulnerable_region_id=f"{pair_id}:vulnerable",
        patched_region_id=f"{pair_id}:patched",
        retrieval_similarity=0.9,
        structural_vulnerable=vulnerable_score,
        structural_patched=vulnerable_score - margin,
        token_vulnerable=vulnerable_score,
        token_patched=vulnerable_score - margin,
        vulnerable_score=vulnerable_score,
        patched_score=vulnerable_score - margin,
        vulnerable_minus_patched=margin,
        ast_coverage=1.0,
    )


def test_classification_does_not_let_a_low_score_large_margin_hide_passing_evidence():
    low_score = _evidence("pair-low", vulnerable_score=0.72, margin=0.60)
    passing = _evidence("pair-pass", vulnerable_score=0.90, margin=0.20)
    corroborating = _evidence("pair-corroborating", vulnerable_score=0.86, margin=0.16)
    aggregates = [
        RegionAggregate(pair_id="pair-low", best_similarity=0.9, support_count=1),
        RegionAggregate(pair_id="pair-pass", best_similarity=0.9, support_count=1),
        RegionAggregate(pair_id="pair-corroborating", best_similarity=0.9, support_count=1),
    ]

    status, _ = classify_evidence([low_score, passing, corroborating], aggregates)

    assert status == "flagged"


def test_classification_does_not_flag_from_one_supporting_region():
    passing = _evidence("pair-pass", vulnerable_score=0.90, margin=0.20)
    aggregates = [RegionAggregate(pair_id="pair-pass", best_similarity=0.9, support_count=4)]

    status, _ = classify_evidence([passing], aggregates)

    assert status == "manual_review"


def test_classification_downgrades_when_patched_contradiction_is_as_strong():
    first = _evidence("pair-first", vulnerable_score=0.90, margin=0.20)
    second = _evidence("pair-second", vulnerable_score=0.86, margin=0.16)
    contradiction = _evidence("pair-patched", vulnerable_score=0.55, margin=-0.25)
    aggregates = [
        RegionAggregate(pair_id=item.pair_id, best_similarity=0.9, support_count=1)
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

    monkeypatch.setattr("pipeline.controller.embedding.encode", fake_encode)
    index = faiss.IndexFlatIP(8)
    index.add(np.ones((len(pairs), 8), dtype=np.float32) / np.sqrt(8))
    detector = RegionDetector(
        [entry],
        RegionRetrievalIndex(model_id="fake", index=index, pairs=pairs, fingerprint="test"),
        HashIndex(),
        RegionDetectorConfig(model_id="fake", retrieval_top_k=4, max_candidate_regions=24),
    )

    result = detector.detect(vulnerable, candidate_id="C-region")

    assert result.status == "flagged"
    assert result.candidate_region_count > 0
    assert result.retrieval_match_count > 0
    assert result.evidence
    assert len(result.advisory_verdicts) == 1
    assert result.advisory_verdicts[0].ghsa_id == entry.ghsa_id


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

    assert result.status == "flagged"
    assert result.candidate_region_count == 0
    assert {(item.ghsa_id, item.status) for item in result.advisory_verdicts} == {
        ("GHSA-earlier", "cleared"),
        ("GHSA-later", "flagged"),
    }


def test_unsupported_syntax_is_explicitly_reported():
    assert source_is_supported("function valid(value) { return value; }")
    assert not source_is_supported("function invalid(value { return value; }")
