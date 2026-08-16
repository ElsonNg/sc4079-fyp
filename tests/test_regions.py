import faiss
import numpy as np
import pytest

from corpus.models.corpus import CorpusEntry, DiagnosticLine
from pipeline.controller.region_extraction import (
    enumerate_candidate_regions,
    extract_vulnerability_regions,
    source_is_supported,
)
from pipeline.controller.region_retrieval import aggregate_region_hits
from pipeline.controller.hashing import HashIndex
from pipeline.controller.region_detection import RegionDetector, RegionDetectorConfig
from pipeline.controller.region_retrieval import RegionRetrievalIndex
from pipeline.controller.region_verification import verify_region_pair
from pipeline.models.regions import RegionRetrievalMatch


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
    assert evidence.vulnerable_score == pytest.approx(
        (
            evidence.structural_vulnerable
            + evidence.token_vulnerable
            + evidence.semantic_vulnerable
        ) / 3
    )


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


def test_unsupported_syntax_is_explicitly_reported():
    assert source_is_supported("function valid(value) { return value; }")
    assert not source_is_supported("function invalid(value { return value; }")
