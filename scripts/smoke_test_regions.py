"""Manual smoke test for the AST-region detector with one real corpus entry.

Run from the repository root. This loads the configured embedding model and performs
one region-index build, region retrieval, and localized verification pass:

    PYTHONPATH=. .venv/bin/python -u scripts/smoke_test_regions.py
"""

from corpus.controller.store import load_entries
from pipeline.controller.hashing import build_hash_index
from pipeline.controller.region_detection import RegionDetector, RegionDetectorConfig
from pipeline.controller.region_extraction import extract_vulnerability_regions, enumerate_candidate_regions
from pipeline.controller.region_retrieval import build_region_index


def main() -> None:
    entry = load_entries()[62]  # Stable current-corpus smoke entry: GHSA-3p68-rc4w-qgx5.
    pairs = extract_vulnerability_regions(entry)
    config = RegionDetectorConfig(
        retrieval_top_k=4,
        retrieval_threshold=0.0,
        max_candidate_regions=24,
        max_verification_candidates=2,
    )
    index = build_region_index(pairs, model_id=config.model_id)
    detector = RegionDetector([entry], index, build_hash_index([entry]), config)
    candidate = entry.vulnerable_function.replace("{", "{\n  if (false) { void 0; }", 1)
    result = detector.detect(candidate, candidate_id="SMOKE-REGION")

    print(f"entry: {entry.ghsa_id}/{entry.function_name}")
    print(f"corpus regions: {len(pairs)}")
    print(f"candidate regions: {len(enumerate_candidate_regions(candidate, max_regions=24))}")
    print(f"status: {result.status}")
    print(f"provenance: {result.provenance_confidence}")
    print(f"retrieval matches: {result.retrieval_match_count}")
    print(f"evidence records: {len(result.evidence)}")


if __name__ == "__main__":
    main()
