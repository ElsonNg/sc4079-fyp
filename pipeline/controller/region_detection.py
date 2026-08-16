"""Active AST-region vulnerable-clone detection pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from corpus.models.corpus import CorpusEntry
from pipeline.controller.hashing import HashIndex, build_hash_index, lookup
from pipeline.controller.region_extraction import (
    enumerate_candidate_regions,
    extract_corpus_region_pairs,
    source_is_supported,
)
from pipeline.controller.region_retrieval import (
    DEFAULT_REGION_THRESHOLD,
    DEFAULT_REGION_TOP_K,
    RegionRetrievalIndex,
    aggregate_region_hits,
    build_region_index,
    load_region_index,
    query_region_batch,
    query_regions,
    save_region_index,
)
from pipeline.controller.region_verification import (
    RegionVerifierConfig,
    classify_evidence,
    verify_region_pair,
)
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.models.regions import (
    RegionAggregate,
    RegionDetectionResult,
)


@dataclass(frozen=True)
class RegionDetectorConfig:
    model_id: str = DEFAULT_MODEL_ID
    retrieval_top_k: int = DEFAULT_REGION_TOP_K
    retrieval_threshold: float = DEFAULT_REGION_THRESHOLD
    max_candidate_regions: int = 96
    max_verification_candidates: int = 5
    # Kept for a later alignment ablation; inactive while the verifier uses
    # the simpler AST/token/semantic score.
    use_embedding_alignment_fallback: bool = False
    verifier: RegionVerifierConfig = RegionVerifierConfig()


class RegionDetector:
    """Detector using region retrieval and localized vulnerable/patched checks."""

    def __init__(
        self,
        entries: list[CorpusEntry],
        region_index: RegionRetrievalIndex,
        hash_index: HashIndex,
        config: RegionDetectorConfig | None = None,
    ) -> None:
        self.entries = entries
        self.region_index = region_index
        self.hash_index = hash_index
        self.config = config or RegionDetectorConfig()
        self.pairs = {pair.pair_id: pair for pair in region_index.pairs}

    def detect(
        self,
        candidate_source: str,
        candidate_id: str | None = None,
        _candidate_regions=None,
        _matches=None,
    ) -> RegionDetectionResult:
        if not source_is_supported(candidate_source):
            return RegionDetectionResult(
                status="manual_review",
                candidate_id=candidate_id,
                candidate_region_count=0,
                retrieval_match_count=0,
                parser_supported=False,
                message="Candidate syntax is unsupported or could not be parsed safely",
            )
        hash_matches = lookup(candidate_source, self.hash_index)
        hash_types = sorted({match.match_type for match in hash_matches})
        vulnerable_hashes = [match for match in hash_matches if match.side == "vulnerable"]
        patched_hashes = [match for match in hash_matches if match.side == "patched"]
        if vulnerable_hashes and not patched_hashes:
            return RegionDetectionResult(
                status="flagged",
                candidate_id=candidate_id,
                provenance_confidence="high",
                hash_match_types=hash_types,
                candidate_region_count=0,
                retrieval_match_count=0,
                message="High-confidence vulnerable-side hash match",
            )
        if patched_hashes and not vulnerable_hashes:
            return RegionDetectionResult(
                status="cleared",
                candidate_id=candidate_id,
                provenance_confidence="none",
                hash_match_types=hash_types,
                candidate_region_count=0,
                retrieval_match_count=0,
                message="Patched-side hash match without a vulnerable-side match",
            )

        candidate_regions = _candidate_regions or enumerate_candidate_regions(
            candidate_source,
            candidate_id=candidate_id,
            max_regions=self.config.max_candidate_regions,
        )
        matches = _matches if _matches is not None else query_regions(
            candidate_regions,
            self.region_index,
            top_k=self.config.retrieval_top_k,
            threshold=self.config.retrieval_threshold,
        )
        grouped = aggregate_region_hits(matches)
        aggregates: list[RegionAggregate] = []
        for pair_id, pair_matches in grouped:
            candidate_region_ids = sorted({match.candidate_region_id for match in pair_matches})
            granularities = sorted({match.candidate_granularity for match in pair_matches})
            aggregates.append(
                RegionAggregate(
                    pair_id=pair_id,
                    best_similarity=max(match.similarity for match in pair_matches),
                    support_count=len(candidate_region_ids),
                    candidate_region_ids=candidate_region_ids,
                    granularities=granularities,
                    top_matches=sorted(pair_matches, key=lambda item: item.similarity, reverse=True)[:5],
                )
            )
        aggregates = aggregates[: self.config.max_verification_candidates]

        regions_by_id = {candidate.region.region_id: candidate.region for candidate in candidate_regions}
        evidence = []
        for aggregate in aggregates:
            best_match = max(aggregate.top_matches, key=lambda item: item.similarity)
            candidate_region = regions_by_id[best_match.candidate_region_id]
            pair = self.pairs[aggregate.pair_id]
            evidence.append(
                verify_region_pair(
                    candidate_region,
                    pair,
                    retrieval_similarity=best_match.similarity,
                    config=self.config.verifier,
                    model_id=self.config.model_id,
                    use_embedding_alignment=self.config.use_embedding_alignment_fallback,
                )
            )
        status, provenance = classify_evidence(evidence, aggregates, self.config.verifier)
        return RegionDetectionResult(
            status=status,
            candidate_id=candidate_id,
            provenance_confidence=provenance,
            hash_match_types=hash_types,
            candidate_region_count=len(candidate_regions),
            retrieval_match_count=len(matches),
            aggregates=aggregates,
            evidence=evidence,
            message=None if evidence else "No vulnerable AST-region evidence retrieved",
        )

    def detect_batch(
        self,
        candidates: list[tuple[str | None, str]],
    ) -> list[RegionDetectionResult]:
        """Detect a batch while encoding all candidate regions in one model call."""
        prepared: list[tuple[str | None, str, list]] = []
        flattened = []
        offsets: list[tuple[int, int]] = []
        for candidate_id, source in candidates:
            regions = enumerate_candidate_regions(
                source,
                candidate_id=candidate_id,
                max_regions=self.config.max_candidate_regions,
            )
            start = len(flattened)
            flattened.extend(regions)
            offsets.append((start, len(flattened)))
            prepared.append((candidate_id, source, regions))
        batches = query_region_batch(
            flattened,
            self.region_index,
            top_k=self.config.retrieval_top_k,
            threshold=self.config.retrieval_threshold,
        )
        results: list[RegionDetectionResult] = []
        for (candidate_id, source, regions), (start, end) in zip(prepared, offsets):
            matches = [match for batch in batches[start:end] for match in batch]
            results.append(
                self.detect(
                    source,
                    candidate_id=candidate_id,
                    _candidate_regions=regions,
                    _matches=matches,
                )
            )
        return results


def build_region_detector(
    entries: list[CorpusEntry],
    config: RegionDetectorConfig | None = None,
    save_index_artifact: bool = True,
    progress_callback=None,
) -> RegionDetector:
    config = config or RegionDetectorConfig()
    pairs = extract_corpus_region_pairs(entries)
    region_index = load_region_index(pairs, model_id=config.model_id)
    if region_index is None:
        region_index = build_region_index(
            pairs,
            model_id=config.model_id,
            progress_callback=progress_callback,
        )
        if save_index_artifact:
            save_region_index(region_index)
    return RegionDetector(entries, region_index, build_hash_index(entries), config)
