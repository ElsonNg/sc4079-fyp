"""Active AST-region vulnerable-clone detection pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from corpus.models.corpus import CorpusEntry
from pipeline.controller.hashing import HashIndex, build_hash_index, lookup
from pipeline.controller.region_extraction import (
    candidate_region_is_informative,
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
    ProvenanceConfidence,
    RegionAdvisoryVerdict,
    RegionAggregate,
    RegionDetectionResult,
)

AdvisoryIdentity = tuple[str, str, str, str | None]


def _hash_identity(match) -> AdvisoryIdentity:
    return match.ghsa_id, match.fix_commit_sha, match.file_path, match.function_name


def _pair_identity(pair) -> AdvisoryIdentity:
    return pair.ghsa_id, pair.fix_commit_sha, pair.file_path, pair.function_name


def _hash_advisory_verdicts(hash_matches) -> list[RegionAdvisoryVerdict]:
    grouped = {}
    for match in hash_matches:
        grouped.setdefault(_hash_identity(match), []).append(match)

    verdicts = []
    for identity in sorted(grouped, key=lambda item: tuple(value or "" for value in item)):
        matches = grouped[identity]
        exact_vulnerable = any(match.side == "vulnerable" and match.match_type == "exact" for match in matches)
        exact_patched = any(match.side == "patched" and match.match_type == "exact" for match in matches)
        vulnerable = any(match.side == "vulnerable" for match in matches)
        patched = any(match.side == "patched" for match in matches)

        if exact_vulnerable and exact_patched:
            status = "manual_review"
            confidence: ProvenanceConfidence = "ambiguous"
            message = "Conflicting exact vulnerable-side and patched-side hash matches"
        elif exact_patched:
            status = "cleared"
            confidence = "none"
            message = "Exact patched-side hash match for this advisory identity"
        elif exact_vulnerable:
            status = "flagged"
            confidence = "high"
            message = "Exact vulnerable-side hash match for this advisory identity"
        elif vulnerable and patched:
            status = "manual_review"
            confidence = "ambiguous"
            message = "Conflicting abstracted vulnerable-side and patched-side hash matches"
        elif patched:
            status = "cleared"
            confidence = "none"
            message = "Abstracted patched-side hash match for this advisory identity"
        else:
            status = "flagged"
            confidence = "high"
            message = "Abstracted vulnerable-side hash match for this advisory identity"

        first = matches[0]
        verdicts.append(
            RegionAdvisoryVerdict(
                ghsa_id=first.ghsa_id,
                cve_id=first.cve_id,
                fix_commit_sha=first.fix_commit_sha,
                file_path=first.file_path,
                function_name=first.function_name,
                status=status,
                provenance_confidence=confidence,
                hash_match_types=sorted({match.match_type for match in matches}),
                message=message,
            )
        )
    return verdicts


def _overall_verdict(verdicts: list[RegionAdvisoryVerdict]) -> tuple[str, ProvenanceConfidence]:
    flagged = [verdict for verdict in verdicts if verdict.status == "flagged"]
    if flagged:
        confidence_order = {"none": 0, "ambiguous": 1, "low": 2, "medium": 3, "high": 4}
        confidence = max(flagged, key=lambda verdict: confidence_order[verdict.provenance_confidence]).provenance_confidence
        return "flagged", confidence
    if any(verdict.status == "manual_review" for verdict in verdicts):
        return "manual_review", "ambiguous"
    return "cleared", "none"


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
        if hash_matches:
            advisory_verdicts = _hash_advisory_verdicts(hash_matches)
            status, provenance = _overall_verdict(advisory_verdicts)
            return RegionDetectionResult(
                status=status,
                candidate_id=candidate_id,
                provenance_confidence=provenance,
                hash_match_types=hash_types,
                hash_matches=hash_matches,
                candidate_region_count=0,
                retrieval_match_count=0,
                advisory_verdicts=advisory_verdicts,
                message="Resolved deterministic hash matches per advisory identity",
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
            if not candidate_region_is_informative(candidate_region):
                continue
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
        evidence_by_identity = {}
        for item in evidence:
            identity = _pair_identity(self.pairs[item.pair_id])
            evidence_by_identity.setdefault(identity, []).append(item)
        aggregates_by_pair = {aggregate.pair_id: aggregate for aggregate in aggregates}
        advisory_verdicts = []
        for identity in sorted(evidence_by_identity, key=lambda item: tuple(value or "" for value in item)):
            scoped_evidence = evidence_by_identity[identity]
            scoped_aggregates = [
                aggregates_by_pair[item.pair_id]
                for item in scoped_evidence
                if item.pair_id in aggregates_by_pair
            ]
            scoped_status, scoped_provenance = classify_evidence(
                scoped_evidence,
                scoped_aggregates,
                self.config.verifier,
            )
            pair = self.pairs[scoped_evidence[0].pair_id]
            advisory_verdicts.append(
                RegionAdvisoryVerdict(
                    ghsa_id=pair.ghsa_id,
                    cve_id=pair.cve_id,
                    fix_commit_sha=pair.fix_commit_sha,
                    file_path=pair.file_path,
                    function_name=pair.function_name,
                    status=scoped_status,
                    provenance_confidence=scoped_provenance,
                    evidence_pair_ids=[item.pair_id for item in scoped_evidence],
                )
            )
        status, provenance = _overall_verdict(advisory_verdicts)
        return RegionDetectionResult(
            status=status,
            candidate_id=candidate_id,
            provenance_confidence=provenance,
            hash_match_types=hash_types,
            hash_matches=hash_matches,
            candidate_region_count=len(candidate_regions),
            retrieval_match_count=len(matches),
            aggregates=aggregates,
            evidence=evidence,
            advisory_verdicts=advisory_verdicts,
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
