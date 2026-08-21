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
    classify_boundary,
    deduplicate_evidence,
    verify_region_pair,
)
from pipeline.controller.provenance import cluster_corpus_entries
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.models.regions import (
    LineageAttribution,
    LineageConfidence,
    PackageApplicability,
    RegionAggregate,
    RegionDetectionResult,
    VulnerabilityState,
)

AdvisoryIdentity = tuple[str, ...]


def _hash_identity(match) -> AdvisoryIdentity:
    if match.lineage_id:
        return "lineage", match.lineage_id
    return match.ghsa_id, match.fix_commit_sha, match.file_path, match.function_name


def _pair_identity(pair) -> AdvisoryIdentity:
    if pair.lineage_id:
        return "lineage", pair.lineage_id
    return pair.ghsa_id, pair.fix_commit_sha, pair.file_path, pair.function_name


def derive_priority(lineages, states, applicabilities):
    credible = {item.lineage_id for item in lineages if item.confidence in {"high", "medium"}}
    scoped = [item for item in states if item.lineage_id in credible]
    vulnerable = [item for item in scoped if item.status == "vulnerable"]
    if any(not item.contradictions for item in vulnerable):
        # Package ownership explains how code entered the project; it does not
        # invalidate strong code-level evidence. Keep applicability as report
        # context and reserve manual review for genuinely ambiguous boundaries.
        return "automatic_vulnerability"
    if vulnerable:
        return "manual_review"
    if any(item.status == "uncertain" for item in scoped):
        return "manual_review"
    if scoped and all(item.status == "patched" for item in scoped):
        return "informational_lineage"
    return "none"


def _confidence(score: float) -> LineageConfidence:
    if score >= 0.82:
        return "high"
    if score >= 0.68:
        return "medium"
    if score >= 0.55:
        return "low"
    return "none"


@dataclass(frozen=True)
class RegionDetectorConfig:
    model_id: str = DEFAULT_MODEL_ID
    retrieval_top_k: int = DEFAULT_REGION_TOP_K
    retrieval_threshold: float = DEFAULT_REGION_THRESHOLD
    max_candidate_regions: int = 96
    max_verification_candidates: int = 5
    max_verification_regions_per_pair: int = 3
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
        self.lineage_meta = {item.lineage_id: item for item in cluster_corpus_entries(entries)}

    def detect(
        self,
        candidate_source: str,
        candidate_id: str | None = None,
        _candidate_regions=None,
        _matches=None,
    ) -> RegionDetectionResult:
        if not source_is_supported(candidate_source):
            return RegionDetectionResult(
                priority="manual_review",
                candidate_id=candidate_id,
                candidate_region_count=0,
                retrieval_match_count=0,
                parser_supported=False,
                message="Candidate syntax is unsupported or could not be parsed safely",
            )
        hash_matches = lookup(candidate_source, self.hash_index)
        hash_types = sorted({match.match_type for match in hash_matches})
        if hash_matches:
            lineage_ids = sorted({match.lineage_id for match in hash_matches if match.lineage_id})
            lineages = []
            for lineage_id in lineage_ids:
                members = [match for match in hash_matches if match.lineage_id == lineage_id]
                first = members[0]
                aliases = {
                    alias.model_dump_json(): alias
                    for match in members for alias in match.advisories
                }
                lineages.append(LineageAttribution(
                    lineage_id=lineage_id,
                    confidence="high",
                    score=1.0,
                    repo=first.repo,
                    file_path=first.file_path,
                    reference_function=first.function_name,
                    associated_advisories=list(aliases.values()),
                ))
            states = []
            for boundary_id in sorted({match.fix_boundary_id for match in hash_matches if match.fix_boundary_id}):
                members = [match for match in hash_matches if match.fix_boundary_id == boundary_id]
                first = members[0]
                vulnerable = any(match.side == "vulnerable" for match in members)
                patched = any(match.side == "patched" for match in members)
                status = "uncertain" if vulnerable and patched else "vulnerable" if vulnerable else "patched"
                states.append(VulnerabilityState(
                    lineage_id=first.lineage_id or "",
                    fix_boundary_id=boundary_id,
                    fix_commit_sha=first.fix_commit_sha,
                    status=status,
                    vulnerable_score=1.0 if vulnerable else 0.0,
                    patched_score=1.0 if patched else 0.0,
                    contrast_score=0.0 if vulnerable and patched else 1.0 if vulnerable else -1.0,
                    fix_evidence=[f"{first.match_type} {first.side}-side hash match"],
                    contradictions=["vulnerable and patched hashes both match"] if vulnerable and patched else [],
                    advisories=first.advisories,
                ))
            applications = self._unknown_applicabilities(lineages)
            return RegionDetectionResult(
                priority=derive_priority(lineages, states, applications),
                candidate_id=candidate_id,
                hash_match_types=hash_types,
                hash_matches=hash_matches,
                candidate_region_count=0,
                retrieval_match_count=0,
                lineages=lineages,
                vulnerability_states=states,
                package_applicabilities=applications,
                message="Resolved deterministic hash evidence by lineage and fix boundary",
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
                    lineage_id=self.pairs[pair_id].lineage_id,
                    fix_boundary_id=self.pairs[pair_id].fix_boundary_id,
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
            pair = self.pairs[aggregate.pair_id]
            seen_candidate_regions: set[str] = set()
            verified_region_count = 0
            for match in sorted(
                aggregate.top_matches,
                key=lambda item: item.similarity,
                reverse=True,
            ):
                if match.candidate_region_id in seen_candidate_regions:
                    continue
                seen_candidate_regions.add(match.candidate_region_id)
                candidate_region = regions_by_id[match.candidate_region_id]
                if not candidate_region_is_informative(candidate_region):
                    continue
                evidence.append(
                    verify_region_pair(
                        candidate_region,
                        pair,
                        retrieval_similarity=match.similarity,
                        config=self.config.verifier,
                        model_id=self.config.model_id,
                        use_embedding_alignment=self.config.use_embedding_alignment_fallback,
                    )
                )
                verified_region_count += 1
                if verified_region_count >= self.config.max_verification_regions_per_pair:
                    break
        evidence_by_boundary = {}
        for item in evidence:
            pair = self.pairs[item.pair_id]
            evidence_by_boundary.setdefault(pair.fix_boundary_id, []).append(item)
        states = []
        for boundary_id, scoped_evidence in sorted(evidence_by_boundary.items()):
            pair = self.pairs[scoped_evidence[0].pair_id]
            states.append(classify_boundary(scoped_evidence, pair, self.config.verifier))

        lineages = []
        evidence_by_lineage = {}
        for item in evidence:
            lineage_id = self.pairs[item.pair_id].lineage_id
            if lineage_id:
                evidence_by_lineage.setdefault(lineage_id, []).append(item)
        for lineage_id, scoped in sorted(evidence_by_lineage.items()):
            independent = deduplicate_evidence(scoped)
            span_scores = sorted(
                0.60 * item.retrieval_similarity
                + 0.25 * max(item.structural_vulnerable, item.structural_patched)
                + 0.15 * 0.5
                for item in independent
            )
            score = span_scores[len(span_scores) // 2] if span_scores else 0.0
            meta = self.lineage_meta[lineage_id]
            lineages.append(LineageAttribution(
                lineage_id=lineage_id,
                confidence=_confidence(score),
                score=score,
                repo=meta.representative.repo,
                file_path=meta.representative.file_path,
                reference_function=meta.representative.function_name,
                associated_advisories=list(meta.advisories),
                evidence_pair_ids=sorted({item.pair_id for item in independent}),
            ))
        lineages.sort(key=lambda item: (-item.score, item.lineage_id))
        applications = self._unknown_applicabilities(lineages)
        return RegionDetectionResult(
            priority=derive_priority(lineages, states, applications),
            candidate_id=candidate_id,
            hash_match_types=hash_types,
            hash_matches=hash_matches,
            candidate_region_count=len(candidate_regions),
            retrieval_match_count=len(matches),
            aggregates=aggregates,
            evidence=evidence,
            lineages=lineages,
            vulnerability_states=states,
            package_applicabilities=applications,
            message=None if evidence else "No credible AST-region lineage evidence retrieved",
        )

    @staticmethod
    def _unknown_applicabilities(lineages):
        values = []
        for lineage in lineages:
            packages = {
                (alias.package_name, alias.ecosystem or "npm")
                for alias in lineage.associated_advisories if alias.package_name
            }
            values.extend(
                PackageApplicability(
                    lineage_id=lineage.lineage_id,
                    package=package,
                    ecosystem=ecosystem,
                )
                for package, ecosystem in sorted(packages)
            )
        return values

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
