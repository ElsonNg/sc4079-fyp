"""Active AST-region vulnerable-clone detection pipeline."""

from __future__ import annotations

from dataclasses import dataclass

from corpus.controller.extraction import compute_diagnostic_lines
from corpus.models.corpus import CorpusEntry
from pipeline.controller.edit_distance import score_edit_distance
from pipeline.controller.local_correspondence import decide_local_correspondence
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
from pipeline.controller.parsing import extract_function_units, source_language
from pipeline.models.regions import (
    LineageAttribution,
    LineageConfidence,
    PackageApplicability,
    RegionAggregate,
    RegionDetectionResult,
    VulnerabilityState,
)

AdvisoryIdentity = tuple[str, ...]

# Canonical filename per language, used as a language hint for native hash helpers.
_LANGUAGE_FILENAME = {
    "javascript": "candidate.js",
    "typescript": "candidate.ts",
    "tsx": "candidate.tsx",
}


def resolve_candidate_language(candidate_id: str | None, language: str | None) -> str:
    """Language for a detection candidate. Prefer an explicit ``language`` from the
    caller; otherwise derive it from ``candidate_id``, stripping any ``::start:end``
    span suffix first so a scan id like "src/a.ts::10:20" is read as TypeScript rather
    than silently falling back to JavaScript."""
    if language:
        return source_language(language=language)
    return source_language((candidate_id or "").split("::", 1)[0])


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
    # Completing S -> T -> E is stronger evidence than retrieval-derived lineage
    # confidence. Do not let a low lineage score veto an already verified boundary.
    vulnerable = [item for item in states if item.status == "vulnerable"]
    if any(not item.contradictions for item in vulnerable):
        # Package ownership explains how code entered the project; it does not
        # invalidate strong code-level evidence. Keep applicability as report
        # context and reserve manual review for genuinely ambiguous boundaries.
        return "automatic_vulnerability"
    if vulnerable:
        return "manual_review"
    patched = [item for item in states if item.status == "patched"]
    unresolved = [
        item for item in scoped
        if item.status == "uncertain"
        and not item.boundary_rejected
    ]
    strong_uncertainty = [
        item for item in unresolved
        if item.token_gate_passed or bool(item.contradictions)
    ]
    # A retrieved boundary that never completed S/T is weak alternative-search
    # noise. It must not override an independently verified patched boundary.
    if patched and not strong_uncertainty:
        return "informational_lineage"
    if strong_uncertainty:
        return "manual_review"
    if unresolved:
        return "manual_review"
    return "none"


def _confidence(score: float) -> LineageConfidence:
    if score >= 0.82:
        return "high"
    if score >= 0.68:
        return "medium"
    if score >= 0.55:
        return "low"
    return "none"


def _infer_candidate_function_name(source: str, filename: str) -> str | None:
    """Return a name only when the submitted source has one outer function."""
    units = extract_function_units(source, filename=filename)
    outer = [
        unit for unit in units
        if not any(
            other.start_byte <= unit.start_byte
            and unit.end_byte <= other.end_byte
            and (other.start_byte, other.end_byte) != (unit.start_byte, unit.end_byte)
            for other in units
        )
    ]
    return outer[0].name if len(outer) == 1 else None


@dataclass(frozen=True)
class RegionDetectorConfig:
    model_id: str = DEFAULT_MODEL_ID
    retrieval_top_k: int = DEFAULT_REGION_TOP_K
    retrieval_threshold: float = DEFAULT_REGION_THRESHOLD
    max_candidate_regions: int = 96
    max_verification_candidates: int = 5
    max_verification_regions_per_pair: int = 3
    # Evaluation-only guard: compare candidates only with corpus evidence written
    # in the same source language. Production keeps this disabled to retain the
    # Native same-language matching is enforced for every detector mode.
    same_language_only: bool = True
    # Kept for a later alignment ablation; inactive under the staged verifier.
    use_embedding_alignment_fallback: bool = False
    # Experimental late fallback. It never bypasses S/T, hashes, identity rejection,
    # or contradictions, and is deliberately disabled in production by default.
    include_local_correspondence_fallback: bool = False
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
        self.boundary_function_pairs = {
            pair.fix_boundary_id: pair
            for pair in region_index.pairs
            if pair.vulnerable_region.granularity == "function"
        }
        self.boundary_diagnostics = {}
        self.lineage_meta = {item.lineage_id: item for item in cluster_corpus_entries(entries)}

    def detect(
        self,
        candidate_source: str,
        candidate_id: str | None = None,
        language: str | None = None,
        candidate_function_name: str | None = None,
        _candidate_regions=None,
        _matches=None,
    ) -> RegionDetectionResult:
        # ``candidate_id`` doubles as a unique identity and, historically, the only
        # language hint -- but a scan passes ids like "src/a.ts::10:20" whose ``::``
        # span suffix hides the extension, so TypeScript was silently analysed as
        # JavaScript (no type erasure; type-annotated bodies failed to parse). Prefer
        # an explicit ``language`` from the caller and fall back to the id only when it
        # is absent, deriving language from the path before any ``::`` span marker.
        candidate_language = resolve_candidate_language(candidate_id, language)
        language_filename = _LANGUAGE_FILENAME.get(candidate_language, "candidate.js")
        if not source_is_supported(candidate_source, filename=language_filename):
            return RegionDetectionResult(
                priority="manual_review",
                candidate_id=candidate_id,
                candidate_region_count=0,
                retrieval_match_count=0,
                parser_supported=False,
                message="Candidate syntax is unsupported or could not be parsed safely",
            )
        hash_matches = lookup(candidate_source, self.hash_index, filename=language_filename)
        hash_matches = [match for match in hash_matches if match.source_language == candidate_language]
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
                    abstention_reason=(
                        "CONTRADICTORY_EVIDENCE" if status == "uncertain" else None
                    ),
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
            function_name=(
                candidate_function_name
                or _infer_candidate_function_name(candidate_source, language_filename)
            ),
            max_regions=self.config.max_candidate_regions,
            filename=language_filename,
        )
        matches = _matches if _matches is not None else query_regions(
            candidate_regions,
            self.region_index,
            top_k=self.config.retrieval_top_k,
            threshold=self.config.retrieval_threshold,
        )
        matches = [match for match in matches if match.source_language == candidate_language]
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
        function_names_by_region_id = {
            candidate.region.region_id: candidate.function_name
            for candidate in candidate_regions
        }
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
                        language=pair.source_language,
                        candidate_function_name=function_names_by_region_id.get(match.candidate_region_id),
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
            pair = self.boundary_function_pairs.get(
                boundary_id,
                self.pairs[scoped_evidence[0].pair_id],
            )
            preliminary = classify_boundary(
                scoped_evidence,
                pair,
                self.config.verifier,
            )
            if not preliminary.token_gate_passed:
                states.append(preliminary)
                continue
            diagnostics = self.boundary_diagnostics.get(boundary_id)
            if diagnostics is None:
                diagnostics = compute_diagnostic_lines(
                    pair.vulnerable_region.source,
                    pair.patched_region.source,
                    language=pair.source_language,
                )
                self.boundary_diagnostics[boundary_id] = diagnostics
            edit = score_edit_distance(candidate_source, diagnostics)
            state = classify_boundary(
                scoped_evidence,
                pair,
                self.config.verifier,
                edit=edit,
            )
            if (
                self.config.include_local_correspondence_fallback
                and state.status == "uncertain"
                and state.token_gate_passed
                and not state.boundary_rejected
                and not state.contradictions
            ):
                local = decide_local_correspondence(
                    pair.vulnerable_region.source,
                    pair.patched_region.source,
                    candidate_source,
                    filename=language_filename,
                )
                decisive_methods = sorted(local["decisive"])
                update = {
                    "local_correspondence_attempted": True,
                    "local_correspondence_status": local["status"],
                    "local_correspondence_methods": decisive_methods,
                    "local_correspondence_reason": local["reason"],
                    "local_correspondence_prior_abstention_reason": state.abstention_reason,
                }
                if local["status"] in {"vulnerable", "patched"}:
                    update.update({
                        "status": local["status"],
                        "abstention_reason": None,
                        "local_correspondence_used": True,
                        "fix_evidence": state.fix_evidence + [
                            "Experimental local correspondence: "
                            + ", ".join(decisive_methods)
                        ],
                    })
                state = state.model_copy(update=update)
            states.append(state)

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
            inferred_name = _infer_candidate_function_name(source, "candidate.js")
            regions = enumerate_candidate_regions(
                source,
                candidate_id=candidate_id,
                function_name=inferred_name,
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
