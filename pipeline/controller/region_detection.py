"""Active AST-region vulnerable-clone detection pipeline."""

from __future__ import annotations

from corpus.controller.extraction import compute_diagnostic_lines
from corpus.models.corpus import CorpusEntry
from pipeline.detection.verification.edit_distance import score_edit_distance
from pipeline.controller.hashing import HashIndex, build_hash_index, lookup
from pipeline.controller.local_correspondence import decide_local_correspondence
from pipeline.controller.parsing import extract_function_units, source_language
from pipeline.controller.provenance import cluster_corpus_entries
from pipeline.controller.region_extraction import (
    candidate_region_is_informative,
    enumerate_candidate_regions,
    extract_corpus_region_pairs,
    source_is_supported,
)
from pipeline.controller.region_retrieval import (
    RegionRetrievalIndex,
    build_region_index,
    load_region_index,
    query_region_batch,
    query_regions,
    save_region_index,
)
from pipeline.detection.verification.classification import classify_boundary
from pipeline.detection.verification.verifier import verify_region_pair
from pipeline.detection.config import (
    DEFAULT_MODEL_ID,
    DEFAULT_REGION_THRESHOLD,
    DEFAULT_REGION_TOP_K,
    RegionDetectorConfig,
    RegionVerifierConfig,
)
from pipeline.detection.hashing import build_hash_result
from pipeline.detection.retrieval import aggregate_retrieval_matches
from pipeline.detection.lineage import (
    attribute_lineages, lineage_confidence as _confidence, unknown_applicabilities,
)
from pipeline.detection.priority import derive_priority
from pipeline.models.boundary import VulnerabilityState, VulnerableRegionPair
from pipeline.models.region import CandidateRegion
from pipeline.models.region_retrieval import RegionAggregate
from pipeline.models.evidence import RegionVerificationEvidence
from pipeline.models.result import RegionDetectionResult

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
    return match.advisory.ghsa_id, match.origin.fix_commit_sha, match.origin.file_path, match.origin.function_name


def _pair_identity(pair) -> AdvisoryIdentity:
    if pair.lineage_id:
        return "lineage", pair.lineage_id
    return pair.advisory.ghsa_id, pair.origin.fix_commit_sha, pair.origin.file_path, pair.origin.function_name


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
        # Resolve language before parsing because scan IDs include a byte-span suffix.
        candidate_language = resolve_candidate_language(candidate_id, language)
        language_filename = _LANGUAGE_FILENAME.get(candidate_language, "candidate.js")
        if (
            self.config.max_candidate_chars is not None
            and len(candidate_source) > self.config.max_candidate_chars
        ):
            return RegionDetectionResult(
                priority="manual_review",
                candidate_id=candidate_id,
                candidate_region_count=0,
                retrieval_match_count=0,
                message=(
                    "Candidate complexity-skipped before retrieval: source has "
                    f"{len(candidate_source)} characters (limit "
                    f"{self.config.max_candidate_chars})"
                ),
            )
        if not source_is_supported(candidate_source, filename=language_filename):
            return RegionDetectionResult(
                priority="manual_review",
                candidate_id=candidate_id,
                candidate_region_count=0,
                retrieval_match_count=0,
                parser_supported=False,
                message="Candidate syntax is unsupported or could not be parsed safely",
            )

        # Resolve deterministic hash matches first and return before region retrieval if found.
        hash_matches = lookup(candidate_source, self.hash_index, filename=language_filename)
        hash_matches = [match for match in hash_matches if match.origin.source_language == candidate_language]
        hash_types = sorted({match.match_type for match in hash_matches})
        if hash_matches:
            return build_hash_result(hash_matches, candidate_id)

        # Retrieve similar corpus regions when hashes cannot resolve the function.
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
        matches = [match for match in matches if match.origin.source_language == candidate_language]

        # Group hits by reference pair and limit how many pairs reach verification.
        aggregates = aggregate_retrieval_matches(
            matches, self.pairs, self.config.max_verification_candidates,
        )

        # verification.verifier compares each selected region with both sides of its fix.
        evidence = self._verify_regions(candidate_regions, aggregates)

        # Combine region evidence by fix boundary before deciding vulnerable or patched.
        states = self._classify_boundaries(candidate_source, language_filename, evidence)

        # Attribute source lineage separately from each fix-boundary verdict.
        lineages = attribute_lineages(evidence, self.pairs, self.lineage_meta)

        # scanning.scan_directory later adds project-specific package applicability.
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

    def _verify_regions(
        self, candidate_regions: list[CandidateRegion], aggregates: list[RegionAggregate],
    ) -> list[RegionVerificationEvidence]:
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
                        language=pair.origin.source_language,
                        candidate_function_name=function_names_by_region_id.get(match.candidate_region_id),
                    )
                )
                verified_region_count += 1
                if verified_region_count >= self.config.max_verification_regions_per_pair:
                    break

        return evidence

    def _classify_boundaries(
        self, candidate_source: str, language_filename: str,
        evidence: list[RegionVerificationEvidence],
    ) -> list[VulnerabilityState]:
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
            if not preliminary.gates.token_gate_passed:
                states.append(preliminary)
                continue
            if (
                self.config.max_edit_candidate_chars is not None
                and len(candidate_source) > self.config.max_edit_candidate_chars
            ):
                support = preliminary.support.model_copy(update={
                    "fix_evidence": preliminary.support.fix_evidence + [
                        "Edit stage complexity-skipped: candidate source has "
                        f"{len(candidate_source)} characters (limit "
                        f"{self.config.max_edit_candidate_chars})"
                    ],
                })
                states.append(preliminary.model_copy(update={"support": support}))
                continue

            # Run edit scoring only after correspondence and size checks pass.
            diagnostics = self.boundary_diagnostics.get(boundary_id)
            if diagnostics is None:
                diagnostics = compute_diagnostic_lines(
                    pair.vulnerable_region.source,
                    pair.patched_region.source,
                    language=pair.origin.source_language,
                )
                self.boundary_diagnostics[boundary_id] = diagnostics
            edit = score_edit_distance(candidate_source, diagnostics)
            state = classify_boundary(
                scoped_evidence,
                pair,
                self.config.verifier,
                edit=edit,
            )

            # The optional local fallback gets a final chance to resolve eligible uncertain cases.
            if (
                self.config.include_local_correspondence_fallback
                and state.status == "uncertain"
                and state.gates.token_gate_passed
                and not state.gates.boundary_rejected
                and not state.support.contradictions
            ):
                state = self._apply_local_correspondence(
                    candidate_source, language_filename, pair, state,
                )
            states.append(state)

        return states

    def _apply_local_correspondence(
        self, candidate_source: str, language_filename: str,
        pair: VulnerableRegionPair, state: VulnerabilityState,
    ) -> VulnerabilityState:
        local = decide_local_correspondence(
            pair.vulnerable_region.source,
            pair.patched_region.source,
            candidate_source,
            filename=language_filename,
        )
        decisive_methods = sorted(local["decisive"])
        fallback_update = {
            "local_correspondence_attempted": True,
            "local_correspondence_status": local["status"],
            "local_correspondence_methods": decisive_methods,
            "local_correspondence_reason": local["reason"],
            "local_correspondence_prior_abstention_reason": state.abstention_reason,
        }
        update = {}
        if local["status"] in {"vulnerable", "patched"}:
            fallback_update["local_correspondence_used"] = True
            support = state.support.model_copy(update={
                "fix_evidence": state.support.fix_evidence + [
                    "Experimental local correspondence: " + ", ".join(decisive_methods)
                ],
            })
            update.update({
                "status": local["status"],
                "abstention_reason": None,
                "support": support,
            })
        update["fallbacks"] = state.fallbacks.model_copy(update=fallback_update)
        return state.model_copy(update=update)

    _unknown_applicabilities = staticmethod(unknown_applicabilities)

    def detect_batch(
        self,
        candidates: list[tuple],
    ) -> list[RegionDetectionResult]:
        """Detect a batch while encoding all candidate regions in one model call."""

        # Flatten regions for shared retrieval, retaining each function's slice.
        prepared: list[tuple[str | None, str, str | None, str | None, list]] = []
        flattened = []
        offsets: list[tuple[int, int]] = []
        for candidate in candidates:
            if len(candidate) == 2:
                candidate_id, source = candidate
                language = None
                candidate_function_name = None
            elif len(candidate) == 4:
                candidate_id, source, language, candidate_function_name = candidate
            else:
                raise ValueError("batch candidates must contain 2 or 4 values")
            candidate_language = resolve_candidate_language(candidate_id, language)
            filename = _LANGUAGE_FILENAME.get(candidate_language, "candidate.js")
            inferred_name = candidate_function_name or _infer_candidate_function_name(source, filename)
            regions = enumerate_candidate_regions(
                source,
                candidate_id=candidate_id,
                function_name=inferred_name,
                max_regions=self.config.max_candidate_regions,
                filename=filename,
            )
            start = len(flattened)
            flattened.extend(regions)
            offsets.append((start, len(flattened)))
            prepared.append((candidate_id, source, language, inferred_name, regions))

        # Batch retrieval happens here before each function enters detect().
        batches = query_region_batch(
            flattened,
            self.region_index,
            top_k=self.config.retrieval_top_k,
            threshold=self.config.retrieval_threshold,
        )

        # Rejoin the normal detection flow with the prepared regions and retrieval hits.
        results: list[RegionDetectionResult] = []
        for (candidate_id, source, language, function_name, regions), (start, end) in zip(prepared, offsets):
            matches = [match for batch in batches[start:end] for match in batch]
            results.append(
                self.detect(
                    source,
                    candidate_id=candidate_id,
                    language=language,
                    candidate_function_name=function_name,
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
