"""Attribute retrieved evidence to source lineages and list their packages."""

from pipeline.controller.provenance import CorpusLineage
from pipeline.detection.verification.aggregation import deduplicate_evidence
from pipeline.models.boundary import VulnerableRegionPair
from pipeline.models.evidence import PackageApplicability, RegionVerificationEvidence
from pipeline.models.lineage import LineageAttribution, LineageConfidence


def lineage_confidence(score: float) -> LineageConfidence:
    if score >= 0.82:
        return "high"
    if score >= 0.68:
        return "medium"
    if score >= 0.55:
        return "low"
    return "none"


def attribute_lineages(
    evidence: list[RegionVerificationEvidence],
    pairs: dict[str, VulnerableRegionPair],
    lineage_meta: dict[str, CorpusLineage],
) -> list[LineageAttribution]:
    lineages = []
    evidence_by_lineage = {}
    for item in evidence:
        lineage_id = pairs[item.pair_id].lineage_id
        if lineage_id:
            evidence_by_lineage.setdefault(lineage_id, []).append(item)
    for lineage_id, scoped in sorted(evidence_by_lineage.items()):
        independent = deduplicate_evidence(scoped)
        span_scores = sorted(
            0.60 * item.retrieval_similarity
            + 0.25 * max(item.vulnerable.structural, item.patched.structural)
            + 0.15 * 0.5
            for item in independent
        )
        score = span_scores[len(span_scores) // 2] if span_scores else 0.0
        meta = lineage_meta[lineage_id]
        lineages.append(LineageAttribution(
            lineage_id=lineage_id,
            confidence=lineage_confidence(score),
            score=score,
            repo=meta.representative.origin.repo,
            file_path=meta.representative.origin.file_path,
            reference_function=meta.representative.origin.function_name,
            associated_advisories=list(meta.advisories),
            evidence_pair_ids=sorted({item.pair_id for item in independent}),
        ))

    lineages.sort(key=lambda item: (-item.score, item.lineage_id))
    return lineages


def unknown_applicabilities(lineages: list[LineageAttribution]) -> list[PackageApplicability]:
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
