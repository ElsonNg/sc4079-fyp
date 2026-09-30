"""Build detection results from deterministic vulnerable and patched hash matches."""

from provtrail.pipeline.detection.lineage import unknown_applicabilities
from provtrail.pipeline.detection.priority import derive_priority
from provtrail.pipeline.models.boundary import (
    BoundaryIdentity, BoundarySupport, VerificationScores, VulnerabilityState,
)
from provtrail.pipeline.models.hashing import HashMatch
from provtrail.pipeline.models.lineage import LineageAttribution
from provtrail.pipeline.models.result import RegionDetectionResult


def build_hash_result(
    hash_matches: list[HashMatch], candidate_id: str | None,
) -> RegionDetectionResult:
    # Shared advisories describe one lineage even when several hash records match.
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
            repo=first.origin.repo,
            file_path=first.origin.file_path,
            reference_function=first.origin.function_name,
            associated_advisories=list(aliases.values()),
        ))

    # Keep verdicts scoped to individual fixes within that lineage.
    states = []
    for boundary_id in sorted({match.fix_boundary_id for match in hash_matches if match.fix_boundary_id}):
        members = [match for match in hash_matches if match.fix_boundary_id == boundary_id]
        first = members[0]
        # Abstraction can erase the change separating the two fix sides. Prefer
        # exact evidence within this boundary; a shared abstracted hash is
        # ambiguous side evidence, not a contradiction.
        exact = [match for match in members if match.match_type == "exact"]
        decisive = exact or members
        vulnerable = any(match.side == "vulnerable" for match in decisive)
        patched = any(match.side == "patched" for match in decisive)
        status = "uncertain" if vulnerable and patched else "vulnerable" if vulnerable else "patched"
        contradictory = bool(exact) and vulnerable and patched
        states.append(VulnerabilityState(
            status=status,
            abstention_reason=(
                "CONTRADICTORY_EVIDENCE" if contradictory else "HASH_SIDE_AMBIGUOUS"
            ) if status == "uncertain" else None,
            advisories=first.advisories,
            boundary=BoundaryIdentity(
                lineage_id=first.lineage_id or '',
                fix_boundary_id=boundary_id,
                fix_commit_sha=first.origin.fix_commit_sha,
            ),
            scores=VerificationScores(
                vulnerable_score=1.0 if vulnerable else 0.0,
                patched_score=1.0 if patched else 0.0,
                contrast_score=0.0 if vulnerable and patched else 1.0 if vulnerable else -1.0,
            ),
            support=BoundarySupport(
                fix_evidence=sorted({f'{match.match_type} {match.side}-side hash match' for match in members}),
                contradictions=['exact vulnerable and patched hashes both match'] if contradictory else [],
            ),
        ))

    applications = unknown_applicabilities(lineages)
    return RegionDetectionResult(
        priority=derive_priority(lineages, states, applications),
        candidate_id=candidate_id,
        hash_match_types=sorted({match.match_type for match in hash_matches}),
        hash_matches=hash_matches,
        candidate_region_count=0,
        retrieval_match_count=0,
        lineages=lineages,
        vulnerability_states=states,
        package_applicabilities=applications,
        message="Resolved deterministic hash evidence by lineage and fix boundary",
    )
