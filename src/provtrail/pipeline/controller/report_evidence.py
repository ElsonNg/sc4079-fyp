"""Select consistent boundary evidence for reports and agent handoffs."""

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ReportBoundary:
    state: dict[str, Any]
    lineage: dict[str, Any]
    observations: list[dict[str, Any]]
    hash_matches: list[dict[str, Any]]

    @property
    def advisories(self) -> list[dict[str, Any]]:
        return self.state.get("advisories") or self.lineage.get("associated_advisories") or []


# Reporting follows the detector's priority without changing its verdict.
def supports_decision(boundary: ReportBoundary, priority: str) -> bool:
    state = boundary.state
    status = state.get("status")
    if priority == "automatic_vulnerability":
        return status == "vulnerable" and not state.get("contradictions")
    if priority == "informational_lineage":
        return status == "patched"
    if priority == "manual_review":
        return (status == "vulnerable" and bool(state.get("contradictions"))) or (
            status == "uncertain" and not state.get("boundary_rejected")
            and boundary.lineage.get("confidence") in {"high", "medium"}
        )
    return False


def _boundary_rank(boundary: ReportBoundary, priority: str) -> tuple:
    state, lineage = boundary.state, boundary.lineage
    return (
        not supports_decision(boundary, priority),
        not bool(state.get("contradictions")) if priority == "manual_review" else False,
        not bool(state.get("token_gate_passed")) if priority == "manual_review" else False,
        not bool(boundary.hash_matches),
        {"high": 0, "medium": 1, "low": 2}.get(lineage.get("confidence"), 3),
        -float(lineage.get("score") or 0),
        str(state.get("fix_boundary_id") or lineage.get("lineage_id") or ""),
    )


# A boundary can retain several region granularities, but never another fix's observations.
def report_boundaries(result: dict[str, Any]) -> list[ReportBoundary]:
    lineages = result.get("lineages") or []
    states = result.get("vulnerability_states") or []
    output = []
    for state in states:
        lineage = next((item for item in lineages if item.get("lineage_id") == state.get("lineage_id")), {})
        if not state.get("advisories") and sum(item.get("lineage_id") == state.get("lineage_id") for item in states) > 1:
            lineage = {**lineage, "associated_advisories": []}
        boundary_id = state.get("fix_boundary_id")
        pair_ids = set(state.get("evidence_pair_ids") or [])
        observations = [
            item for item in result.get("evidence") or []
            if item.get("pair_id") in pair_ids or (
                boundary_id and str(item.get("pair_id") or "").startswith(boundary_id + ":")
            )
        ]
        matches = [
            item for item in result.get("hash_matches") or []
            if boundary_id and item.get("fix_boundary_id") == boundary_id
        ]
        output.append(ReportBoundary(state, lineage, observations, matches))

    # Retain candidates without a verdict as alternatives with no inferred boundary state.
    for lineage in lineages:
        if any(item.get("lineage_id") == lineage.get("lineage_id") for item in states):
            continue
        output.append(ReportBoundary({}, lineage, [], []))
    return sorted(output, key=lambda item: _boundary_rank(item, result.get("priority", "none")))


def decision_boundaries(result: dict[str, Any]) -> list[ReportBoundary]:
    boundaries = report_boundaries(result)
    supporting = [item for item in boundaries if supports_decision(item, result.get("priority", "none"))]
    return supporting or boundaries[:1]


def boundary_advisories(boundaries: list[ReportBoundary]) -> list[dict[str, Any]]:
    unique = {}
    for boundary in boundaries:
        for alias in boundary.advisories:
            key = tuple(alias.get(field) for field in ("ghsa_id", "cve_id", "osv_id", "package_name"))
            unique.setdefault(key, alias)
    return list(unique.values())


# Highlight a local patch observation when correspondence passes, otherwise show its limits.
def primary_observation(boundary: ReportBoundary) -> dict[str, Any]:
    side = "patched" if boundary.state.get("status") == "patched" else "vulnerable"

    def rank(item: dict[str, Any]) -> tuple:
        span = item.get("candidate_span") or {}
        correspondence = min(float(item.get(f"structural_{side}") or 0), float(item.get(f"token_{side}") or 0))
        if boundary.state.get("status") == "uncertain":
            correspondence = max(correspondence, min(float(item.get("structural_patched") or 0), float(item.get("token_patched") or 0)))
        return (
            item.get("reference_granularity") != "changed",
            -correspondence,
            int(span.get("end_byte") or 0) - int(span.get("start_byte") or 0),
            item.get("candidate_granularity") != "changed",
        )

    return min(boundary.observations, key=rank) if boundary.observations else {}


def boundary_reason(boundary: ReportBoundary | None) -> tuple[str, str]:
    if boundary is None:
        return "No boundary evidence was recorded.", "Inspect the scan coverage and available reference metadata."
    state = boundary.state
    if state.get("contradictions"):
        return (
            "Conflicting evidence prevents a confident decision for this fix.",
            "Compare the conflicting observations with the upstream change before deciding whether to apply it.",
        )
    if state.get("status") == "vulnerable":
        exact = any(item.get("match_type") == "exact" and item.get("side") == "vulnerable"
                    and item.get("representation", "native") == "native" for item in boundary.hash_matches)
        hashed = any(item.get("side") == "vulnerable" for item in boundary.hash_matches)
        return (
            "The function exactly matches this vulnerable reference." if exact else
            "An abstracted-code hash matches this vulnerable reference." if hashed else
            "Verification favours the vulnerable side of this specific upstream fix.",
            "Inspect the upstream change below, adapt it to the project code, then rescan this function.",
        )
    if state.get("status") == "patched":
        return (
            "Verification favours the patched side of this specific upstream fix.",
            "No change is indicated for this boundary. Other code and vulnerability classes remain outside this conclusion.",
        )
    reasons = {
        "S_FAILED": (
            "Structural correspondence was too weak to establish this code match.",
            "Check whether the functions implement the same operation before considering this advisory.",
        ),
        "T_FAILED": (
            "Token correspondence did not pass. Generic structure alone does not establish this vulnerability.",
            "Check the function's purpose and security-sensitive operations before comparing the patch.",
        ),
        "E_MARGIN_AMBIGUOUS": (
            "The vulnerable and patched edits are too similar to distinguish confidently.",
            "Check whether the specific guard or behavior added by the upstream patch is present here.",
        ),
        "E_SIDE_WEAK": (
            "Neither reference edit has enough support to decide this boundary.",
            "Inspect the relevant upstream edit and its surrounding project code to establish correspondence.",
        ),
        "E_SIDE_AND_MARGIN_WEAK": (
            "Patch correspondence is weak and does not clearly favour either side.",
            "Establish that this is the same operation before investigating whether the patch applies.",
        ),
        "CONTRASTIVE_CONFLICT": (
            "The edit comparisons disagree about which side the project retains.",
            "Inspect both reference edits and their context before accepting or dismissing this candidate.",
        ),
    }
    return reasons.get(state.get("abstention_reason"), (
        "The available evidence cannot resolve this candidate's vulnerability state.",
        "Verify code correspondence and the upstream security change before accepting or dismissing this candidate.",
    ))
