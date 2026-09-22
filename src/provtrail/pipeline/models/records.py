"""Conversion between grouped domain evidence and existing flat JSON records."""

from typing import Any, ClassVar, Self

from pydantic import BaseModel


class FlatRecordModel(BaseModel):
    """Grouped evidence with explicit conversion to existing flat records."""

    record_groups: ClassVar[dict[str, dict[str, str]]]

    def to_record(self) -> dict[str, Any]:
        record = self.model_dump(mode="json")
        for group, names in self.record_groups.items():
            values = record.pop(group)
            record.update({legacy: values[name] for name, legacy in names.items()})
        return record

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> Self:
        values = dict(record)
        for group, names in cls.record_groups.items():
            values[group] = {
                name: values.pop(legacy)
                for name, legacy in names.items()
                if legacy in values
            }
        return cls.model_validate(values)


ADVISORY_FIELDS = {
    "ghsa_id": "ghsa_id",
    "cve_id": "cve_id",
    "osv_id": "osv_id",
    "advisory_title": "advisory_title",
    "advisory_description": "advisory_description",
    "advisory_url": "advisory_url",
    "advisory_references": "advisory_references",
    "cwes": "cwes",
    "severity": "severity",
    "package_name": "package_name",
    "ecosystem": "ecosystem",
    "affected_versions": "affected_versions",
    "fixed_versions": "fixed_versions"
}


SOURCE_REFERENCE_FIELDS = {
    "repo": "repo",
    "fix_commit_sha": "fix_commit_sha",
    "file_path": "file_path",
    "function_name": "function_name",
    "source_language": "source_language"
}


VULNERABLE_REGION_PAIR_FIELDS = {
    "advisory": ADVISORY_FIELDS,
    "origin": SOURCE_REFERENCE_FIELDS,
    "change": {
        "change_kind": "change_kind",
        "diagnostic_line_count": "diagnostic_line_count",
        "vulnerable_signature_tokens": "vulnerable_signature_tokens",
        "fix_signature_tokens": "fix_signature_tokens",
        "vulnerable_source_sha256": "vulnerable_source_sha256",
        "patched_source_sha256": "patched_source_sha256"
    },
}


HASH_MATCH_FIELDS = {
    "advisory": ADVISORY_FIELDS,
    "origin": SOURCE_REFERENCE_FIELDS,
}


REGION_VERIFICATION_EVIDENCE_FIELDS = {
    "candidate": {
        "region_id": "candidate_region_id",
        "span": "candidate_span",
        "granularity": "candidate_granularity",
        "function_name": "candidate_function_name"
    },
    "reference": {
        "vulnerable_region_id": "vulnerable_region_id",
        "patched_region_id": "patched_region_id",
        "granularity": "reference_granularity"
    },
    "vulnerable": {
        "structural": "structural_vulnerable",
        "token": "token_vulnerable",
        "api_anchor": "api_anchor_vulnerable",
        "local_alignment": "local_alignment_vulnerable",
        "score": "vulnerable_score",
        "containment_structural": "containment_structural_vulnerable",
        "containment_token": "containment_token_vulnerable",
        "containment_coverage": "containment_coverage_vulnerable",
        "containment_used": "containment_fallback_vulnerable",
        "containment_attempted": "containment_fallback_attempted_vulnerable"
    },
    "patched": {
        "structural": "structural_patched",
        "token": "token_patched",
        "api_anchor": "api_anchor_patched",
        "local_alignment": "local_alignment_patched",
        "score": "patched_score",
        "containment_structural": "containment_structural_patched",
        "containment_token": "containment_token_patched",
        "containment_coverage": "containment_coverage_patched",
        "containment_used": "containment_fallback_patched",
        "containment_attempted": "containment_fallback_attempted_patched"
    },
    "comparison": {
        "correspondence_score": "correspondence_score",
        "margin": "vulnerable_minus_patched",
        "ast_coverage": "ast_coverage",
        "fix_signature_coverage": "fix_signature_coverage",
        "vulnerable_signature_coverage": "vulnerable_signature_coverage",
        "lineage_confidence": "lineage_confidence",
        "alignment_fallback_used": "fallback_used"
    },
}


VULNERABILITY_STATE_FIELDS = {
    "boundary": {
        "lineage_id": "lineage_id",
        "fix_boundary_id": "fix_boundary_id",
        "fix_commit_sha": "fix_commit_sha"
    },
    "scores": {
        "vulnerable_score": "vulnerable_score",
        "patched_score": "patched_score",
        "correspondence_score": "correspondence_score",
        "contrast_score": "contrast_score",
        "structural_vulnerable": "structural_vulnerable",
        "structural_patched": "structural_patched",
        "token_vulnerable": "token_vulnerable",
        "token_patched": "token_patched"
    },
    "edit": {
        "strategy": "edit_strategy",
        "vulnerable": "edit_vulnerable",
        "patched": "edit_patched",
        "margin": "edit_margin",
        "vulnerable_anchor_has_identity": "edit_vulnerable_anchor_has_identity",
        "patched_anchor_has_identity": "edit_patched_anchor_has_identity",
        "raw_vulnerable": "edit_raw_vulnerable",
        "raw_patched": "edit_raw_patched",
        "contrastive_vulnerable": "edit_contrastive_vulnerable",
        "contrastive_patched": "edit_contrastive_patched",
        "contrastive_used": "edit_contrastive_used"
    },
    "gates": {
        "structure_gate_passed": "structure_gate_passed",
        "token_gate_passed": "token_gate_passed",
        "context_correspondence_passed": "context_correspondence_passed",
        "function_identity_state": "function_identity_state",
        "edit_anchor_has_identity": "edit_anchor_has_identity",
        "boundary_identity_gate_passed": "boundary_identity_gate_passed",
        "boundary_rejected": "boundary_rejected"
    },
    "fallbacks": {
        "containment_attempted": "containment_fallback_attempted",
        "containment_used": "containment_fallback_used",
        "local_correspondence_attempted": "local_correspondence_attempted",
        "local_correspondence_used": "local_correspondence_used",
        "local_correspondence_status": "local_correspondence_status",
        "local_correspondence_methods": "local_correspondence_methods",
        "local_correspondence_reason": "local_correspondence_reason",
        "local_correspondence_prior_abstention_reason": "local_correspondence_prior_abstention_reason"
    },
    "support": {
        "fix_signature_coverage": "fix_signature_coverage",
        "vulnerable_signature_coverage": "vulnerable_signature_coverage",
        "signature_evidence_state": "signature_evidence_state",
        "independent_region_count": "independent_region_count",
        "vulnerable_support_count": "vulnerable_support_count",
        "patched_support_count": "patched_support_count",
        "side_consensus_ratio": "side_consensus_ratio",
        "fix_evidence": "fix_evidence",
        "contradictions": "contradictions"
    },
}
