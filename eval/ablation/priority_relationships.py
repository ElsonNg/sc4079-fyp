"""Experimental priority with revision links and conservative identity checks."""
from dataclasses import dataclass

from provtrail.pipeline.controller.provenance import cluster_corpus_entries
from provtrail.pipeline.detection.priority import derive_priority
from eval.ablation.priority_policy import PROTECTED_REASONS


POLICY = "revision_relationship_uncertainty_v2"


@dataclass
class RevisionRelationships:
    components: dict[str, str]
    origins: dict[str, tuple]
    links: list[dict]

    @classmethod
    def from_entries(cls, entries):
        components, origins, links = {}, {}, []
        for lineage in cluster_corpus_entries(entries):
            members = lineage.boundaries
            parent = {b.fix_boundary_id: b.fix_boundary_id for b in members}

            def root(key):
                while parent[key] != key:
                    key = parent[key]
                return key

            for a in members:
                entry = a.representative
                origins[a.fix_boundary_id] = (lineage.lineage_id, entry.origin.repo,
                                               entry.origin.file_path, entry.origin.function_name,
                                               entry.origin.source_language)
                for b in members:
                    if (a.fix_boundary_id != b.fix_boundary_id
                        and entry.origin.source_language == b.representative.origin.source_language
                        and entry.patched_function == b.representative.vulnerable_function):
                        ra, rb = root(a.fix_boundary_id), root(b.fix_boundary_id)
                        parent[max(ra, rb)] = min(ra, rb)
                        links.append(dict(patched_boundary=a.fix_boundary_id,
                                          vulnerable_boundary=b.fix_boundary_id,
                                          lineage_id=lineage.lineage_id))
            components.update({key: root(key) for key in parent})
        return cls(components, origins, links)

    def relation(self, state, patched):
        key = state.boundary.fix_boundary_id
        if key not in self.components or any(p not in self.components for p in patched):
            return "unknown"
        if any(self.components[key] == self.components[p] for p in patched):
            return "connected_revision"
        origin = self.origins[key]
        other_origins = [self.origins[p] for p in patched]
        # A missing edge, different path or name alone is not a rejection.
        # Reuse the verifier's identity signals for generic, changed-only noise:
        # conflicting candidate/reference names, no broader correspondence and
        # both selected edit anchors explicitly lacking identifying tokens.
        incompatible = (
            bool(origin[3]) and all(o[3] and o[0] != origin[0] for o in other_origins)
            and state.gates.function_identity_state == "conflict"
            and not state.gates.context_correspondence_passed
            and state.edit.vulnerable_anchor_has_identity is False
            and state.edit.patched_anchor_has_identity is False
        )
        return "identity_incompatible" if incompatible else "unknown"


def review_alternatives(result, relationships):
    credible = {l.lineage_id for l in result.lineages if l.confidence in {"high", "medium"}}
    patched = [s.boundary.fix_boundary_id for s in result.vulnerability_states if s.status == "patched"]
    decisions = []
    for state in result.vulnerability_states:
        if (state.status != "uncertain" or state.gates.boundary_rejected
            or state.boundary.lineage_id not in credible):
            continue
        protected = bool(state.support.contradictions) or state.abstention_reason in PROTECTED_REASONS
        relation = relationships.relation(state, patched)
        # Preserve existing S/T-failed noise handling. A confirmed revision
        # connection can make even that weak evidence worth inspecting.
        relevant = protected or relation == "connected_revision" or state.gates.token_gate_passed
        if relevant:
            decisions.append(dict(boundary=state.boundary.fix_boundary_id, relationship=relation,
                                  abstention_reason=state.abstention_reason,
                                  review_required=protected or relation != "identity_incompatible"))
    return decisions


def experimental_priority(result, relationships):
    baseline = derive_priority(result.lineages, result.vulnerability_states, result.package_applicabilities)
    states = result.vulnerability_states
    if result.hash_matches or any(s.status == "vulnerable" for s in states):
        return baseline
    if not any(s.status == "patched" for s in states):
        return baseline
    # Keep explicit conflicts even if retrieval confidence is low.
    if any(s.status == "uncertain" and not s.gates.boundary_rejected
           and (s.support.contradictions or s.abstention_reason in PROTECTED_REASONS)
           for s in states):
        return "manual_review"
    if any(d["review_required"] for d in review_alternatives(result, relationships)):
        return "manual_review"
    return "informational_lineage"
