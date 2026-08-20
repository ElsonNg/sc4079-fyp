import hashlib
from dataclasses import dataclass, field
from typing import Literal

import tree_sitter

from corpus.models.corpus import CorpusEntry
from pipeline.controller.provenance import CorpusLineage, cluster_corpus_entries
from pipeline.controller.parsing import (
    _apply_replacements,
    _collapse_whitespace,
    _find_comment_ranges,
    normalize_source,
    parse_source,
)
from pipeline.models.hashing import FunctionFingerprint, HashMatch

# VUDDY's own reported threshold: "the shortest vulnerable function consists of 51
# characters after abstraction and normalization." Measured on the abstracted string,
# per the paper; functions shorter than this are excluded from both hashes entirely.
MIN_HASHABLE_LENGTH = 50

_BOUND_NAME_TYPES = {
    "identifier",
    "shorthand_property_identifier_pattern",
    "object_pattern",
    "array_pattern",
    "rest_pattern",
    "assignment_pattern",
    "pair_pattern",
}

# Node types whose text could be a use-site reference to an already-collected FPARAM/LVAR
# name. `shorthand_property_identifier_pattern` is the destructuring-binding form (e.g.
# `const { name } = x`); `shorthand_property_identifier` is the distinct object-literal
# *expression* form (e.g. `return { name }`, meaning `{ name: name }`) -- both are
# genuine references to the bound variable and need abstracting the same way.
_ABSTRACTABLE_NODE_TYPES = (
    "identifier",
    "shorthand_property_identifier_pattern",
    "shorthand_property_identifier",
)


def _collect_bound_identifiers(node: tree_sitter.Node) -> list[tuple[str, tree_sitter.Node]]:
    """Recursively resolves a binding-pattern subtree (a formal parameter, a
    variable_declarator's name, a catch_clause parameter, or a for-in/for-of binding)
    down to the actual identifier(s) it declares. Handles plain identifiers, shorthand
    destructured properties, object/array destructuring (including nested patterns and
    default values), and rest elements."""
    if node.type in ("identifier", "shorthand_property_identifier_pattern"):
        return [(node.text.decode("utf-8"), node)]
    if node.type == "assignment_pattern":
        left = node.child_by_field_name("left")
        return _collect_bound_identifiers(left) if left is not None else []
    if node.type == "pair_pattern":
        value = node.child_by_field_name("value")
        return _collect_bound_identifiers(value) if value is not None else []
    if node.type in ("object_pattern", "array_pattern", "rest_pattern", "formal_parameters"):
        found: list[tuple[str, tree_sitter.Node]] = []
        for child in node.children:
            if child.type in _BOUND_NAME_TYPES:
                found.extend(_collect_bound_identifiers(child))
        return found
    return []


def _collect_formal_parameters(root: tree_sitter.Node) -> list[tuple[str, tree_sitter.Node]]:
    """Every formal_parameters node anywhere in the subtree, in document order, feeding
    one continuous FPARAM sequence. Nested arrow functions/methods have their own
    separate formal_parameters node, but their source is part of this unit's hashed
    body too, so their parameters need abstracting as well."""
    found: list[tuple[str, tree_sitter.Node]] = []

    def walk(node: tree_sitter.Node) -> None:
        if node.type == "formal_parameters":
            found.extend(_collect_bound_identifiers(node))
        for child in node.children:
            walk(child)

    walk(root)
    return found


def _collect_local_variables(root: tree_sitter.Node) -> list[tuple[str, tree_sitter.Node]]:
    """Every variable_declarator name, catch_clause parameter, and for-in/for-of loop
    binding anywhere in the subtree, in document order. `for (const item of items)`
    does not wrap `item` in a variable_declarator the way a C-style `for` does -- it
    sits directly on for_in_statement's `left` field -- so that case is handled
    explicitly rather than falling out of the variable_declarator sweep."""
    found: list[tuple[str, tree_sitter.Node]] = []

    def walk(node: tree_sitter.Node) -> None:
        if node.type == "variable_declarator":
            name = node.child_by_field_name("name")
            if name is not None:
                found.extend(_collect_bound_identifiers(name))
        elif node.type == "catch_clause":
            for child in node.children:
                if child.type in _BOUND_NAME_TYPES:
                    found.extend(_collect_bound_identifiers(child))
                    break
        elif node.type == "for_in_statement":
            left = node.child_by_field_name("left")
            if left is not None and left.type in _BOUND_NAME_TYPES:
                found.extend(_collect_bound_identifiers(left))
        for child in node.children:
            walk(child)

    walk(root)
    return found


def abstract_identifiers(unit_source: str) -> str:
    """Level-2-equivalent VUDDY abstraction, adapted for JS: every formal parameter
    occurrence becomes FPARAM<n>, every local variable occurrence becomes LVAR<n>,
    positional by first-declaration order within its own role (not VUDDY's literal
    shared FPARAM/LVAR token for every name -- see build plan for why). Comments are
    stripped in the same pass. No real scope resolution: a name shadowed by a nested
    re-declaration still resolves to the outer mapping's token, matching VUDDY's own
    non-scope-aware, syntax-only approach."""
    tree = parse_source(unit_source)
    root = tree.root_node

    fparam_map: dict[str, str] = {}
    for name, _ in _collect_formal_parameters(root):
        if name not in fparam_map:
            fparam_map[name] = f"FPARAM{len(fparam_map) + 1}"

    lvar_map: dict[str, str] = {}
    for name, _ in _collect_local_variables(root):
        if name not in lvar_map:
            lvar_map[name] = f"LVAR{len(lvar_map) + 1}"

    replacements: list[tuple[int, int, str]] = [
        (start, end, "") for start, end in _find_comment_ranges(root)
    ]

    def walk(node: tree_sitter.Node) -> None:
        if node.type in _ABSTRACTABLE_NODE_TYPES:
            text = node.text.decode("utf-8")
            token = fparam_map.get(text, lvar_map.get(text))
            if token is not None:
                replacements.append((node.start_byte, node.end_byte, token))
            return
        for child in node.children:
            walk(child)

    walk(root)
    return _apply_replacements(unit_source, replacements)


def compute_fingerprint(unit_source: str) -> FunctionFingerprint:
    exact_string = " ".join(normalize_source(unit_source))
    abstracted_string = " ".join(_collapse_whitespace(abstract_identifiers(unit_source)))

    if len(abstracted_string) < MIN_HASHABLE_LENGTH:
        return FunctionFingerprint(
            hashable=False,
            exact_length=len(exact_string),
            abstracted_length=len(abstracted_string),
        )

    return FunctionFingerprint(
        hashable=True,
        exact_hash=hashlib.sha256(exact_string.encode("utf-8")).hexdigest(),
        exact_length=len(exact_string),
        abstracted_hash=hashlib.sha256(abstracted_string.encode("utf-8")).hexdigest(),
        abstracted_length=len(abstracted_string),
    )


HashBucket = dict[int, dict[str, list[HashMatch]]]


@dataclass
class HashIndex:
    exact: HashBucket = field(default_factory=dict)
    abstracted: HashBucket = field(default_factory=dict)


def _insert(bucket: HashBucket, length: int, digest: str, match: HashMatch) -> None:
    bucket.setdefault(length, {}).setdefault(digest, []).append(match)


def _match_from_entry(
    entry: CorpusEntry,
    side: Literal["vulnerable", "patched"],
    match_type: Literal["exact", "abstracted"],
    lineage: CorpusLineage | None = None,
    boundary_id: str | None = None,
    advisories: list | None = None,
) -> HashMatch:
    return HashMatch(
        lineage_id=lineage.lineage_id if lineage else None,
        fix_boundary_id=boundary_id,
        advisories=advisories if advisories is not None else (list(lineage.advisories) if lineage else []),
        ghsa_id=entry.ghsa_id,
        cve_id=entry.cve_id,
        osv_id=entry.osv_id,
        advisory_title=entry.advisory_title,
        advisory_description=entry.advisory_description,
        advisory_url=entry.advisory_url,
        advisory_references=entry.advisory_references,
        side=side,
        match_type=match_type,
        cwes=entry.cwes,
        severity=entry.severity,
        package_name=entry.package_name,
        ecosystem=entry.ecosystem,
        affected_versions=entry.affected_versions,
        fixed_versions=entry.fixed_versions,
        repo=entry.repo,
        fix_commit_sha=entry.fix_commit_sha,
        file_path=entry.file_path,
        function_name=entry.function_name,
    )


def build_hash_index(entries: list[CorpusEntry]) -> HashIndex:
    """Built fresh in memory at pipeline setup from corpus.store.load_entries() -- hashing
    is cheap regardless of corpus size, so this avoids a corpus.db schema migration for
    something trivially recomputed."""
    index = HashIndex()
    for lineage in cluster_corpus_entries(entries):
        for boundary in lineage.boundaries:
            entry = boundary.representative
            for side, source in (
                ("vulnerable", entry.vulnerable_function),
                ("patched", entry.patched_function),
            ):
                fingerprint = compute_fingerprint(source)
                if not fingerprint.hashable:
                    continue
                _insert(
                    index.exact,
                    fingerprint.exact_length,
                    fingerprint.exact_hash,
                    _match_from_entry(
                        entry, side, "exact", lineage,
                        boundary.fix_boundary_id, list(boundary.advisories),
                    ),
                )
                _insert(
                    index.abstracted,
                    fingerprint.abstracted_length,
                    fingerprint.abstracted_hash,
                    _match_from_entry(
                        entry, side, "abstracted", lineage,
                        boundary.fix_boundary_id, list(boundary.advisories),
                    ),
                )
    return index


def lookup(target_source: str, index: HashIndex) -> list[HashMatch]:
    """VUDDY's S4 (length-key lookup) then S5 (hash lookup) against both the exact and
    abstracted indices. A target can legitimately match both a "vulnerable" and a
    "patched" entry -- every match found is returned rather than picking one."""
    fingerprint = compute_fingerprint(target_source)
    if not fingerprint.hashable:
        return []

    matches: list[HashMatch] = []
    matches.extend(
        index.exact.get(fingerprint.exact_length, {}).get(fingerprint.exact_hash, [])
    )
    matches.extend(
        index.abstracted.get(fingerprint.abstracted_length, {}).get(
            fingerprint.abstracted_hash, []
        )
    )
    return matches
