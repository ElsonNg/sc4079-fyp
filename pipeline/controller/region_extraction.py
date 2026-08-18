"""AST-region extraction for vulnerable corpus pairs and candidate functions."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

import tree_sitter

from corpus.models.corpus import CorpusEntry
from pipeline.controller.parsing import FUNCTION_NODE_TYPES, normalize_source, parse_source
from pipeline.models.regions import (
    AstRegion,
    CandidateRegion,
    RegionGranularity,
    SourceSpan,
    VulnerableRegionPair,
)

_SYNTHETIC_PREFIX = "class __CodexRegionWrapper {\n"
_SYNTHETIC_SUFFIX = "\n}\n"
_TOKEN_RE = re.compile(
    r"(?:[A-Za-z_$][A-Za-z0-9_$]*|(?:\d+(?:\.\d+)?)|===|!==|==|!=|=>|<=|>=|&&|\|\||\?\?|\+\+|--|\+=|-=|\*=|/=|.)",
    re.DOTALL,
)

_STATEMENT_TYPES = {
    "expression_statement", "return_statement", "throw_statement", "debugger_statement",
    "empty_statement", "if_statement", "for_statement", "for_in_statement",
    "while_statement", "do_statement", "switch_statement", "try_statement",
    "with_statement", "lexical_declaration", "variable_declaration", "import_statement",
    "export_statement", "break_statement", "continue_statement", "class_declaration",
}
_BLOCK_TYPES = {
    "statement_block", "if_statement", "for_statement", "for_in_statement",
    "while_statement", "do_statement", "switch_statement", "switch_case",
    "try_statement", "catch_clause", "finally_clause", "else_clause",
}
_EXPRESSION_TYPES = {
    "call_expression", "new_expression", "assignment_expression", "await_expression",
    "binary_expression", "logical_expression", "ternary_expression", "member_expression",
    "subscript_expression", "unary_expression", "update_expression", "object",
    "array", "arrow_function",
}
_LITERAL_TYPES = {
    "string", "string_fragment", "template_string", "number", "true", "false", "null",
    "regex", "undefined",
}


@dataclass(frozen=True)
class _ParsedSource:
    source: str
    tree: tree_sitter.Tree
    root: tree_sitter.Node
    line_offset: int = 0
    byte_offset: int = 0


def _parse_region_source(source: str) -> _ParsedSource:
    tree = parse_source(source)
    if not tree.root_node.has_error:
        return _ParsedSource(source, tree, tree.root_node)

    wrapped = _SYNTHETIC_PREFIX + source + _SYNTHETIC_SUFFIX
    wrapped_tree = parse_source(wrapped)
    if wrapped_tree.root_node.has_error:
        return _ParsedSource(source, tree, tree.root_node)
    return _ParsedSource(
        source,
        wrapped_tree,
        wrapped_tree.root_node,
        line_offset=1,
        byte_offset=len(_SYNTHETIC_PREFIX.encode("utf-8")),
    )


def source_is_supported(source: str) -> bool:
    """Return whether standalone or synthetic-method parsing produced a clean tree."""
    return not _parse_region_source(source).tree.root_node.has_error


def _function_root(parsed: _ParsedSource) -> tree_sitter.Node:
    candidates: list[tree_sitter.Node] = []

    def walk(node: tree_sitter.Node) -> None:
        if node.type in FUNCTION_NODE_TYPES:
            candidates.append(node)
        for child in node.named_children:
            walk(child)

    walk(parsed.root)
    if candidates:
        return min(candidates, key=lambda node: (node.start_byte, -node.end_byte))
    return parsed.root


def _relative_span(node: tree_sitter.Node, parsed: _ParsedSource) -> SourceSpan:
    return SourceSpan(
        start_byte=max(0, node.start_byte - parsed.byte_offset),
        end_byte=max(0, node.end_byte - parsed.byte_offset),
        start_line=max(0, node.start_point[0] - parsed.line_offset),
        end_line=max(0, node.end_point[0] - parsed.line_offset),
    )


def _node_path(node: tree_sitter.Node, root: tree_sitter.Node) -> list[str]:
    path: list[str] = []
    current: tree_sitter.Node | None = node
    while current is not None:
        path.append(current.type)
        if current.id == root.id:
            break
        current = current.parent
    return list(reversed(path))


def _source_slice(source: str, span: SourceSpan) -> str:
    raw = source.encode("utf-8")
    return raw[span.start_byte:span.end_byte].decode("utf-8")


def _node_features(node: tree_sitter.Node, text: str) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    identifiers: list[str] = []
    literals: list[str] = []
    calls: list[str] = []
    members: list[str] = []
    node_types: list[str] = []

    def walk(current: tree_sitter.Node) -> None:
        node_types.append(current.type)
        if current.type in {"identifier", "property_identifier", "private_property_identifier"} and current.text:
            identifiers.append(current.text.decode("utf-8"))
        if current.type in _LITERAL_TYPES and current.text:
            literals.append(current.text.decode("utf-8"))
        if current.type == "call_expression":
            function_node = current.child_by_field_name("function")
            if function_node is not None and function_node.text:
                calls.append(function_node.text.decode("utf-8"))
        if current.type == "member_expression" and current.text:
            members.append(current.text.decode("utf-8"))
        for child in current.named_children:
            walk(child)

    walk(node)
    normalized_text = " ".join(normalize_source(text))
    tokens = [token for token in _TOKEN_RE.findall(normalized_text) if not token.isspace()]
    return tokens, node_types, calls, members, identifiers + literals


def _region_embedding_text(
    node_type: str,
    path: list[str],
    tokens: list[str],
    calls: list[str],
    members: list[str],
) -> str:
    return " ".join(
        [
            "node=" + node_type,
            "path=" + "/".join(path),
            "tokens=" + " ".join(tokens),
            "calls=" + " ".join(calls),
            "members=" + " ".join(members),
        ]
    )


def _make_region(
    source: str,
    parsed: _ParsedSource,
    node: tree_sitter.Node,
    granularity: RegionGranularity,
    region_id: str,
    span: SourceSpan | None = None,
    node_type: str | None = None,
) -> AstRegion:
    actual_span = span or _relative_span(node, parsed)
    text = _source_slice(source, actual_span)
    tokens, node_types, calls, members, identifier_literals = _node_features(node, text)
    identifiers = [value for value in identifier_literals if re.match(r"^[A-Za-z_$]", value)]
    literals = [value for value in identifier_literals if value not in identifiers]
    path = _node_path(node, _function_root(parsed))
    actual_type = node_type or node.type
    return AstRegion(
        region_id=region_id,
        source=text,
        span=actual_span,
        granularity=granularity,
        node_type=actual_type,
        ast_path=path,
        ast_shape=node_types,
        normalized_tokens=tokens,
        calls=sorted(set(calls)),
        member_accesses=sorted(set(members)),
        identifiers=sorted(set(identifiers)),
        literals=sorted(set(literals)),
        embedding_text=_region_embedding_text(actual_type, path, tokens, calls, members),
    )


_GENERIC_LITERALS = {"true", "false", "null", "undefined", "0", "1", "''", '""'}
MIN_INFORMATIVE_REGION_TOKENS = 6
MIN_INFORMATIVE_REGION_AST_NODES = 4
MIN_INFORMATIVE_CONTEXT_TOKENS = 12


def candidate_region_is_informative(region: AstRegion) -> bool:
    """Reject tiny syntax-only fragments that cannot identify vulnerable behavior.

    Concrete calls, member accesses, and non-trivial literals are meaningful anchors
    even in a short region.  Otherwise a statement/block must carry enough token and
    AST structure to distinguish it from ubiquitous fragments such as ``return x;``,
    ``return;``, ``throw x;``, or ``var x;``.  Context and function regions use their
    wider source span, so they are retained once that span contains enough tokens.
    """
    meaningful_literals = set(region.literals) - _GENERIC_LITERALS
    if region.calls or region.member_accesses or meaningful_literals:
        return True
    if region.granularity in {"context", "function"}:
        return len(region.normalized_tokens) >= MIN_INFORMATIVE_CONTEXT_TOKENS
    return (
        len(region.normalized_tokens) >= MIN_INFORMATIVE_REGION_TOKENS
        and len(region.ast_shape) >= MIN_INFORMATIVE_REGION_AST_NODES
    )


def _all_named_nodes(root: tree_sitter.Node) -> list[tree_sitter.Node]:
    nodes: list[tree_sitter.Node] = []

    def walk(node: tree_sitter.Node) -> None:
        if node.is_named:
            nodes.append(node)
        for child in node.named_children:
            walk(child)

    walk(root)
    return nodes


def _contains_line(node: tree_sitter.Node, line: int, parsed: _ParsedSource) -> bool:
    start = node.start_point[0] - parsed.line_offset
    end = node.end_point[0] - parsed.line_offset
    return start <= line <= end


def _nearest_node(nodes: list[tree_sitter.Node], line: int, parsed: _ParsedSource) -> tree_sitter.Node:
    candidates = [
        node for node in nodes
        if _contains_line(node, line, parsed)
        and (node.type in _STATEMENT_TYPES or node.type in _EXPRESSION_TYPES)
    ]
    if not candidates:
        return _function_root(parsed)
    return min(
        candidates,
        key=lambda node: (
            0 if node.type in _STATEMENT_TYPES else 1,
            node.end_byte - node.start_byte,
        ),
    )


def _nearest_block(node: tree_sitter.Node, root: tree_sitter.Node) -> tree_sitter.Node:
    current: tree_sitter.Node | None = node
    while current is not None and current.id != root.id:
        if current.type in _BLOCK_TYPES:
            return current
        current = current.parent
    return root


def _line_context_span(source: str, start_line: int, end_line: int, padding: int = 2) -> SourceSpan:
    lines = source.splitlines(keepends=True)
    if not lines:
        return SourceSpan(start_byte=0, end_byte=0, start_line=0, end_line=0)
    first = max(0, start_line - padding)
    last = min(len(lines) - 1, end_line + padding)
    start_byte = sum(len(line.encode("utf-8")) for line in lines[:first])
    end_byte = sum(len(line.encode("utf-8")) for line in lines[: last + 1])
    return SourceSpan(start_byte=start_byte, end_byte=end_byte, start_line=first, end_line=last)


def enumerate_candidate_regions(
    source: str,
    candidate_id: str | None = None,
    function_name: str | None = None,
    max_regions: int = 96,
) -> list[CandidateRegion]:
    """Generate prioritized changed/block/context/function regions for one function."""
    parsed = _parse_region_source(source)
    root = _function_root(parsed)
    nodes = _all_named_nodes(root)
    targets = [
        node for node in nodes
        if node.type in _STATEMENT_TYPES or node.type in _EXPRESSION_TYPES
    ]
    targets.sort(key=lambda node: (node.start_byte, node.end_byte - node.start_byte))

    regions: list[CandidateRegion] = []
    seen: set[tuple[int, int, str]] = set()

    def add(node: tree_sitter.Node, granularity: RegionGranularity, span: SourceSpan | None = None, label: str | None = None) -> None:
        actual_span = span or _relative_span(node, parsed)
        key = (actual_span.start_byte, actual_span.end_byte, granularity)
        if key in seen or actual_span.end_byte <= actual_span.start_byte:
            return
        seen.add(key)
        region_id = f"candidate:{candidate_id or 'anonymous'}:{len(regions):04d}"
        region = _make_region(source, parsed, node, granularity, region_id, span=actual_span, node_type=label)
        if not candidate_region_is_informative(region):
            return
        regions.append(CandidateRegion(candidate_id=candidate_id, function_name=function_name, region=region))

    for target in targets:
        add(target, "changed")
        block = _nearest_block(target, root)
        add(block, "block")
        target_span = _relative_span(target, parsed)
        add(
            target,
            "context",
            span=_line_context_span(source, target_span.start_line, target_span.end_line),
            label="context_slice",
        )
        if len(regions) >= max_regions - 1:
            break

    add(root, "function")
    return regions[:max_regions]


def _anchor_line(source: str, lines: list[int]) -> int:
    if lines:
        return max(0, min(min(lines), max(0, len(source.splitlines()) - 1)))
    return max(0, len(source.splitlines()) // 2)


def _regions_for_anchor(source: str, lines: list[int], prefix: str) -> dict[RegionGranularity, AstRegion]:
    parsed = _parse_region_source(source)
    root = _function_root(parsed)
    nodes = _all_named_nodes(root)
    anchor = _anchor_line(source, lines)
    target = _nearest_node(nodes, anchor, parsed)
    block = _nearest_block(target, root)
    target_span = _relative_span(target, parsed)

    return {
        "changed": _make_region(source, parsed, target, "changed", f"{prefix}:changed"),
        "block": _make_region(source, parsed, block, "block", f"{prefix}:block"),
        "context": _make_region(
            source,
            parsed,
            target,
            "context",
            f"{prefix}:context",
            span=_line_context_span(source, target_span.start_line, target_span.end_line),
            node_type="context_slice",
        ),
        "function": _make_region(source, parsed, root, "function", f"{prefix}:function"),
    }


def _change_kind(entry: CorpusEntry) -> str:
    kinds = {line.kind for line in entry.diagnostic_lines}
    if kinds == {"added"}:
        return "insertion"
    if kinds == {"removed"}:
        return "deletion"
    if kinds == {"added", "removed"}:
        return "replacement"
    return "unknown"


def extract_vulnerability_regions(entry: CorpusEntry) -> list[VulnerableRegionPair]:
    """Extract paired multi-resolution regions from one vulnerable/patched entry."""
    # A missing patched snapshot cannot provide a meaningful contrast.  Parsing an
    # empty string produces a synthetic ``program`` region, which then receives
    # zero structural/token similarity and can create an artificial vulnerable
    # margin.  Keep such records available to the vulnerable-side hash index, but
    # exclude them from paired region retrieval/verification.
    if not entry.vulnerable_function.strip() or not entry.patched_function.strip():
        return []
    vulnerable_lines = [line.vulnerable_line for line in entry.diagnostic_lines if line.vulnerable_line is not None]
    patched_lines = [line.patched_line for line in entry.diagnostic_lines if line.patched_line is not None]
    vulnerable = _regions_for_anchor(entry.vulnerable_function, vulnerable_lines, f"{entry.ghsa_id}:v")
    patched = _regions_for_anchor(entry.patched_function, patched_lines, f"{entry.ghsa_id}:p")
    vulnerable_digest = hashlib.sha256(entry.vulnerable_function.encode("utf-8")).hexdigest()
    patched_digest = hashlib.sha256(entry.patched_function.encode("utf-8")).hexdigest()

    pairs: list[VulnerableRegionPair] = []
    for granularity in ("changed", "block", "context", "function"):
        pair_id = (
            f"{entry.ghsa_id}:{entry.fix_commit_sha}:{entry.file_path}:"
            f"{entry.function_name}:{granularity}"
        )
        pairs.append(
            VulnerableRegionPair(
                pair_id=pair_id,
                ghsa_id=entry.ghsa_id,
                cve_id=entry.cve_id,
                advisory_title=entry.advisory_title,
                advisory_description=entry.advisory_description,
                advisory_url=entry.advisory_url,
                advisory_references=entry.advisory_references,
                cwes=entry.cwes,
                severity=entry.severity,
                repo=entry.repo,
                fix_commit_sha=entry.fix_commit_sha,
                file_path=entry.file_path,
                function_name=entry.function_name,
                package_name=entry.package_name,
                ecosystem=entry.ecosystem,
                osv_id=entry.osv_id,
                affected_versions=entry.affected_versions,
                fixed_versions=entry.fixed_versions,
                vulnerable_region=vulnerable[granularity].model_copy(update={"region_id": pair_id + ":vulnerable"}),
                patched_region=patched[granularity].model_copy(update={"region_id": pair_id + ":patched"}),
                change_kind=_change_kind(entry),
                diagnostic_line_count=len(entry.diagnostic_lines),
                vulnerable_source_sha256=vulnerable_digest,
                patched_source_sha256=patched_digest,
            )
        )
    return pairs


def extract_corpus_region_pairs(entries: list[CorpusEntry]) -> list[VulnerableRegionPair]:
    pairs: list[VulnerableRegionPair] = []
    for entry in entries:
        pairs.extend(extract_vulnerability_regions(entry))
    return pairs
