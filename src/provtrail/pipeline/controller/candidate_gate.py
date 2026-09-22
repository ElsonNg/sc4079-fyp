"""Preservation gate for transformed vulnerable-clone candidates.

An LLM asked to rewrite a function may silently "fix" the bug (turning a labelled
positive into a mislabelled negative) or regenerate a memorised patch. This gate
rejects such outputs before they enter an evaluation set, by checking that the
security-relevant constructs recorded in the corpus ``diagnostic_lines`` survive
the rewrite.

The anchors are chosen to be exactly the things a behaviour-preserving rewrite
must keep even when it renames locals and restructures control flow: literal
constants (strings, template text, regexes, numbers) and the names of called
functions / accessed properties (library API surface). Bare local identifiers are
ignored because renaming them is a legitimate Type-3 transformation.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import tree_sitter

from provtrail.corpus.models.corpus import DiagnosticLine
from provtrail.pipeline.controller.parsing import normalize_source, parse_source

_WORD_RE = re.compile(r"[A-Za-z_$][\w$]*")


@dataclass
class GateResult:
    passed: bool
    reason: str
    ungateable: bool = False
    parses: bool = True
    literal_anchors: list[str] = field(default_factory=list)
    call_anchors: list[str] = field(default_factory=list)
    missing_literals: list[str] = field(default_factory=list)
    missing_calls: list[str] = field(default_factory=list)


def _diagnostic_text(diagnostic_lines: list[DiagnosticLine | dict], side: str) -> str:
    kind = "removed" if side == "vulnerable" else "added"
    texts: list[str] = []
    for line in diagnostic_lines:
        payload = line if isinstance(line, dict) else line.model_dump()
        if payload.get("kind") == kind:
            texts.append(payload.get("text", ""))
    return "\n".join(texts)


def _literal_content(node: tree_sitter.Node, source_bytes: bytes) -> str | None:
    raw = source_bytes[node.start_byte:node.end_byte].decode("utf-8", "replace")
    if node.type in {"string", "template_string"}:
        inner = raw[1:-1] if len(raw) >= 2 else ""
        return inner if inner.strip() else None
    if node.type in {"regex", "number"}:
        return raw if raw.strip() else None
    return None


def _collect_anchors(text: str) -> tuple[list[str], list[str]]:
    """Return (literal_anchors, call_property_anchors) found in a code fragment.

    The fragment may be a partial diff hunk; tree-sitter error-recovers, and we
    walk whatever nodes it produces. Wrapping in a function block helps a bare
    statement fragment parse into real literal/call nodes.
    """
    literals: list[str] = []
    calls: list[str] = []
    for candidate_text in (text, f"function __anchor__() {{\n{text}\n}}"):
        source_bytes = candidate_text.encode("utf-8")
        tree = parse_source(candidate_text, language="javascript")

        def walk(node: tree_sitter.Node) -> None:
            if node.type in {"string", "template_string", "regex", "number"}:
                content = _literal_content(node, source_bytes)
                if content is not None:
                    literals.append(content)
            elif node.type == "call_expression":
                function = node.child_by_field_name("function")
                if function is not None:
                    if function.type == "identifier":
                        calls.append(function.text.decode("utf-8"))
                    elif function.type == "member_expression":
                        prop = function.child_by_field_name("property")
                        if prop is not None:
                            calls.append(prop.text.decode("utf-8"))
            elif node.type == "member_expression":
                prop = node.child_by_field_name("property")
                if prop is not None and prop.type == "property_identifier":
                    calls.append(prop.text.decode("utf-8"))
            elif node.type == "new_expression":
                constructor = node.child_by_field_name("constructor")
                if constructor is not None and constructor.type == "identifier":
                    calls.append(constructor.text.decode("utf-8"))
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        if literals or calls:
            break

    # Preserve order while de-duplicating.
    return list(dict.fromkeys(literals)), list(dict.fromkeys(calls))


def has_high_signal_anchor(
    diagnostic_lines: list[DiagnosticLine | dict], side: str
) -> bool:
    """True if the diagnostic lines for ``side`` contain at least one literal or
    call/property anchor — i.e. the entry is gateable at all."""
    literals, calls = _collect_anchors(_diagnostic_text(diagnostic_lines, side))
    return bool(literals or calls)


def _parses(source: str) -> bool:
    # Try both grammars: a transformed TypeScript function keeps type syntax that the
    # JavaScript grammar rejects, and vice versa. A candidate is accepted if either
    # grammar parses it cleanly (optionally inside a class wrapper for method snippets).
    for language in ("javascript", "typescript"):
        for text in (source, "class __CandidateWrapper {\n" + source + "\n}\n"):
            try:
                if not parse_source(text, language=language).root_node.has_error:
                    return True
            except (RuntimeError, ValueError):
                continue
    return False


def _word_present(candidate: str, word: str) -> bool:
    return re.search(rf"(?<![\w$]){re.escape(word)}(?![\w$])", candidate) is not None


def diagnostic_preservation_gate(
    candidate_source: str,
    diagnostic_lines: list[DiagnosticLine | dict],
    *,
    side: str,
    vulnerable_source: str | None = None,
    patched_source: str | None = None,
    min_call_ratio: float = 0.5,
) -> GateResult:
    """Check that a transformed function preserves its security-relevant anchors.

    ``side`` is "vulnerable" for a transformed vulnerable function (a positive) or
    "patched" for a paraphrased patched function (a negative). The gate passes iff
    the candidate parses, every literal anchor from the relevant diagnostic lines
    survives, at least ``min_call_ratio`` of the call/property anchors survive, and
    the candidate is materially different from both the vulnerable and patched
    originals (when supplied).
    """
    if side not in {"vulnerable", "patched"}:
        raise ValueError(f"side must be 'vulnerable' or 'patched', got {side!r}")

    if not _parses(candidate_source):
        return GateResult(passed=False, reason="candidate_parse_error", parses=False)

    literal_anchors, call_anchors = _collect_anchors(_diagnostic_text(diagnostic_lines, side))
    if not literal_anchors and not call_anchors:
        return GateResult(
            passed=False,
            reason="ungateable_no_anchor",
            ungateable=True,
            literal_anchors=literal_anchors,
            call_anchors=call_anchors,
        )

    missing_literals = [lit for lit in literal_anchors if lit not in candidate_source]
    missing_calls = [name for name in call_anchors if not _word_present(candidate_source, name)]

    surviving_calls = len(call_anchors) - len(missing_calls)
    call_ratio = surviving_calls / len(call_anchors) if call_anchors else 1.0

    result = GateResult(
        passed=False,
        reason="",
        literal_anchors=literal_anchors,
        call_anchors=call_anchors,
        missing_literals=missing_literals,
        missing_calls=missing_calls,
    )

    if missing_literals:
        result.reason = "literal_anchor_dropped"
        return result
    if call_ratio < min_call_ratio:
        result.reason = "call_anchors_dropped"
        return result

    if vulnerable_source is not None and _normalized_equal(candidate_source, vulnerable_source):
        result.reason = "identical_to_vulnerable"
        return result
    if patched_source is not None and _normalized_equal(candidate_source, patched_source):
        result.reason = "identical_to_patched"
        return result

    result.passed = True
    result.reason = "ok"
    return result


def _normalized_equal(left: str, right: str) -> bool:
    try:
        return normalize_source(left) == normalize_source(right)
    except (RuntimeError, ValueError):
        return left.strip() == right.strip()
