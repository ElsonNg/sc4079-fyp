"""Patch-local fuzzy edit scoring for vulnerable/patched side decisions."""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable

from provtrail.pipeline.controller.parsing import normalize_source
from provtrail.pipeline.models.evidence import EditDistanceEvidence


_KEYWORDS = {
    "async", "await", "break", "case", "catch", "class", "const", "continue",
    "default", "delete", "do", "else", "export", "extends", "false", "finally",
    "for", "function", "if", "import", "in", "instanceof", "let", "new", "null",
    "of", "return", "super", "switch", "this", "throw", "true", "try", "typeof",
    "undefined", "var", "void", "while", "yield",
}
_LEX = re.compile(
    r"""
    /(?:\\.|\[(?:\\.|[^\]\\])*\]|[^/\\\n])+/[A-Za-z]*
    |'(?:\\.|[^'\\])*'
    |"(?:\\.|[^"\\])*"
    |\`(?:\\.|[^\`\\])*\`
    |[A-Za-z_$][A-Za-z0-9_$]*
    |(?:\d+(?:\.\d+)?)
    |===|!==|=>|==|!=|<=|>=|&&|\|\||\?\?|\+\+|--|\+=|-=|\*=|/=|%=|\*\*
    |[^\s]
    """,
    re.VERBOSE,
)
_IDENTIFIER = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def role_tokens(source: str) -> list[str]:
    """Normalize renameable identifiers while preserving operations and regexes."""
    normalized = " ".join(normalize_source(source))
    raw = _LEX.findall(normalized)
    result: list[str] = []
    for index, token in enumerate(raw):
        if not _IDENTIFIER.match(token) or token in _KEYWORDS:
            result.append(token)
            continue
        previous = raw[index - 1] if index else ""
        following = raw[index + 1] if index + 1 < len(raw) else ""
        if previous in {".", "?."}:
            result.append(f"API:{token}")
        elif following == "(":
            result.append(f"CALL:{token}")
        else:
            result.append("ID")
    return result


def anchor_has_identity(tokens: list[str]) -> bool:
    """Whether an edit anchor retains a named operation or security literal.

    Pure syntax such as ``return ID [ ID ] ;`` is useful for fuzzy alignment,
    but cannot by itself identify which fix boundary it came from.
    """
    return any(
        token.startswith(("API:", "CALL:"))
        or token[:1] in {"'", '"', "`", "/"}
        or token[:1].isdigit()
        for token in tokens
    )


def fuzzy_substring_similarity(query: list[str], candidate: list[str]) -> float:
    """Levenshtein similarity against the candidate's best matching substring."""
    if not query or not candidate:
        return 0.0
    previous = [0] * (len(candidate) + 1)
    for row, query_token in enumerate(query, start=1):
        current = [row]
        for column, candidate_token in enumerate(candidate, start=1):
            current.append(min(
                previous[column] + 1,
                current[column - 1] + 1,
                previous[column - 1] + (query_token != candidate_token),
            ))
        previous = current
    return max(0.0, 1.0 - min(previous) / len(query))


def _line_value(line, field: str):
    return line.get(field) if isinstance(line, dict) else getattr(line, field)


def _coverage(anchors: list[list[str]], candidate: list[str]) -> float | None:
    if not anchors:
        return None
    weights = [len(anchor) for anchor in anchors]
    return sum(
        fuzzy_substring_similarity(anchor, candidate) * weight
        for anchor, weight in zip(anchors, weights)
    ) / sum(weights)


def _best_anchor_has_identity(anchors: list[list[str]], candidate: list[str]) -> bool | None:
    if not anchors:
        return None
    best = max(
        anchors,
        key=lambda anchor: (fuzzy_substring_similarity(anchor, candidate), len(anchor)),
    )
    return anchor_has_identity(best)


_DELTA_OPERATORS = {
    "===", "!==", "==", "!=", "<=", ">=", "<", ">", "&&", "||", "??",
    "!", "+", "-", "*", "/", "%", "=", "+=", "-=", "*=", "/=", "%=",
    "++", "--", "=>", "?", ":",
}
_DELTA_KEYWORDS = {
    "if", "else", "return", "throw", "new", "await", "typeof", "instanceof",
    "in", "delete", "true", "false", "null", "undefined",
}


def _is_distinctive_token(token: str) -> bool:
    """Keep behavior-bearing delta tokens, not punctuation or renameable IDs."""
    return (
        token.startswith(("API:", "CALL:"))
        or token[:1] in {"'", '"', "`", "/"}
        or token[:1].isdigit()
        or token in _DELTA_OPERATORS
        or token in _DELTA_KEYWORDS
    )


def _contrastive_anchors(
    anchors: list[list[str]],
    opposite: list[list[str]],
    radius: int = 2,
) -> list[list[str]]:
    """Extract local windows around behavior-bearing tokens unique to one side."""
    remaining = Counter(token for anchor in opposite for token in anchor)
    result: list[list[str]] = []
    for anchor in anchors:
        unique_positions: list[int] = []
        for index, token in enumerate(anchor):
            if remaining[token]:
                remaining[token] -= 1
            elif _is_distinctive_token(token):
                unique_positions.append(index)
        if not unique_positions:
            continue
        selected: set[int] = set()
        for index in unique_positions:
            selected.update(range(max(0, index - radius), min(len(anchor), index + radius + 1)))
        result.append([anchor[index] for index in sorted(selected)])
    return result


def score_edit_distance(candidate_source: str, diagnostic_lines: Iterable) -> EditDistanceEvidence:
    """Compare a candidate with the removed and added lines of one fix boundary."""
    candidate = role_tokens(candidate_source)
    lines = list(diagnostic_lines)
    vulnerable_anchors = [
        tokens
        for line in lines
        if _line_value(line, "kind") == "removed"
        if (tokens := role_tokens(_line_value(line, "text") or ""))
    ]
    patched_anchors = [
        tokens
        for line in lines
        if _line_value(line, "kind") == "added"
        if (tokens := role_tokens(_line_value(line, "text") or ""))
    ]
    raw_vulnerable = _coverage(vulnerable_anchors, candidate)
    raw_patched = _coverage(patched_anchors, candidate)
    vulnerable_delta = _contrastive_anchors(vulnerable_anchors, patched_anchors)
    patched_delta = _contrastive_anchors(patched_anchors, vulnerable_anchors)
    contrastive_vulnerable = _coverage(vulnerable_delta, candidate)
    contrastive_patched = _coverage(patched_delta, candidate)
    contrastive_used = contrastive_vulnerable is not None or contrastive_patched is not None
    if contrastive_vulnerable is not None and contrastive_patched is not None:
        vulnerable, patched = contrastive_vulnerable, contrastive_patched
    elif contrastive_patched is not None:
        patched = contrastive_patched
        vulnerable = (
            raw_vulnerable
            if raw_vulnerable is not None and raw_vulnerable > contrastive_patched
            else 1.0 - contrastive_patched
        )
    elif contrastive_vulnerable is not None:
        vulnerable = contrastive_vulnerable
        patched = (
            raw_patched
            if raw_patched is not None and raw_patched > contrastive_vulnerable
            else 1.0 - contrastive_vulnerable
        )
    else:
        vulnerable, patched = raw_vulnerable, raw_patched
    if vulnerable is None and patched is not None:
        vulnerable = 1.0 - patched
    if patched is None and vulnerable is not None:
        patched = 1.0 - vulnerable
    return EditDistanceEvidence(
        vulnerable or 0.0,
        patched or 0.0,
        vulnerable_anchor_has_identity=_best_anchor_has_identity(
            vulnerable_delta or vulnerable_anchors, candidate
        ),
        patched_anchor_has_identity=_best_anchor_has_identity(
            patched_delta or patched_anchors, candidate
        ),
        raw_vulnerable=raw_vulnerable,
        raw_patched=raw_patched,
        raw_vulnerable_anchor_has_identity=_best_anchor_has_identity(
            vulnerable_anchors, candidate
        ),
        raw_patched_anchor_has_identity=_best_anchor_has_identity(
            patched_anchors, candidate
        ),
        contrastive_vulnerable=contrastive_vulnerable,
        contrastive_patched=contrastive_patched,
        contrastive_vulnerable_anchor_has_identity=_best_anchor_has_identity(
            vulnerable_delta, candidate
        ),
        contrastive_patched_anchor_has_identity=_best_anchor_has_identity(
            patched_delta, candidate
        ),
        contrastive_used=contrastive_used,
    )
