"""Role-normalized tokens, API anchors and containment measurements."""

from __future__ import annotations

import re

from provtrail.pipeline.models.region import AstRegion
from provtrail.pipeline.detection.verification.sequences import sequence_similarity, containment_similarity


_IDENTIFIER_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


_API_ANCHOR_SEPARATOR_RE = re.compile(r"\?\.|\.")


_KEYWORDS = {
    "if", "else", "for", "while", "do", "switch", "case", "return", "throw", "try",
    "catch", "finally", "const", "let", "var", "new", "function", "class", "await",
    "async", "true", "false", "null", "undefined", "this", "typeof", "instanceof",
}


def _jaccard(left: list[str], right: list[str]) -> float | None:
    a, b = set(left), set(right)
    if not a and not b:
        return None
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def role_tokens(region: AstRegion) -> list[str]:
    tokens: list[str] = []
    literal_values = set(region.literals)
    for token in region.normalized_tokens:
        if token in literal_values:
            tokens.append("LIT")
        elif _IDENTIFIER_RE.match(token) and token not in _KEYWORDS:
            tokens.append("ID")
        else:
            tokens.append(token)
    # A regular expression is executable matching logic rather than an opaque
    # data literal. Keep its complete pattern and flags as an explicit token so
    # security fixes such as ``[^)]`` -> ``[^()]`` survive role normalization.
    # Ordinary strings and numbers continue to collapse to LIT above.
    tokens.extend(
        f"REGEX:{value}"
        for value in region.literals
        if value.startswith("/")
    )
    return tokens


def token_score(candidate: AstRegion, reference: AstRegion) -> float:
    role_score = sequence_similarity(role_tokens(candidate), role_tokens(reference))
    return role_score


def containment_components(
    candidate: AstRegion, reference: AstRegion, max_cells: int | None = None
) -> tuple[float, float, float]:
    shape, shape_coverage = containment_similarity(candidate.ast_shape, reference.ast_shape, max_cells)
    path, path_coverage = containment_similarity(candidate.ast_path, reference.ast_path, max_cells)
    token, token_coverage = containment_similarity(
        role_tokens(candidate), role_tokens(reference), max_cells
    )
    return 0.5 * shape + 0.5 * path, token, min(shape_coverage, path_coverage, token_coverage)


def _normalize_api_anchor(value: str) -> str:
    """Ignore a renameable receiver while retaining the API/property path."""
    compact = re.sub(r"\s+", "", value)
    parts = _API_ANCHOR_SEPARATOR_RE.split(compact)
    if len(parts) >= 2 and all(_IDENTIFIER_RE.match(part) for part in parts):
        if parts[0] not in {"this", "super"}:
            parts[0] = "ID"
        return ".".join(parts)
    return compact


def api_anchor_score(candidate: AstRegion, reference: AstRegion) -> float | None:
    calls = _jaccard(
        [_normalize_api_anchor(value) for value in candidate.calls],
        [_normalize_api_anchor(value) for value in reference.calls],
    )
    members = _jaccard(
        [_normalize_api_anchor(value) for value in candidate.member_accesses],
        [_normalize_api_anchor(value) for value in reference.member_accesses],
    )
    available = [score for score in (calls, members) if score is not None]
    return sum(available) / len(available) if available else None


def signature_coverage(values: list[str], candidate_tokens: set[str]) -> float:
    signature = {
        "ID" if _IDENTIFIER_RE.match(token) and token not in _KEYWORDS else token
        for token in values
        if token.strip()
    }
    return len(signature & candidate_tokens) / len(signature) if signature else 0.0
