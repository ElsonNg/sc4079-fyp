"""Stage-by-stage vulnerable-origin metrics for corpus evaluation."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


OriginKey = tuple[str, str, str, str | None]


def _value(item: Any, name: str, default: Any = None) -> Any:
    return item.get(name, default) if isinstance(item, Mapping) else getattr(item, name, default)


def _origin_key(item: Any) -> OriginKey:
    origin = _value(item, "origin", item)
    advisory = _value(item, "advisory", item)
    return (
        str(_value(advisory, "ghsa_id") or ""),
        str(_value(origin, "fix_commit_sha") or ""),
        str(_value(origin, "file_path") or ""),
        _value(origin, "function_name"),
    )


def _matches_origin(item: Any, expected: OriginKey) -> bool:
    actual = _origin_key(item)
    if actual[1:] != expected[1:]:
        return False
    advisory_ids = {
        str(_value(alias, "ghsa_id") or "")
        for alias in (_value(item, "advisories", []) or [])
    }
    return actual[0] == expected[0] or expected[0] in advisory_ids


def _primary_lineage(lineages: list[dict[str, Any]]) -> dict[str, Any] | None:
    credible = [
        item for item in lineages
        if item.get("confidence") in {"high", "medium"}
    ]
    values = credible or lineages
    return max(values, key=lambda item: float(item.get("score") or 0.0), default=None)


def vulnerable_origin_stages(
    result: Mapping[str, Any],
    *,
    expected: OriginKey,
    pairs: Mapping[str, Any],
) -> dict[str, Any]:
    """Measure whether an expected vulnerable origin survives each evidence stage.

    ``origin_visible`` follows the report's default policy: every retained lineage is
    visible, including low-confidence lineages. User filters do not change the metric.
    """

    expected_pair_ids = {
        pair_id for pair_id, pair in pairs.items() if _matches_origin(pair, expected)
    }
    expected_lineage_ids = {
        str(_value(pairs[pair_id], "lineage_id") or "")
        for pair_id in expected_pair_ids
        if _value(pairs[pair_id], "lineage_id")
    }
    expected_boundary_ids = {
        str(_value(pairs[pair_id], "fix_boundary_id") or "")
        for pair_id in expected_pair_ids
        if _value(pairs[pair_id], "fix_boundary_id")
    }
    hash_matches = list(result.get("hash_matches") or [])
    expected_hashes = [item for item in hash_matches if _matches_origin(item, expected)]
    aggregates = list(result.get("aggregates") or [])
    aggregate_rank = next(
        (
            rank for rank, item in enumerate(aggregates, start=1)
            if item.get("pair_id") in expected_pair_ids
        ),
        None,
    )
    shortlisted = bool(expected_hashes) or aggregate_rank is not None
    verified = bool(expected_hashes) or any(
        item.get("pair_id") in expected_pair_ids for item in (result.get("evidence") or [])
    )
    lineages = list(result.get("lineages") or [])
    retained = any(
        str(item.get("lineage_id") or "") in expected_lineage_ids for item in lineages
    )
    primary = _primary_lineage(lineages)
    primary_matches = bool(primary) and str(primary.get("lineage_id") or "") in expected_lineage_ids
    expected_vulnerable_boundary = any(
        item.get("status") == "vulnerable"
        and (
            str(item.get("fix_boundary_id") or "") in expected_boundary_ids
            or str(item.get("lineage_id") or "") in expected_lineage_ids
        )
        for item in (result.get("vulnerability_states") or [])
    )
    priority = result.get("priority") or result.get("status")
    return {
        "expected_aggregate_rank": aggregate_rank,
        "origin_shortlisted": shortlisted,
        "origin_verified": verified,
        "origin_retained": retained,
        "origin_visible": retained,
        "origin_primary": primary_matches,
        "origin_automatically_flagged": (
            priority in {"automatic_vulnerability", "flagged"}
            and expected_vulnerable_boundary
        ),
    }


def vulnerable_origin_summary(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Aggregate staged vulnerable-origin rates from serialized evaluation rows."""

    values = list(rows)
    count = len(values)
    names = (
        "origin_shortlisted",
        "origin_verified",
        "origin_retained",
        "origin_visible",
        "origin_primary",
        "origin_automatically_flagged",
    )
    output: dict[str, Any] = {"origin_candidate_count": count}
    for name in names:
        matched = sum(bool(item.get(name)) for item in values)
        output[f"{name}_count"] = matched
        output[f"{name}_rate"] = matched / count if count else None
    return output
