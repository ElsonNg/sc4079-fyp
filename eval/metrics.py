"""Shared evaluation metrics for Tier 1, Tier 2, and ablation runs."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from typing import Any


ABSTAINED = {"abstained_positive", "abstained_negative"}
EXCLUDED = {"not_applicable", "source_fetch_error", "source_absent", "function_absent"}
METRICS_SCHEMA = "interim_report_chapter5_v1"


def classification_outcome(expected_status: str, priority: str) -> str:
    """Convert a verifier priority and ground-truth status into a confusion bucket."""
    automatic = priority in {"automatic_vulnerability", "flagged"}
    review = priority in {"manual_review", "abstained"}
    if expected_status == "flagged":
        return "true_positive" if automatic else (
            "abstained_positive" if review else "false_negative"
        )
    return "false_positive" if automatic else (
        "abstained_negative" if review else "true_negative"
    )


def _rate(rows: list[Mapping[str, Any]], predicate) -> float | None:
    return sum(bool(predicate(row)) for row in rows) / len(rows) if rows else None


def retrieval_rank(row: Mapping[str, Any]) -> int | None:
    """Return the effective lineage rank, with expected hash evidence at rank 1."""
    if row.get("hash_retrieval_hit"):
        return 1
    value = row.get("retrieval_rank")
    return int(value) if value is not None else None


def ranked_retrieval_rank(row: Mapping[str, Any]) -> int | None:
    """Return only the aggregate-ranking rank, excluding exact hash hits."""
    value = row.get("ranked_retrieval_rank", row.get("retrieval_rank"))
    return int(value) if value is not None else None


def expected_hash_match_types(
    detection: Any,
    expected: tuple[str, str, str, str | None],
) -> set[str]:
    """Return exact/abstracted hash types belonging to the expected lineage boundary."""

    def field(value: Any, name: str, default: Any = None) -> Any:
        return value.get(name, default) if isinstance(value, Mapping) else getattr(value, name, default)

    expected_ghsa, expected_commit, expected_path, expected_function = expected
    matched: set[str] = set()
    for match in field(detection, "hash_matches", []) or []:
        origin = field(match, "origin", match)
        advisory = field(match, "advisory", match)
        aliases = {
            str(field(alias, "ghsa_id", "") or "")
            for alias in (field(match, "advisories", []) or [])
        }
        identity_matches = (
            str(field(origin, "fix_commit_sha", "") or "") == expected_commit
            and str(field(origin, "file_path", "") or "").replace("\\", "/") == expected_path
            and field(origin, "function_name") == expected_function
            and (
                str(field(advisory, "ghsa_id", "") or "") == expected_ghsa
                or expected_ghsa in aliases
            )
        )
        if identity_matches:
            match_type = str(field(match, "match_type", "") or "")
            if match_type in {"exact", "abstracted"}:
                matched.add(match_type)
    return matched


def expected_retrieval_fields(record: Mapping[str, Any]) -> tuple[str, str, str, str | None]:
    entry = record.get("corpus_entry") or record
    return (
        str(entry.get("ghsa_id") or ""),
        str(entry.get("fix_commit_sha") or ""),
        str(entry.get("file_path") or "").replace("\\", "/"),
        entry.get("function_name"),
    )


def detection_rank(detection: Any, expected: tuple[str, str, str, str | None], pairs: Mapping[str, Any]) -> int | None:
    """Find the first ranked aggregate belonging to the expected corpus pair."""
    def field(value: Any, name: str, default: Any = None) -> Any:
        return value.get(name, default) if isinstance(value, Mapping) else getattr(value, name, default)

    aggregates = field(detection, "aggregates", []) or []

    matching_ids = set()
    for pair_id, pair in pairs.items():
        origin = field(pair, "origin", pair)
        advisory = field(pair, "advisory", pair)
        fields = (
            str(field(advisory, "ghsa_id", "") or ""),
            str(field(origin, "fix_commit_sha", "") or ""),
            str(field(origin, "file_path", "") or "").replace("\\", "/"),
            field(origin, "function_name"),
        )
        if fields[1:] == expected[1:] and (fields[0] == expected[0] or expected[0] in {
            str(field(alias, "ghsa_id", "") or "")
            for alias in (field(pair, "advisories", []) or [])
        }):
            matching_ids.add(pair_id)
    return next(
        (rank for rank, aggregate in enumerate(aggregates, start=1)
         if field(aggregate, "pair_id") in matching_ids),
        None,
    )


def retrieval_metrics(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    values = list(rows)
    ranks = [retrieval_rank(row) for row in values]
    non_hash_values = [row for row in values if not row.get("hash_retrieval_hit")]
    non_hash_ranks = [ranked_retrieval_rank(row) for row in non_hash_values]

    def rank_metrics(scoped_values, scoped_ranks):
        count = len(scoped_values)
        return {
            "sample_count": count,
            "recall_at_1": sum(rank is not None and rank <= 1 for rank in scoped_ranks) / count if count else None,
            "recall_at_5": sum(rank is not None and rank <= 5 for rank in scoped_ranks) / count if count else None,
            "recall_at_10": sum(rank is not None and rank <= 10 for rank in scoped_ranks) / count if count else None,
            "mrr": sum(1.0 / rank for rank in scoped_ranks if rank is not None) / count if count else None,
            "misses": sum(rank is None for rank in scoped_ranks),
        }

    combined = rank_metrics(values, ranks)
    return {
        **combined,
        "hash_retrieval_hits": sum(bool(row.get("hash_retrieval_hit")) for row in values),
        "exact_hash_retrieval_hits": sum(bool(row.get("exact_hash_retrieval_hit")) for row in values),
        "abstracted_hash_retrieval_hits": sum(bool(row.get("abstracted_hash_retrieval_hit")) for row in values),
        "non_hash_retrieval": rank_metrics(non_hash_values, non_hash_ranks),
    }


def verification_metrics(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    values = list(rows)
    scored = [row for row in values if row.get("outcome") not in EXCLUDED]
    vulnerable = [row for row in scored if row.get("expected_status") == "flagged"]
    patched = [row for row in scored if row.get("expected_status") == "cleared"]
    true_positive = sum(row.get("outcome") == "true_positive" for row in vulnerable)
    false_negative = sum(row.get("outcome") == "false_negative" for row in vulnerable)
    vulnerable_abstained = sum(row.get("outcome") == "abstained_positive" for row in vulnerable)
    patched_false_positive = sum(row.get("outcome") == "false_positive" for row in patched)
    patched_true_negative = sum(row.get("outcome") == "true_negative" for row in patched)
    patched_abstained = sum(row.get("outcome") == "abstained_negative" for row in patched)

    def fraction(numerator: int, denominator: int) -> float | None:
        return numerator / denominator if denominator else None

    return {
        "sample_count": len(values),
        "scored_count": len(scored),
        "true_positive": true_positive,
        "false_negative": false_negative,
        "vulnerable_abstained": vulnerable_abstained,
        "patched_false_positive": patched_false_positive,
        "patched_true_negative": patched_true_negative,
        "patched_abstained": patched_abstained,
        "vulnerable_recall": fraction(true_positive, true_positive + false_negative),
        "patched_false_positive_rate": fraction(
            patched_false_positive, patched_false_positive + patched_true_negative
        ),
        "abstention_rate": fraction(
            vulnerable_abstained + patched_abstained,
            len(scored),
        ),
        "outcome_counts": dict(Counter(row.get("outcome", "unknown") for row in values)),
    }


def llm_metrics(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    all_values = list(rows)
    values = [row for row in all_values if row.get("llm_decision") is not None]
    decisions = [
        row for row in values
        if row.get("llm_decision") not in {"abstained", "manual_review"}
    ]
    correct = [
        row for row in decisions
        if (row.get("llm_decision") == "vulnerable") == (row.get("expected_status") == "flagged")
    ]
    vulnerable = [
        row for row in all_values
        if row.get("expected_status") == "flagged" and row.get("outcome") not in EXCLUDED
    ]
    final_true_positives = sum(
        row.get("outcome") == "true_positive" or row.get("llm_decision") == "vulnerable"
        for row in vulnerable
    )
    return {
        "llm_sample_count": len(values),
        "llm_non_abstained_count": len(decisions),
        "llm_abstention_count": len(values) - len(decisions),
        "llm_decision_accuracy": len(correct) / len(decisions) if decisions else None,
        "llm_adjusted_vulnerable_recall": (
            final_true_positives / len(vulnerable) if values and vulnerable else None
        ),
    }


def summarize_evaluation(rows: Iterable[Mapping[str, Any]], *, strata: tuple[str, ...] = ()) -> dict[str, Any]:
    values = list(rows)
    output = {
        "metrics_schema": METRICS_SCHEMA,
        "retrieval": retrieval_metrics(values),
        "verification": verification_metrics(values),
        "llm": llm_metrics(values),
    }
    by_stratum: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in values:
        key = "/".join(str(row.get(field, "na")) for field in strata) if strata else "all"
        by_stratum[key].append(row)
    output["by_stratum"] = {
        key: {"retrieval": retrieval_metrics(group), "verification": verification_metrics(group),
              "llm": llm_metrics(group)}
        for key, group in sorted(by_stratum.items())
    }
    return output
