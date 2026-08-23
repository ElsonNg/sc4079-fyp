"""Shared evaluation metrics for Tier 1, Tier 2, and ablation runs."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from typing import Any


ABSTAINED = {"abstained_positive", "abstained_negative"}
EXCLUDED = {"not_applicable", "source_fetch_error", "source_absent", "function_absent"}


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
    """Return the ranked aggregate position of the expected lineage.

    Exact hash hits are deliberately reported separately and do not receive a
    synthetic rank, so Recall@K/MRR remain metrics of ranked retrieval.
    """
    value = row.get("retrieval_rank")
    return int(value) if value is not None else None


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
        fields = (
            str(field(pair, "ghsa_id", "") or ""),
            str(field(pair, "fix_commit_sha", "") or ""),
            str(field(pair, "file_path", "") or "").replace("\\", "/"),
            field(pair, "function_name"),
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
    return {
        "sample_count": len(values),
        "recall_at_1": _rate(values, lambda row: retrieval_rank(row) is not None and retrieval_rank(row) <= 1),
        "recall_at_5": _rate(values, lambda row: retrieval_rank(row) is not None and retrieval_rank(row) <= 5),
        "recall_at_10": _rate(values, lambda row: retrieval_rank(row) is not None and retrieval_rank(row) <= 10),
        "mrr": sum(1.0 / rank for rank in ranks if rank is not None) / len(values) if values else None,
        "ranked_misses": sum(rank is None for rank in ranks),
        "hash_retrieval_hits": sum(bool(row.get("hash_retrieval_hit")) for row in values),
    }


def verification_metrics(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    values = list(rows)
    scored = [row for row in values if row.get("outcome") not in EXCLUDED]
    vulnerable = [row for row in scored if row.get("expected_status") == "flagged"]
    patched = [row for row in scored if row.get("expected_status") == "cleared"]
    return {
        "sample_count": len(values),
        "scored_count": len(scored),
        "true_positive": sum(row.get("outcome") == "true_positive" for row in scored),
        "false_negative": sum(row.get("outcome") == "false_negative" for row in scored),
        "patched_false_positive": sum(row.get("outcome") == "false_positive" for row in patched),
        "patched_true_negative": sum(row.get("outcome") == "true_negative" for row in patched),
        "vulnerable_recall": _rate(vulnerable, lambda row: row.get("outcome") == "true_positive"),
        "vulnerable_recall_including_abstain": _rate(
            vulnerable, lambda row: row.get("outcome") in {"true_positive", "abstained_positive"}
        ),
        "patched_false_positive_rate": _rate(
            patched, lambda row: row.get("outcome") == "false_positive"
        ),
        "abstention_rate": _rate(values, lambda row: row.get("outcome") in ABSTAINED),
        "outcome_counts": dict(Counter(row.get("outcome", "unknown") for row in values)),
    }


def llm_metrics(rows: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    values = [row for row in rows if row.get("llm_decision") is not None]
    decisions = [row for row in values if row.get("llm_decision") not in {"abstained", "manual_review"}]
    correct = [
        row for row in decisions
        if (row.get("llm_decision") == "vulnerable") == (row.get("expected_status") == "flagged")
    ]
    vulnerable = [row for row in values if row.get("expected_status") == "flagged"]
    return {
        "llm_sample_count": len(values),
        "llm_non_abstained_count": len(decisions),
        "llm_abstention_count": len(values) - len(decisions),
        "llm_decision_accuracy": len(correct) / len(decisions) if decisions else None,
        "llm_adjusted_vulnerable_recall": (
            sum(row.get("llm_decision") == "vulnerable" for row in vulnerable) / len(vulnerable)
            if vulnerable else None
        ),
    }


def summarize_evaluation(rows: Iterable[Mapping[str, Any]], *, strata: tuple[str, ...] = ()) -> dict[str, Any]:
    values = list(rows)
    output = {"retrieval": retrieval_metrics(values), "verification": verification_metrics(values),
              "llm": llm_metrics(values)}
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
