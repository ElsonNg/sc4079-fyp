"""Evaluate the 30-positive + 60-negative evaluation fixture serially.

Run from the repository root:

    PYTHONPATH=. .venv/bin/python -u scripts/validate_mixed_subset.py
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from corpus.controller.store import DEFAULT_DB_PATH, load_entries
from pipeline.controller.evaluation import vulnerable_origin_stages, vulnerable_origin_summary
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector

DEFAULT_POSITIVE_INPUT = Path(__file__).resolve().parent.parent / "eval" / "candidate_subset_30.jsonl"
DEFAULT_NEGATIVE_INPUT = Path(__file__).resolve().parent.parent / "eval" / "negative_subset_60.jsonl"
DEFAULT_OUTPUT = Path("/tmp/candidate_subset_90_results.json")


def _load_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _corpus_key(record: dict) -> tuple[str, str, str, str | None]:
    identity = record["corpus_entry"]
    return identity["ghsa_id"], identity["fix_commit_sha"], identity["file_path"], identity["function_name"]


def _pair_key(pair) -> tuple[str, str, str, str | None]:
    return pair.ghsa_id, pair.fix_commit_sha, pair.file_path, pair.function_name


def _expected_category(record: dict) -> str:
    return "positive" if record["expected_status"] == "flagged" else record["negative_category"]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive-input", type=Path, default=DEFAULT_POSITIVE_INPUT)
    parser.add_argument("--negative-input", type=Path, default=DEFAULT_NEGATIVE_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument(
        "--corpus-prefix",
        default=None,
        help="Only index corpus entries whose ghsa_id starts with this prefix",
    )
    args = parser.parse_args()

    positives = _load_records(args.positive_input)
    negatives = _load_records(args.negative_input)
    records = positives + negatives
    if args.limit is not None:
        records = records[: args.limit]

    print(
        f"Loaded {len(positives)} positives and {len(negatives)} negatives; "
        f"evaluating {len(records)} candidate(s)...",
        flush=True,
    )
    entries = load_entries(args.db_path)
    if args.corpus_prefix:
        entries = [entry for entry in entries if entry.ghsa_id.startswith(args.corpus_prefix)]
    if not entries:
        raise RuntimeError("No corpus entries matched the requested database/filter")
    config = RegionDetectorConfig(
        retrieval_top_k=10,
        retrieval_threshold=0.0,
        max_verification_candidates=10,
    )
    print(
        f"Preparing detector: {len(entries)} corpus entries, model={config.model_id}, top_k=10...",
        flush=True,
    )
    def report_index_progress(completed: int, total: int) -> None:
        print(f"Indexing regions: {completed}/{total}", flush=True)

    detector = build_region_detector(
        entries,
        config=config,
        progress_callback=report_index_progress,
    )
    print(
        f"Detector ready: {len(detector.region_index.pairs)} vulnerable/patched region pairs. "
        "Evaluating serially...",
        flush=True,
    )

    serialized = []
    rank_values: list[int | None] = []
    category_statuses: dict[str, Counter] = defaultdict(Counter)
    confusion: Counter = Counter()

    for index, record in enumerate(records, start=1):
        category = _expected_category(record)
        expected = record["expected_status"]
        print(
            f"[{index}/{len(records)}] running {record['candidate_id']} "
            f"category={category} expected={expected}...",
            flush=True,
        )
        result = detector.detect(record["candidate_source"], candidate_id=record["candidate_id"])
        actual = result.priority
        category_statuses[category][actual] += 1
        if expected == "flagged":
            outcome = "true_positive" if actual == "automatic_vulnerability" else (
                "abstained_positive" if actual == "manual_review" else "false_negative"
            )
        else:
            outcome = "false_positive" if actual == "automatic_vulnerability" else (
                "abstained_negative" if actual == "manual_review" else "true_negative"
            )
        confusion[outcome] += 1

        stages = None
        rank = None
        if expected == "flagged":
            expected_key = _corpus_key(record)
            stages = vulnerable_origin_stages(
                result.model_dump(mode="json"),
                expected=expected_key,
                pairs=detector.pairs,
            )
            rank = stages["expected_aggregate_rank"]
            rank_values.append(rank)

        serialized.append(
            {
                "candidate_id": record["candidate_id"],
                "expected_status": expected,
                "category": category,
                "negative_category": record.get("negative_category"),
                "corpus_entry": record["corpus_entry"],
                "expected_aggregate_rank": rank,
                **(stages or {}),
                "outcome": outcome,
                "result": result.model_dump(),
            }
        )
        print(
            f"[{index}/{len(records)}] {record['candidate_id']} "
            f"actual={actual:13s} outcome={outcome:20s} "
            f"regions={result.candidate_region_count:3d} "
            f"matches={result.retrieval_match_count:4d} "
            f"provenance={result.provenance_confidence}",
            flush=True,
        )

    positive_hash_count = sum(
        bool(row["result"]["hash_match_types"])
        for row in serialized
        if row["category"] == "positive"
    )
    positive_region_count = len(rank_values)
    summary = {
        "candidate_count": len(serialized),
        "positive_count": sum(row["category"] == "positive" for row in serialized),
        "negative_count": sum(row["category"] != "positive" for row in serialized),
        "patched_negative_count": sum(row["category"] == "patched" for row in serialized),
        "benign_similar_negative_count": sum(
            row["category"] == "benign_similar" for row in serialized
        ),
        "corpus_entry_count": len(entries),
        "region_pair_count": len(detector.region_index.pairs),
        "model_id": config.model_id,
        "retrieval_top_k": config.retrieval_top_k,
        "retrieval_threshold": config.retrieval_threshold,
        "positive_region_path_count": positive_region_count,
        "positive_hash_path_count": positive_hash_count,
        "positive_region_recall_at_1": (
            sum(rank is not None and rank <= 1 for rank in rank_values) / positive_region_count
            if positive_region_count else None
        ),
        "positive_region_recall_at_5": (
            sum(rank is not None and rank <= 5 for rank in rank_values) / positive_region_count
            if positive_region_count else None
        ),
        "priority_counts": dict(Counter(row["result"]["priority"] for row in serialized)),
        "priority_by_category": {key: dict(value) for key, value in sorted(category_statuses.items())},
        "outcome_counts": dict(confusion),
        **vulnerable_origin_summary(
            row for row in serialized if row["category"] == "positive"
        ),
    }
    output = {
        "schema": "candidate_subset_mixed_90_ast_region_methodology_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "positive_input": str(args.positive_input),
        "negative_input": str(args.negative_input),
        "methodology": "hash fast path -> multi-resolution AST-region retrieval -> three-signal localized verification",
        "summary": summary,
        "results": serialized,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
