"""Evaluate the AST-region detector on eval/candidate_subset_30.jsonl.

Run from the repository root:
    PYTHONPATH=. .venv/bin/python -u scripts/validate_region_candidate_subset.py

Candidates are intentionally evaluated serially. This keeps each detector run
observable and makes it possible to stop after, or diagnose, a specific case.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from corpus.controller.store import load_entries
from pipeline.controller.evaluation import vulnerable_origin_stages, vulnerable_origin_summary
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector

DEFAULT_INPUT = Path(__file__).resolve().parent.parent / "eval" / "candidate_subset_30.jsonl"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "candidate_subset_30_region_results.json"


def _load_records(path: Path) -> list[dict]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(records) != 30:
        raise ValueError(f"Expected 30 records, found {len(records)}")
    return records


def _corpus_key(record: dict) -> tuple[str, str, str, str | None]:
    identity = record["corpus_entry"]
    return identity["ghsa_id"], identity["fix_commit_sha"], identity["file_path"], identity["function_name"]


def _pair_key(pair) -> tuple[str, str, str, str | None]:
    return pair.advisory.ghsa_id, pair.origin.fix_commit_sha, pair.origin.file_path, pair.origin.function_name


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model", default=None)
    parser.add_argument("--limit", type=int, default=None, help="Run only the first N records for a smoke evaluation")
    args = parser.parse_args()

    records = _load_records(args.input)
    if args.limit is not None:
        records = records[: args.limit]
    print(f"Loading {len(records)} candidate(s) and the corpus...", flush=True)
    entries = load_entries()
    config = RegionDetectorConfig(
        **({"model_id": args.model} if args.model else {}),
        retrieval_top_k=10,
        retrieval_threshold=0.0,
        max_verification_candidates=10,
    )
    print(
        f"Preparing detector: {len(entries)} corpus entries, model={config.model_id}, "
        "top_k=10...",
        flush=True,
    )
    def report_index_progress(done: int, total: int) -> None:
        print(f"  indexed corpus regions: {done}/{total}", flush=True)

    detector = build_region_detector(
        entries,
        config=config,
        progress_callback=report_index_progress,
    )
    print(
        f"Detector ready: {len(detector.region_index.pairs)} vulnerable/patched region pairs. "
        "Evaluating candidates serially...",
        flush=True,
    )

    serialized = []
    rank_values: list[int | None] = []
    results = []
    for index, record in enumerate(records, start=1):
        print(
            f"[{index}/{len(records)}] running {record['candidate_id']} "
            f"({record['transformation_family']})...",
            flush=True,
        )
        result = detector.detect(
            record["candidate_source"],
            candidate_id=record["candidate_id"],
        )
        results.append(result)
        expected = _corpus_key(record)
        result_payload = result.model_dump(mode="json")
        stages = vulnerable_origin_stages(
            result_payload,
            expected=expected,
            pairs=detector.pairs,
        )
        rank = stages["expected_aggregate_rank"]
        rank_values.append(rank)
        serialized.append(
            {
                "candidate_id": record["candidate_id"],
                "expected_status": record["expected_status"],
                "transformation_family": record["transformation_family"],
                "corpus_entry": record["corpus_entry"],
                **stages,
                "result": result_payload,
            }
        )
        print(
            f"[{index}/{len(records)}] {record['candidate_id']} priority={result.priority:24s} "
            f"regions={result.candidate_region_count:3d} matches={result.retrieval_match_count:4d} "
            f"correct_aggregate_rank={rank or 'MISS'} provenance={result.provenance_confidence}",
            flush=True,
        )

    summary = {
        "candidate_count": len(results),
        "corpus_entry_count": len(entries),
        "region_pair_count": len(detector.region_index.pairs),
        "model_id": config.model_id,
        "retrieval_top_k": config.retrieval_top_k,
        "retrieval_threshold": config.retrieval_threshold,
        "aggregate_recall_at_1": sum(rank is not None and rank <= 1 for rank in rank_values) / len(rank_values),
        "aggregate_recall_at_5": sum(rank is not None and rank <= 5 for rank in rank_values) / len(rank_values),
        "aggregate_recall_at_10": sum(rank is not None and rank <= 10 for rank in rank_values) / len(rank_values),
        "priority_counts": dict(Counter(result.priority for result in results)),
        "provenance_counts": dict(Counter(result.provenance_confidence for result in results)),
        **vulnerable_origin_summary(serialized),
    }
    output = {
        "schema": "candidate_subset_ast_region_methodology_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input": str(args.input),
        "methodology": "hash fast path -> multi-resolution AST-region retrieval -> localized AST verification -> vulnerable/patched contrast",
        "summary": summary,
        "results": serialized,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2), flush=True)
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
