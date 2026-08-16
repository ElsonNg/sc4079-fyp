"""Run the positive candidate subset through the current detector methodology.

This is an evaluation harness, not a pipeline implementation. It measures the
existing hash -> whole-function embedding retrieval -> hierarchical verification
path against the 30 records in eval/candidate_subset_30.jsonl.

Run from the repository root:
    PYTHONPATH=. .venv/bin/python scripts/validate_candidate_subset.py
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from corpus.controller.store import load_entries
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.hashing import build_hash_index, lookup
from pipeline.controller.hierarchy import EmbeddingCache
from pipeline.controller.retrieval import build_or_load_index, query_batch
from pipeline.controller.verification import verify_candidate

DEFAULT_INPUT = Path(__file__).resolve().parent.parent / "eval" / "candidate_subset_30.jsonl"
DEFAULT_OUTPUT = (
    Path(__file__).resolve().parent.parent / "eval" / "candidate_subset_30_current_results.json"
)
DEFAULT_RETRIEVAL_K = 5
DEFAULT_RETRIEVAL_THRESHOLD = 0.7


def _key_from_record(record: dict) -> tuple[str, str, str, str | None]:
    entry = record["corpus_entry"]
    return (entry["ghsa_id"], entry["fix_commit_sha"], entry["file_path"], entry["function_name"])


def _key_from_match(match) -> tuple[str, str, str, str | None]:
    return (match.ghsa_id, match.fix_commit_sha, match.file_path, match.function_name)


def _load_records(path: Path) -> list[dict]:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(records) != 30:
        raise ValueError(f"Expected 30 candidate records, found {len(records)}")
    return records


def _rank_for(matches: list, expected_key) -> tuple[int | None, float | None]:
    for rank, match in enumerate(matches, start=1):
        if _key_from_match(match) == expected_key:
            return rank, match.similarity
    return None, None


def _run_one(
    record: dict,
    entry_by_key: dict,
    hash_index,
    all_matches: list,
    default_matches: list,
    isolated_cache: EmbeddingCache,
) -> dict:
    expected_key = _key_from_record(record)
    entry = entry_by_key[expected_key]
    candidate = record["candidate_source"]

    hash_matches = lookup(candidate, hash_index)
    full_rank, full_similarity = _rank_for(all_matches, expected_key)
    default_rank, default_similarity = _rank_for(default_matches, expected_key)

    isolated = verify_candidate(candidate, entry, isolated_cache)

    # The correctness metric follows validate_worst_case.py: once the expected
    # corpus entry is in the default shortlist, the isolated verification result
    # is the end-to-end result for that entry. We intentionally do not verify the
    # other shortlist entries here; that measures attribution noise but does not
    # change whether this known-positive entry is detected.
    e2e_result = isolated if default_rank is not None else None

    retrieval_preview = [
        {
            "rank": rank,
            "similarity": match.similarity,
            "identity": {
                "ghsa_id": match.ghsa_id,
                "cve_id": match.cve_id,
                "fix_commit_sha": match.fix_commit_sha,
                "file_path": match.file_path,
                "function_name": match.function_name,
            },
        }
        for rank, match in enumerate(all_matches[:10], start=1)
    ]

    result = {
        "candidate_id": record["candidate_id"],
        "expected_status": record["expected_status"],
        "transformation_family": record["transformation_family"],
        "corpus_entry": record["corpus_entry"],
        "hash_match_types": sorted({match.match_type for match in hash_matches}),
        "hash_match_count": len(hash_matches),
        "retrieval_rank": full_rank,
        "retrieval_similarity": full_similarity,
        "retrieval_recall_at_1": full_rank is not None and full_rank <= 1,
        "retrieval_recall_at_5": full_rank is not None and full_rank <= 5,
        "retrieval_recall_at_10": full_rank is not None and full_rank <= 10,
        "default_shortlist_rank": default_rank,
        "default_shortlist_similarity": default_similarity,
        "default_shortlist_size": len(default_matches),
        "isolated_verification": isolated.model_dump(),
        "e2e_correct_entry_verification": e2e_result.model_dump() if e2e_result else None,
        "wrong_entry_verification_performed": False,
        "retrieval_top10": retrieval_preview,
    }

    print(
        f"  {record['candidate_id']} {record['corpus_entry']['cve_id']} "
        f"hash={','.join(result['hash_match_types']) or 'none':14s} "
        f"rank={full_rank or 'MISS':>4} "
        f"default={default_rank or 'MISS':>4} "
        f"isolated={isolated.status:13s} "
        f"e2e={e2e_result.status if e2e_result else 'NOT_RETRIEVED'}"
    )
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--model", default=DEFAULT_MODEL_ID)
    parser.add_argument("--k", type=int, default=DEFAULT_RETRIEVAL_K)
    parser.add_argument("--threshold", type=float, default=DEFAULT_RETRIEVAL_THRESHOLD)
    args = parser.parse_args()

    records = _load_records(args.input)
    entries = load_entries()
    entry_by_key = {
        (e.ghsa_id, e.fix_commit_sha, e.file_path, e.function_name): e
        for e in entries
    }
    missing = [_key_from_record(record) for record in records if _key_from_record(record) not in entry_by_key]
    if missing:
        raise RuntimeError(f"Candidate records refer to missing corpus entries: {missing}")

    print(f"Corpus entries: {len(entries)}")
    print(f"Candidates: {len(records)}")
    print(f"Model: {args.model}")
    print(f"Default retrieval: k={args.k}, threshold={args.threshold}")
    print("Building current whole-function hash and retrieval indexes...")
    started = time.time()
    hash_index = build_hash_index(entries)
    retrieval_index = build_or_load_index(entries, model_id=args.model)
    print(f"Indexes ready in {time.time() - started:.1f}s")

    sources = [record["candidate_source"] for record in records]
    all_matches_batch = query_batch(sources, retrieval_index, k=len(entries), threshold=0.0)
    # The default-threshold shortlist is a filter over the same full ranking.
    # Reusing that ranking preserves the current retrieval semantics and avoids
    # encoding the same 30 candidates a second time.
    default_matches_batch = [
        [match for match in matches[: args.k] if match.similarity >= args.threshold]
        for matches in all_matches_batch
    ]

    print("Running current methodology per candidate:")
    isolated_cache = EmbeddingCache()
    results = []
    for record, all_matches, default_matches in zip(
        records, all_matches_batch, default_matches_batch
    ):
        results.append(
            _run_one(
                record,
                entry_by_key,
                hash_index,
                all_matches,
                default_matches,
                isolated_cache,
            )
        )

    e2e_statuses = [
        result["e2e_correct_entry_verification"]["status"]
        if result["e2e_correct_entry_verification"]
        else "not_retrieved"
        for result in results
    ]
    isolated_statuses = [result["isolated_verification"]["status"] for result in results]
    summary = {
        "candidate_count": len(results),
        "corpus_entry_count": len(entries),
        "model_id": args.model,
        "retrieval_k": args.k,
        "retrieval_threshold": args.threshold,
        "hash_match_rate": sum(result["hash_match_count"] > 0 for result in results) / len(results),
        "hash_match_type_counts": dict(
            Counter(
                match_type
                for result in results
                for match_type in result["hash_match_types"]
            )
        ),
        "retrieval_recall_at_1": sum(result["retrieval_recall_at_1"] for result in results) / len(results),
        "retrieval_recall_at_5": sum(result["retrieval_recall_at_5"] for result in results) / len(results),
        "retrieval_recall_at_10": sum(result["retrieval_recall_at_10"] for result in results) / len(results),
        "default_shortlist_reached_correct_entry": sum(
            result["default_shortlist_rank"] is not None for result in results
        ) / len(results),
        "isolated_status_counts": dict(Counter(isolated_statuses)),
        "isolated_expected_flagged": sum(status == "flagged" for status in isolated_statuses),
        "e2e_correct_entry_status_counts": dict(Counter(e2e_statuses)),
        "e2e_expected_flagged": sum(status == "flagged" for status in e2e_statuses),
        "e2e_correct_entry_reached_and_flagged": sum(status == "flagged" for status in e2e_statuses),
        "e2e_not_retrieved": sum(status == "not_retrieved" for status in e2e_statuses),
    }

    output = {
        "schema": "candidate_subset_current_methodology_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "input": str(args.input),
        "methodology": "whole-function hash -> whole-function embedding retrieval -> hierarchical verification",
        "verification_scope": "correct_retrieved_entry_only",
        "summary": summary,
        "results": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")

    print("\nSummary:")
    print(json.dumps(summary, indent=2))
    print(f"\nWrote raw results to {args.output}")


if __name__ == "__main__":
    main()
