"""Run corpus-wide retrieval/verification ablations on the 30+60 fixture.

Candidate AST regions are embedded and searched once at the largest requested K.
Each configuration then filters those identical ranked results before verification,
so differences are caused by the retrieval budget/threshold rather than repeated
model inference.
"""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean

from corpus.controller.store import load_entries
from pipeline.controller.evaluation import vulnerable_origin_stages, vulnerable_origin_summary
from pipeline.controller.region_detection import RegionDetector, RegionDetectorConfig, build_region_detector
from pipeline.controller.region_extraction import enumerate_candidate_regions
from pipeline.controller.region_retrieval import query_region_batch


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POSITIVES = ROOT / "eval" / "candidate_subset_30.jsonl"
DEFAULT_NEGATIVES = ROOT / "eval" / "negative_subset_60.jsonl"
DEFAULT_OUTPUT = ROOT / "eval" / "retrieval_ablation_results.json"

CONFIGURATIONS = (
    {"name": "k5_verify5_t0", "top_k": 5, "verify": 5, "threshold": 0.0},
    {"name": "k5_verify20_t0", "top_k": 5, "verify": 20, "threshold": 0.0},
    {"name": "k10_verify10_t0", "top_k": 10, "verify": 10, "threshold": 0.0},
    {"name": "k10_verify20_t0", "top_k": 10, "verify": 20, "threshold": 0.0},
    {"name": "k20_verify20_t0", "top_k": 20, "verify": 20, "threshold": 0.0},
    {"name": "k20_verify10_t0", "top_k": 20, "verify": 10, "threshold": 0.0},
    {"name": "k10_verify10_t055", "top_k": 10, "verify": 10, "threshold": 0.55},
    {"name": "k10_verify10_t070", "top_k": 10, "verify": 10, "threshold": 0.70},
)


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _expected(record: dict) -> tuple[str, str, str, str | None]:
    item = record["corpus_entry"]
    return item["ghsa_id"], item["fix_commit_sha"], item["file_path"], item["function_name"]


def _expected_pair_ids(record: dict, pairs: dict) -> set[str]:
    expected = _expected(record)
    values = set()
    for pair_id, pair in pairs.items():
        core = (pair.origin.fix_commit_sha, pair.origin.file_path, pair.origin.function_name)
        aliases = {item.ghsa_id for item in pair.advisories}
        if core == expected[1:] and (pair.advisory.ghsa_id == expected[0] or expected[0] in aliases):
            values.add(pair_id)
    return values


def _percentile_95(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return float(ordered[min(len(ordered) - 1, int(0.95 * len(ordered)))])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive-input", type=Path, default=DEFAULT_POSITIVES)
    parser.add_argument("--negative-input", type=Path, default=DEFAULT_NEGATIVES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    positives, negatives = _load(args.positive_input), _load(args.negative_input)
    records = [dict(item, category="positive") for item in positives]
    records.extend(dict(item, category=item.get("negative_category", "negative")) for item in negatives)
    if args.limit is not None:
        records = records[: args.limit]

    started = time.perf_counter()
    entries = load_entries()
    max_k = max(item["top_k"] for item in CONFIGURATIONS)
    print(f"Loading region index for {len(entries)} corpus entries...", flush=True)
    base = build_region_detector(entries, config=RegionDetectorConfig(
        retrieval_top_k=max_k, retrieval_threshold=0.0,
        max_verification_candidates=max(item["verify"] for item in CONFIGURATIONS),
    ))
    print(f"Index ready: {len(base.region_index.pairs)} region pairs", flush=True)

    prepared = []
    for index, record in enumerate(records, 1):
        regions = enumerate_candidate_regions(
            record["candidate_source"], candidate_id=record["candidate_id"], max_regions=96,
        )
        raw_batches = query_region_batch(regions, base.region_index, top_k=max_k, threshold=0.0)
        prepared.append((record, regions, [match for batch in raw_batches for match in batch]))
        print(f"[{index}/{len(records)}] retrieved {record['candidate_id']} ({len(regions)} regions)", flush=True)

    pairs = base.pairs
    summaries, per_configuration = [], {}
    for spec in CONFIGURATIONS:
        config_started = time.perf_counter()
        config = RegionDetectorConfig(
            retrieval_top_k=spec["top_k"], retrieval_threshold=spec["threshold"],
            max_verification_candidates=spec["verify"],
        )
        detector = RegionDetector(entries, base.region_index, base.hash_index, config)
        rows, origin_rows, unique_pair_counts = [], [], []
        positive_priorities, negative_priorities = Counter(), Counter()
        for record, regions, raw_matches in prepared:
            matches = [
                item for item in raw_matches
                if item.rank <= spec["top_k"] and item.similarity >= spec["threshold"]
            ]
            unique_pair_counts.append(len({item.pair_id for item in matches}))
            result = detector.detect(
                record["candidate_source"], candidate_id=record["candidate_id"],
                _candidate_regions=regions, _matches=matches,
            )
            payload = result.model_dump(mode="json")
            row = {
                "candidate_id": record["candidate_id"], "category": record["category"],
                "priority": result.priority, "retrieval_match_count": len(matches),
            }
            if record["category"] == "positive":
                positive_priorities[result.priority] += 1
                stages = vulnerable_origin_stages(payload, expected=_expected(record), pairs=pairs)
                expected_pairs = _expected_pair_ids(record, pairs)
                ranks = [item.rank for item in matches if item.pair_id in expected_pairs]
                row.update(stages)
                row["origin_retrieved"] = bool(ranks) or bool(payload["hash_matches"])
                row["best_raw_origin_rank"] = min(ranks) if ranks else None
                origin_rows.append(row)
            else:
                negative_priorities[result.priority] += 1
            rows.append(row)

        positive_count = sum(positive_priorities.values())
        negative_count = sum(negative_priorities.values())
        origin_summary = vulnerable_origin_summary(origin_rows)
        origin_retrieved = sum(item["origin_retrieved"] for item in origin_rows)
        summary = {
            **spec,
            "positive_count": positive_count, "negative_count": negative_count,
            "positive_priorities": dict(positive_priorities),
            "negative_priorities": dict(negative_priorities),
            "origin_retrieved_count": origin_retrieved,
            "origin_retrieved_rate": origin_retrieved / positive_count if positive_count else None,
            **origin_summary,
            "unsafe_negative_automatic_count": negative_priorities["automatic_vulnerability"],
            "unsafe_negative_automatic_rate": (
                negative_priorities["automatic_vulnerability"] / negative_count if negative_count else None
            ),
            "negative_review_count": negative_priorities["manual_review"],
            "negative_review_rate": negative_priorities["manual_review"] / negative_count if negative_count else None,
            "average_unique_pairs_retrieved": mean(unique_pair_counts) if unique_pair_counts else 0.0,
            "p95_unique_pairs_retrieved": _percentile_95(unique_pair_counts),
            "elapsed_seconds": time.perf_counter() - config_started,
        }
        summaries.append(summary)
        per_configuration[spec["name"]] = rows
        print(json.dumps(summary, indent=2), flush=True)

    output = {
        "schema": "provtrail_retrieval_ablation_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "corpus_entry_count": len(entries), "region_pair_count": len(base.region_index.pairs),
        "positive_input": str(args.positive_input), "negative_input": str(args.negative_input),
        "methodology": (
            "One shared max-K AST-region retrieval pass; rank/threshold filtering per configuration; "
            "unchanged localized verification and classification"
        ),
        "total_elapsed_seconds": time.perf_counter() - started,
        "summaries": summaries, "results": per_configuration,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
