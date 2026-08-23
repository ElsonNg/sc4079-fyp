"""Score the Tier-2 LLM-transformed set into a confusion matrix.

Modeled on validate_mixed_subset.py but uses only current RegionDetectionResult
fields (no provenance_confidence). Buckets detector.detect(...).priority against
each record's expected_status, broken down by clone type and language.

Run from the repo root:
    $env:PYTHONPATH="."; .venv\\Scripts\\python.exe scripts\\validate_llm_transformed_subset.py
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from corpus.controller.store import load_entries
from eval.common import DEFAULT_SNAPSHOT_DB, extension_for
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector

POSITIVE_INPUT = Path(__file__).resolve().parent.parent / "eval" / "llm_transformed_positive.jsonl"
NEGATIVE_INPUT = Path(__file__).resolve().parent.parent / "eval" / "llm_transformed_negative.jsonl"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "llm_transformed_results.json"


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _outcome(expected: str, priority: str) -> str:
    if expected == "flagged":
        if priority == "automatic_vulnerability":
            return "true_positive"
        return "abstained_positive" if priority == "manual_review" else "false_negative"
    if priority == "automatic_vulnerability":
        return "false_positive"
    return "abstained_negative" if priority == "manual_review" else "true_negative"


def _has_language_scoped_ghsa(detection, ghsa_id: str, language: str) -> bool:
    """Require the expected advisory to appear in same-language evidence."""
    payload = detection.model_dump(mode="json")

    def walk(node) -> bool:
        if isinstance(node, dict):
            if node.get("ghsa_id") == ghsa_id and node.get("source_language") == language:
                return True
            return any(walk(value) for value in node.values())
        if isinstance(node, list):
            return any(walk(value) for value in node)
        return False

    return walk(payload)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive", type=Path, default=POSITIVE_INPUT)
    parser.add_argument("--negative", type=Path, default=NEGATIVE_INPUT)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    records = _load(args.positive) + _load(args.negative)
    if not records:
        print("No candidate records found; run the generator first.")
        return 2

    entries = load_entries(args.snapshot)
    print(f"Corpus: {len(entries)} entries; candidates: {len(records)}")
    detector = build_region_detector(
        entries,
        config=RegionDetectorConfig(
            retrieval_top_k=10,
            retrieval_threshold=0.0,
            max_verification_candidates=10,
            same_language_only=True,
        ),
    )
    print(f"Detector ready: {len(detector.region_index.pairs)} region pairs")

    confusion: Counter = Counter()
    by_stratum: dict[str, Counter] = defaultdict(Counter)
    results = []

    for index, record in enumerate(records, start=1):
        expected = record["expected_status"]
        cid = f"{record['candidate_id']}{extension_for(record['source_language'])}"
        detection = detector.detect(
            record["candidate_source"],
            candidate_id=cid,
            language=record["source_language"],
        )
        priority = detection.priority
        outcome = _outcome(expected, priority)
        confusion[outcome] += 1
        stratum = f"{record.get('clone_type', 'na')}/{record['source_language']}"
        by_stratum[stratum][outcome] += 1

        expected_ghsa = record["corpus_entry"]["ghsa_id"]
        retrieved = _has_language_scoped_ghsa(detection, expected_ghsa, record["source_language"])
        results.append({
            "candidate_id": record["candidate_id"],
            "expected_status": expected,
            "clone_type": record.get("clone_type"),
            "source_language": record["source_language"],
            "package_name": record["package_name"],
            "corpus_entry": record["corpus_entry"],
            "priority": priority,
            "outcome": outcome,
            "expected_ghsa_retrieved": retrieved,
            "hash_match_types": detection.hash_match_types,
        })
        print(f"[{index}/{len(records)}] {record['candidate_id']:6s} {stratum:16s} "
              f"expected={expected:8s} priority={priority:22s} -> {outcome}")

    positives = [r for r in results if r["expected_status"] == "flagged"]
    negatives = [r for r in results if r["expected_status"] == "cleared"]

    def _rate(rows, predicate):
        return (sum(predicate(r) for r in rows) / len(rows)) if rows else None

    summary = {
        "candidate_count": len(results),
        "positive_count": len(positives),
        "negative_count": len(negatives),
        "corpus_entry_count": len(entries),
        "region_pair_count": len(detector.region_index.pairs),
        "outcome_counts": dict(confusion),
        "outcomes_by_stratum": {k: dict(v) for k, v in sorted(by_stratum.items())},
        "positive_recall_automatic": _rate(positives, lambda r: r["outcome"] == "true_positive"),
        "positive_recall_including_abstain": _rate(
            positives, lambda r: r["outcome"] in {"true_positive", "abstained_positive"}
        ),
        "positive_retrieval_hit_rate": _rate(positives, lambda r: r["expected_ghsa_retrieved"]),
        "negative_false_positive_rate": _rate(negatives, lambda r: r["outcome"] == "false_positive"),
    }
    output = {
        "schema": "llm_transformed_tier2_v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "positive_input": str(args.positive),
        "negative_input": str(args.negative),
        "summary": summary,
        "results": results,
    }
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print("\nSummary:")
    print(json.dumps(summary, indent=2))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
