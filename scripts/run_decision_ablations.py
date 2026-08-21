"""Ablate automatic-decision gates with retrieval fixed at K=5/evidence=20."""

from __future__ import annotations

import argparse
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from corpus.controller.store import load_entries
from pipeline.controller.evaluation import vulnerable_origin_stages, vulnerable_origin_summary
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector, derive_priority
from pipeline.controller.region_verification import RegionVerifierConfig, classify_boundary


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POSITIVES = ROOT / "eval" / "candidate_subset_30.jsonl"
DEFAULT_NEGATIVES = ROOT / "eval" / "negative_subset_60.jsonl"
DEFAULT_OUTPUT = ROOT / "eval" / "decision_ablation_k5_evidence20_results.json"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _expected(record: dict) -> tuple[str, str, str, str | None]:
    item = record["corpus_entry"]
    return item["ghsa_id"], item["fix_commit_sha"], item["file_path"], item["function_name"]


def _configurations() -> list[tuple[str, RegionVerifierConfig]]:
    values: list[tuple[str, RegionVerifierConfig]] = []
    for score in (0.75, 0.80, 0.85, 0.90):
        for margin in (0.08, 0.12, 0.15, 0.20, 0.25):
            for signature in (0.50, 0.65):
                name = f"s{score:.2f}_m{margin:.2f}_sig{signature:.2f}"
                values.append((name, RegionVerifierConfig(
                    minimum_vulnerable_score=score,
                    minimum_margin=margin,
                    signature_threshold=signature,
                )))
    values.extend([
        ("baseline_support3", RegionVerifierConfig(minimum_supporting_regions=3)),
        ("baseline_support4", RegionVerifierConfig(minimum_supporting_regions=4)),
        ("baseline_consensus075", RegionVerifierConfig(minimum_consensus_ratio=0.75)),
        ("baseline_patched_margin004", RegionVerifierConfig(patched_margin=0.04)),
        ("baseline_patched_margin012", RegionVerifierConfig(patched_margin=0.12)),
    ])
    return values


def _reclassify(result, pairs: dict, verifier: RegionVerifierConfig):
    if result.hash_matches:
        return result
    grouped = defaultdict(list)
    for evidence in result.evidence:
        grouped[pairs[evidence.pair_id].fix_boundary_id].append(evidence)
    states = []
    for boundary_id, evidence in sorted(grouped.items()):
        pair = pairs[evidence[0].pair_id]
        states.append(classify_boundary(evidence, pair, verifier))
    priority = derive_priority(result.lineages, states, result.package_applicabilities)
    return result.model_copy(update={"vulnerability_states": states, "priority": priority})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive-input", type=Path, default=DEFAULT_POSITIVES)
    parser.add_argument("--negative-input", type=Path, default=DEFAULT_NEGATIVES)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    positives = [dict(item, category="positive") for item in _load(args.positive_input)]
    negatives = [
        dict(item, category=item.get("negative_category", "negative"))
        for item in _load(args.negative_input)
    ]
    records = positives + negatives
    started = time.perf_counter()
    entries = load_entries()
    retrieval_config = RegionDetectorConfig(
        retrieval_top_k=5,
        retrieval_threshold=0.0,
        max_verification_candidates=20,
    )
    print(f"Loading K5/evidence-20 detector for {len(entries)} corpus entries...", flush=True)
    detector = build_region_detector(entries, config=retrieval_config)
    print(f"Index ready: {len(detector.region_index.pairs)} region pairs", flush=True)
    baseline_results = []
    for index, record in enumerate(records, 1):
        result = detector.detect(record["candidate_source"], candidate_id=record["candidate_id"])
        baseline_results.append(result)
        print(f"[{index}/{len(records)}] verified {record['candidate_id']} -> {result.priority}", flush=True)

    summaries, results_by_config = [], {}
    for name, verifier in _configurations():
        positive_priorities, negative_priorities = Counter(), Counter()
        patched_auto = benign_auto = wrong_origin_auto = 0
        origin_rows, rows = [], []
        for record, baseline in zip(records, baseline_results):
            result = _reclassify(baseline, detector.pairs, verifier)
            row = {
                "candidate_id": record["candidate_id"],
                "category": record["category"],
                "priority": result.priority,
            }
            if record["category"] == "positive":
                positive_priorities[result.priority] += 1
                stages = vulnerable_origin_stages(
                    result.model_dump(mode="json"), expected=_expected(record), pairs=detector.pairs,
                )
                row.update(stages)
                origin_rows.append(row)
                if result.priority == "automatic_vulnerability" and not stages["origin_automatically_flagged"]:
                    wrong_origin_auto += 1
            else:
                negative_priorities[result.priority] += 1
                if result.priority == "automatic_vulnerability":
                    if record["category"] == "patched":
                        patched_auto += 1
                    elif record["category"] == "benign_similar":
                        benign_auto += 1
            rows.append(row)

        positive_count, negative_count = len(positives), len(negatives)
        positive_auto = positive_priorities["automatic_vulnerability"]
        negative_auto = negative_priorities["automatic_vulnerability"]
        total_auto = positive_auto + negative_auto
        summary = {
            "name": name,
            "minimum_vulnerable_score": verifier.minimum_vulnerable_score,
            "minimum_margin": verifier.minimum_margin,
            "signature_threshold": verifier.signature_threshold,
            "patched_margin": verifier.patched_margin,
            "minimum_supporting_regions": verifier.minimum_supporting_regions,
            "minimum_consensus_ratio": verifier.minimum_consensus_ratio,
            **vulnerable_origin_summary(origin_rows),
            "positive_priorities": dict(positive_priorities),
            "negative_priorities": dict(negative_priorities),
            "positive_automatic_count": positive_auto,
            "positive_automatic_rate": positive_auto / positive_count,
            "expected_origin_automatic_count": sum(
                item["origin_automatically_flagged"] for item in origin_rows
            ),
            "wrong_origin_automatic_positive_count": wrong_origin_auto,
            "negative_automatic_count": negative_auto,
            "negative_automatic_rate": negative_auto / negative_count,
            "patched_automatic_count": patched_auto,
            "benign_similar_automatic_count": benign_auto,
            "negative_review_count": negative_priorities["manual_review"],
            "negative_review_rate": negative_priorities["manual_review"] / negative_count,
            "binary_automatic_precision": positive_auto / total_auto if total_auto else None,
        }
        summaries.append(summary)
        results_by_config[name] = rows

    summaries.sort(key=lambda item: (
        item["negative_automatic_count"],
        -item["expected_origin_automatic_count"],
        -item["origin_visible_count"],
    ))
    output = {
        "schema": "provtrail_decision_ablation_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "retrieval": {"top_k": 5, "threshold": 0.0, "evidence_budget": 20},
        "corpus_entry_count": len(entries),
        "region_pair_count": len(detector.region_index.pairs),
        "positive_count": len(positives),
        "negative_count": len(negatives),
        "methodology": (
            "One K5/evidence-20 verification pass; reclassify identical evidence under each "
            "decision-gate configuration"
        ),
        "total_elapsed_seconds": time.perf_counter() - started,
        "summaries": summaries,
        "results": results_by_config,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print("Top configurations:", flush=True)
    print(json.dumps(summaries[:12], indent=2), flush=True)
    print(f"Wrote {args.output}", flush=True)


if __name__ == "__main__":
    main()
