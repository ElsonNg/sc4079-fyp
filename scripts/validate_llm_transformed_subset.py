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
from corpus.models.corpus import CorpusEntry
from eval.common import DEFAULT_SNAPSHOT_DB, extension_for
from eval.metrics import (
    METRICS_SCHEMA,
    classification_outcome,
    expected_hash_match_types,
    expected_retrieval_fields,
    summarize_evaluation,
)
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector
from pipeline.controller.region_verification import RegionVerifierConfig
from pipeline.controller.parsing import source_language

POSITIVE_INPUT = Path(__file__).resolve().parent.parent / "eval" / "llm_transformed_positive.jsonl"
NEGATIVE_INPUT = Path(__file__).resolve().parent.parent / "eval" / "llm_transformed_negative.jsonl"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "llm_transformed_results.json"


def _load(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _record_language(record: dict) -> str:
    return record.get("source_language") or source_language(
        record.get("corpus_entry", {}).get("file_path", "candidate.js")
    )


def _fixture_entries(records: list[dict]) -> list[CorpusEntry]:
    """Build the self-contained reference corpus embedded in fixture records."""
    entries = {}
    for record in records:
        identity = record["corpus_entry"]
        key = (
            identity["ghsa_id"],
            identity["fix_commit_sha"],
            identity["file_path"],
            identity.get("function_name"),
        )
        entries[key] = CorpusEntry(
            ghsa_id=identity["ghsa_id"],
            cve_id=identity.get("cve_id"),
            osv_id=record.get("osv_id"),
            cwes=record.get("cwes", []),
            severity=record.get("severity", "unknown"),
            package_name=record.get("package_name", "unknown"),
            ecosystem=record.get("ecosystem", "npm"),
            repo=identity["repo"],
            fix_commit_sha=identity["fix_commit_sha"],
            file_path=identity["file_path"],
            function_name=identity.get("function_name"),
            vulnerable_function=record["vulnerable_function"],
            patched_function=record["patched_function"],
            diagnostic_lines=record.get("diagnostic_lines", []),
            affected_versions=record.get("affected_versions", []),
            fixed_versions=record.get("fixed_versions", []),
            osv_confirmed=record.get("osv_confirmed", False),
            source_language=_record_language(record),
        )
    return list(entries.values())


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


def _expected_pair_ids(record: dict, pairs: dict) -> set[str]:
    """Resolve the generated candidate back to its original region pair.

    Tier-2 candidates retain the vulnerable source digest and corpus identity,
    but do not persist the derived region ``pair_id``.  Resolve that identity
    against the current immutable corpus/index so ranked retrieval metrics are
    measured against the actual vulnerable region pair.
    """
    entry = record["corpus_entry"]
    language = record.get("source_language")
    vulnerable_digest = record.get("vulnerable_source_sha256")
    expected_commit = entry.get("fix_commit_sha")
    expected_path = str(entry.get("file_path") or "").replace("\\", "/")
    expected_function = entry.get("function_name")
    expected_ghsa = entry.get("ghsa_id")

    matches: set[str] = set()
    for pair_id, pair in pairs.items():
        if language and pair.origin.source_language != language:
            continue
        if vulnerable_digest and pair.change.vulnerable_source_sha256 == vulnerable_digest:
            matches.add(pair_id)
            continue
        if (
            pair.origin.fix_commit_sha == expected_commit
            and pair.origin.file_path.replace("\\", "/") == expected_path
            and pair.origin.function_name == expected_function
            and (not expected_ghsa or pair.advisory.ghsa_id == expected_ghsa)
        ):
            matches.add(pair_id)
    return matches


def _rank_expected_lineage(detection, expected_pair_ids: set[str]) -> int | None:
    """Return the 1-based rank of the expected pair in ranked aggregates."""
    if not expected_pair_ids:
        return None
    for rank, aggregate in enumerate(detection.aggregates, start=1):
        if aggregate.pair_id in expected_pair_ids:
            return rank
    return None


def _review_contributor_keys(detection) -> set[tuple[str, str]]:
    """Mirror priority aggregation and identify states that force manual review."""
    if detection.priority != "manual_review":
        return set()
    vulnerable = [
        state for state in detection.vulnerability_states
        if state.status == "vulnerable"
    ]
    if vulnerable:
        return {
            (state.boundary.lineage_id, state.boundary.fix_boundary_id)
            for state in vulnerable if state.support.contradictions
        }
    credible = {
        lineage.lineage_id for lineage in detection.lineages
        if lineage.confidence in {"high", "medium"}
    }
    unresolved = [
        state for state in detection.vulnerability_states
        if state.boundary.lineage_id in credible
        and state.status == "uncertain"
        and not state.gates.boundary_rejected
    ]
    strong = [
        state for state in unresolved
        if state.gates.token_gate_passed or state.support.contradictions
    ]
    contributors = strong or unresolved
    return {(state.boundary.lineage_id, state.boundary.fix_boundary_id) for state in contributors}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--positive", type=Path, default=POSITIVE_INPUT)
    parser.add_argument("--negative", type=Path, default=NEGATIVE_INPUT)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--corpus-from-fixtures",
        action="store_true",
        help="Build a self-contained corpus from references embedded in the input fixtures.",
    )
    parser.add_argument("--minimum-e-side", type=float, default=0.90)
    parser.add_argument("--minimum-e-margin", type=float, default=0.10)
    parser.add_argument("--experimental-local-correspondence", action="store_true")
    args = parser.parse_args()

    records = _load(args.positive) + _load(args.negative)
    if not records:
        print("No candidate records found; run the generator first.")
        return 2

    entries = _fixture_entries(records) if args.corpus_from_fixtures else load_entries(args.snapshot)
    print(f"Corpus: {len(entries)} entries; candidates: {len(records)}")
    detector = build_region_detector(
        entries,
        config=RegionDetectorConfig(
            retrieval_top_k=10,
            retrieval_threshold=0.0,
            max_verification_candidates=10,
            include_local_correspondence_fallback=args.experimental_local_correspondence,
            verifier=RegionVerifierConfig(
                minimum_edit_side_score=args.minimum_e_side,
                minimum_edit_margin=args.minimum_e_margin,
            ),
        ),
    )
    print(f"Detector ready: {len(detector.region_index.pairs)} region pairs")

    confusion: Counter = Counter()
    by_stratum: dict[str, Counter] = defaultdict(Counter)
    results = []

    for index, record in enumerate(records, start=1):
        expected = record["expected_status"]
        language = _record_language(record)
        cid = f"{record['candidate_id']}{extension_for(language)}"
        detection = detector.detect(
            record["candidate_source"],
            candidate_id=cid,
            language=language,
        )
        priority = detection.priority
        outcome = classification_outcome(expected, priority)
        confusion[outcome] += 1
        stratum = f"{record.get('clone_type', 'na')}/{language}"
        by_stratum[stratum][outcome] += 1

        expected_ghsa = record["corpus_entry"]["ghsa_id"]
        retrieved = _has_language_scoped_ghsa(detection, expected_ghsa, language)
        expected_pair_ids = _expected_pair_ids(record, detector.pairs)
        ranked_rank = _rank_expected_lineage(detection, expected_pair_ids)
        hash_match_types = expected_hash_match_types(
            detection,
            expected_retrieval_fields(record),
        )
        exact_hash_retrieval_hit = "exact" in hash_match_types
        abstracted_hash_retrieval_hit = "abstracted" in hash_match_types
        hash_retrieval_hit = bool(hash_match_types)
        rank = 1 if hash_retrieval_hit else ranked_rank
        review_contributors = _review_contributor_keys(detection)
        boundary_verification = [
            {
                "lineage_id": state.boundary.lineage_id,
                "fix_boundary_id": state.boundary.fix_boundary_id,
                "status": state.status,
                "abstention_reason": state.abstention_reason,
                "edit_strategy": state.edit.strategy,
                "structure_gate_passed": state.gates.structure_gate_passed,
                "token_gate_passed": state.gates.token_gate_passed,
                "containment_fallback_attempted": state.fallbacks.containment_attempted,
                "containment_fallback_used": state.fallbacks.containment_used,
                "boundary_rejected": state.gates.boundary_rejected,
                "local_correspondence_attempted": state.fallbacks.local_correspondence_attempted,
                "local_correspondence_used": state.fallbacks.local_correspondence_used,
                "local_correspondence_status": state.fallbacks.local_correspondence_status,
                "local_correspondence_methods": state.fallbacks.local_correspondence_methods,
                "local_correspondence_reason": state.fallbacks.local_correspondence_reason,
                "local_correspondence_prior_abstention_reason": state.fallbacks.local_correspondence_prior_abstention_reason,
                "review_contributor": (
                    state.boundary.lineage_id, state.boundary.fix_boundary_id
                ) in review_contributors,
            }
            for state in detection.vulnerability_states
        ]
        results.append({
            "candidate_id": record["candidate_id"],
            "expected_status": expected,
            "clone_type": record.get("clone_type"),
            "source_language": language,
            "package_name": record["package_name"],
            "corpus_entry": record["corpus_entry"],
            "priority": priority,
            "outcome": outcome,
            "expected_ghsa_retrieved": retrieved,
            "expected_pair_ids": sorted(expected_pair_ids),
            "retrieval_rank": rank,
            "ranked_retrieval_rank": ranked_rank,
            "hash_retrieval_hit": hash_retrieval_hit,
            "exact_hash_retrieval_hit": exact_hash_retrieval_hit,
            "abstracted_hash_retrieval_hit": abstracted_hash_retrieval_hit,
            "hash_match_types": sorted(hash_match_types),
            "boundary_verification": boundary_verification,
        })
        print(f"[{index}/{len(records)}] {record['candidate_id']:6s} {stratum:16s} "
              f"expected={expected:8s} priority={priority:22s} -> {outcome}")

    summary = {
        "candidate_count": len(results),
        "positive_count": sum(r["expected_status"] == "flagged" for r in results),
        "negative_count": sum(r["expected_status"] == "cleared" for r in results),
        "corpus_entry_count": len(entries),
        "region_pair_count": len(detector.region_index.pairs),
        **summarize_evaluation(results, strata=("clone_type", "source_language")),
    }
    summary["abstention_reason_counts"] = dict(sorted(Counter(
        boundary["abstention_reason"]
        for result in results
        for boundary in result["boundary_verification"]
        if boundary["review_contributor"]
        and boundary["abstention_reason"] is not None
    ).items()))
    output = {
        "schema": "evaluation_results_v5",
        "metrics_schema": METRICS_SCHEMA,
        "tier": "tier2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "positive_input": str(args.positive),
        "negative_input": str(args.negative),
        "corpus_from_fixtures": args.corpus_from_fixtures,
        "experimental_local_correspondence": args.experimental_local_correspondence,
        "verification_thresholds": {
            "minimum_e_side": args.minimum_e_side,
            "minimum_e_margin": args.minimum_e_margin,
        },
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
