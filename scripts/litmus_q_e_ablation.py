"""Tier-2 litmus for staged structural, token, and patch-local edit gates.

This is deliberately separate from production classification.  Structure must
first establish boundary correspondence, role-normalized tokens must confirm
the same reference side, and E then chooses vulnerable or patched.  Hash
matches retain their normal deterministic bypass.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from corpus.controller.extraction import compute_diagnostic_lines
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
from pipeline.controller.region_detection import (
    RegionDetectorConfig,
    build_region_detector,
    derive_priority,
)
from pipeline.controller.region_verification import RegionVerifierConfig
from pipeline.controller.region_verification import deduplicate_evidence
from pipeline.controller.parsing import source_language
from scripts.litmus_edit_signatures import score as edit_score
from scripts.validate_llm_transformed_subset import (
    NEGATIVE_INPUT,
    POSITIVE_INPUT,
    _expected_pair_ids,
    _has_language_scoped_ghsa,
    _load,
    _rank_expected_lineage,
)


ROOT = Path(__file__).resolve().parent.parent


def _record_language(record: dict) -> str:
    return record.get("source_language") or source_language(
        record.get("corpus_entry", {}).get("file_path", "candidate.js")
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--positive", type=Path, default=POSITIVE_INPUT)
    parser.add_argument("--negative", type=Path, default=NEGATIVE_INPUT)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--corpus-from-fixtures",
        action="store_true",
        help="Build a self-contained in-memory corpus from references embedded in the fixtures.",
    )
    parser.add_argument("--minimum-structure", type=float, default=0.70)
    parser.add_argument("--minimum-token", type=float, default=0.70)
    parser.add_argument("--minimum-e-side", type=float, default=0.90)
    parser.add_argument("--minimum-e-margin", type=float, default=0.10)
    return parser


def _fixture_entries(records: list[dict]) -> list[CorpusEntry]:
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


_GRANULARITY_WEIGHT = {"changed": 4.0, "block": 3.0, "context": 2.0, "function": 1.0}


def _weighted_median(values: list[tuple[float, float]]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    halfway = sum(weight for _value, weight in ordered) / 2.0
    running = 0.0
    for value, weight in ordered:
        running += weight
        if running >= halfway:
            return value
    return ordered[-1][0]


def _boundary_components(detection, boundary_id: str, pair_boundaries: dict[str, str]):
    independent = deduplicate_evidence([
        item
        for item in detection.evidence
        if pair_boundaries.get(item.pair_id) == boundary_id
    ])
    weighted = [
        (
            item,
            _GRANULARITY_WEIGHT[item.candidate_granularity] * max(item.ast_coverage, 0.1),
        )
        for item in independent
    ]

    def median(field: str) -> float:
        return _weighted_median([
            (getattr(item, field), weight)
            for item, weight in weighted
        ])

    return {
        "structural_vulnerable": median("structural_vulnerable"),
        "structural_patched": median("structural_patched"),
        "token_vulnerable": median("token_vulnerable"),
        "token_patched": median("token_patched"),
        "independent_region_count": len(independent),
    }


def _evidence_decisions(
    detection,
    candidate_source: str,
    function_pairs,
    pair_boundaries: dict[str, str],
    args,
):
    decisions = []
    revised_states = []
    for state in detection.vulnerability_states:
        pair = function_pairs.get(state.fix_boundary_id)
        components = _boundary_components(
            detection,
            state.fix_boundary_id,
            pair_boundaries,
        )
        structure_sides = {
            side
            for side in ("vulnerable", "patched")
            if components[f"structural_{side}"] >= args.minimum_structure
        }
        token_sides = {
            side
            for side in structure_sides
            if components[f"token_{side}"] >= args.minimum_token
        }
        structure_passed = bool(structure_sides)
        token_passed = bool(token_sides)
        status = "uncertain"
        vulnerable = patched = margin = 0.0
        if pair is not None:
            diagnostics = compute_diagnostic_lines(
                pair.vulnerable_region.source,
                pair.patched_region.source,
                language=pair.source_language,
            )
            scored = edit_score({
                "candidate_id": detection.candidate_id or "candidate",
                "expected_status": "flagged",
                "clone_type": None,
                "candidate_source": candidate_source,
                "diagnostic_lines": [item.model_dump() for item in diagnostics],
            })
            vulnerable = scored["edit_vulnerable"]
            patched = scored["edit_patched"]
            margin = scored["edit_margin"]
            if token_passed:
                if vulnerable >= args.minimum_e_side and margin >= args.minimum_e_margin:
                    status = "vulnerable"
                elif patched >= args.minimum_e_side and margin <= -args.minimum_e_margin:
                    status = "patched"
        decisions.append({
            "fix_boundary_id": state.fix_boundary_id,
            "ghsa_id": pair.ghsa_id if pair is not None else None,
            **components,
            "structure_passed": structure_passed,
            "structure_sides": sorted(structure_sides),
            "token_passed": token_passed,
            "token_sides": sorted(token_sides),
            "q_status": state.status,
            "edit_vulnerable": vulnerable,
            "edit_patched": patched,
            "edit_margin": margin,
            "e_status": status,
        })
        revised_states.append(state.model_copy(update={
            "status": status,
            "contradictions": [],
        }))
    priority = derive_priority(
        detection.lineages,
        revised_states,
        detection.package_applicabilities,
    )
    return priority, decisions


def main() -> int:
    args = _parser().parse_args()
    records = _load(args.positive) + _load(args.negative)
    entries = (
        _fixture_entries(records)
        if args.corpus_from_fixtures
        else load_entries(args.snapshot)
    )
    detector = build_region_detector(
        entries,
        config=RegionDetectorConfig(
            retrieval_top_k=10,
            retrieval_threshold=0.0,
            max_verification_candidates=10,
            same_language_only=True,
            verifier=RegionVerifierConfig(),
        ),
        save_index_artifact=not args.corpus_from_fixtures,
    )
    function_pairs = {
        pair.fix_boundary_id: pair
        for pair in detector.pairs.values()
        if pair.vulnerable_region.granularity == "function"
    }
    pair_boundaries = {
        pair.pair_id: pair.fix_boundary_id
        for pair in detector.pairs.values()
    }

    confusion: Counter = Counter()
    by_stratum: dict[str, Counter] = defaultdict(Counter)
    results = []
    for index, record in enumerate(records, start=1):
        language = _record_language(record)
        candidate_id = f"{record['candidate_id']}{extension_for(language)}"
        detection = detector.detect(
            record["candidate_source"],
            candidate_id=candidate_id,
            language=language,
        )
        if detection.hash_matches:
            priority = detection.priority
            e_decisions = []
        else:
            priority, e_decisions = _evidence_decisions(
                detection,
                record["candidate_source"],
                function_pairs,
                pair_boundaries,
                args,
            )
        outcome = classification_outcome(record["expected_status"], priority)
        confusion[outcome] += 1
        stratum = f"{record.get('clone_type', 'na')}/{language}"
        by_stratum[stratum][outcome] += 1

        expected_pair_ids = _expected_pair_ids(record, detector.pairs)
        ranked_rank = _rank_expected_lineage(detection, expected_pair_ids)
        hash_match_types = expected_hash_match_types(
            detection,
            expected_retrieval_fields(record),
        )
        hash_hit = bool(hash_match_types)
        results.append({
            "candidate_id": record["candidate_id"],
            "expected_status": record["expected_status"],
            "clone_type": record.get("clone_type"),
            "source_language": language,
            "package_name": record["package_name"],
            "corpus_entry": record["corpus_entry"],
            "priority": priority,
            "outcome": outcome,
            "expected_ghsa_retrieved": _has_language_scoped_ghsa(
                detection,
                record["corpus_entry"]["ghsa_id"],
                language,
            ),
            "expected_pair_ids": sorted(expected_pair_ids),
            "retrieval_rank": 1 if hash_hit else ranked_rank,
            "ranked_retrieval_rank": ranked_rank,
            "hash_retrieval_hit": hash_hit,
            "exact_hash_retrieval_hit": "exact" in hash_match_types,
            "abstracted_hash_retrieval_hit": "abstracted" in hash_match_types,
            "hash_match_types": sorted(hash_match_types),
            "e_decisions": e_decisions,
        })
        print(
            f"[{index}/{len(records)}] {record['candidate_id']:6s} "
            f"gates=S->T->E -> {outcome}",
            flush=True,
        )

    summary = {
        "candidate_count": len(results),
        "positive_count": sum(item["expected_status"] == "flagged" for item in results),
        "negative_count": sum(item["expected_status"] == "cleared" for item in results),
        "corpus_entry_count": len(entries),
        "region_pair_count": len(detector.region_index.pairs),
        **summarize_evaluation(results, strata=("clone_type", "source_language")),
    }
    payload = {
        "schema": "staged_s_t_e_litmus_v1",
        "metrics_schema": METRICS_SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "configuration": {
            "verification_gates": ["structure", "tokens", "edit"],
            "same_side_structure_token_confirmation": True,
            "api_anchors": False,
            "minimum_structure": args.minimum_structure,
            "minimum_token": args.minimum_token,
            "minimum_e_side": args.minimum_e_side,
            "minimum_e_margin": args.minimum_e_margin,
            "hash_bypass": True,
            "corpus_from_fixtures": args.corpus_from_fixtures,
        },
        "summary": summary,
        "results": results,
    }
    args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(json.dumps(summary["verification"], indent=2))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
