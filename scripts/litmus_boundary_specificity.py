"""Observe boundary-specificity evidence without changing production decisions.

The staged verifier answers two separate questions:

* S/T: does an AST region correspond to either side of a fix boundary?
* E: does a removed or added diagnostic line occur somewhere in the candidate?

This litmus checks whether those signals meet on the same candidate region and
how common the decisive edit anchors are in the corpus.  It deliberately does
not introduce a threshold or reclassify a result.
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
from eval.common import DEFAULT_SNAPSHOT_DB
from pipeline.controller.edit_distance import fuzzy_substring_similarity, role_tokens, score_edit_distance
from pipeline.controller.region_extraction import enumerate_candidate_regions, extract_corpus_region_pairs
from pipeline.controller.region_verification import RegionVerifierConfig, verify_region_pair
from pipeline.controller.parsing import extract_function_units, source_language


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUTS = (
    ROOT / "eval" / "llm_transformed_positive.jsonl",
    ROOT / "eval" / "llm_transformed_negative.jsonl",
    ROOT / "eval" / "candidate_subset_30.jsonl",
    ROOT / "eval" / "negative_subset_60.jsonl",
    ROOT / "eval" / "klaban_verification_positive.jsonl",
    ROOT / "eval" / "klaban_verification_negative.jsonl",
)
DEFAULT_RESULTS = (
    ROOT / "eval" / "llm_transformed_results_staged_s070_t070_e.json",
    ROOT / "eval" / "wider_deterministic_fixture_staged_s070_t070_e.json",
    ROOT / "eval" / "wider_klaban_fixture_staged_s070_t070_e.json",
)
DEFAULT_OUTPUT = ROOT / "eval" / "boundary_specificity_litmus.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--input", type=Path, action="append", dest="inputs")
    parser.add_argument("--results", type=Path, action="append", dest="result_files")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--minimum-structure", type=float, default=0.70)
    parser.add_argument("--minimum-token", type=float, default=0.70)
    parser.add_argument("--minimum-e-side", type=float, default=0.90)
    parser.add_argument("--minimum-e-margin", type=float, default=0.10)
    return parser


def _load_jsonl(paths: list[Path]) -> dict[str, dict]:
    records: dict[str, dict] = {}
    for path in paths:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                record = json.loads(line)
                records.setdefault(record["candidate_id"], record)
    return records


def _fixture_entries(records: list[dict]) -> list[CorpusEntry]:
    """Recreate references that were used by self-contained fixture runs."""
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
            source_language=record.get("source_language") or source_language(identity["file_path"]),
        )
    return list(entries.values())


def _contains(sequence: list[str], query: list[str]) -> bool:
    if not query or len(query) > len(sequence):
        return False
    width = len(query)
    return any(sequence[index:index + width] == query for index in range(len(sequence) - width + 1))


def _anchors(diagnostics, side: str) -> list[dict]:
    kind = "removed" if side == "vulnerable" else "added"
    values = []
    for line in diagnostics:
        if line.kind != kind:
            continue
        tokens = role_tokens(line.text or "")
        if tokens:
            values.append({"text": line.text, "tokens": tokens})
    return values


def _corpus_snapshots(entries) -> list[tuple[str, str, list[str]]]:
    return [
        (entry.ghsa_id, "vulnerable", role_tokens(entry.vulnerable_function))
        for entry in entries
    ] + [
        (entry.ghsa_id, "patched", role_tokens(entry.patched_function))
        for entry in entries
    ]


def _corpus_anchor_frequency(snapshots, anchors: list[dict]) -> list[dict]:
    output = []
    for anchor in anchors:
        matching = [
            {"ghsa_id": ghsa_id, "side": side}
            for ghsa_id, side, tokens in snapshots
            if _contains(tokens, anchor["tokens"])
        ]
        output.append({
            **anchor,
            "token_count": len(anchor["tokens"]),
            "snapshot_document_frequency": len(matching),
            "snapshot_document_ratio": len(matching) / len(snapshots) if snapshots else 0.0,
            "matching_snapshots": matching,
        })
    return output


def _best_anchor_matches(anchors: list[dict], candidate_source: str) -> list[dict]:
    candidate = role_tokens(candidate_source)
    def identity_tokens(tokens: list[str]) -> list[str]:
        return [
            token for token in tokens
            if token.startswith(("API:", "CALL:"))
            or token[:1] in {"'", '"', "`", "/"}
            or token[:1].isdigit()
        ]
    return sorted(
        ({
            **anchor,
            "candidate_similarity": fuzzy_substring_similarity(anchor["tokens"], candidate),
            "identity_tokens": identity_tokens(anchor["tokens"]),
        }
         for anchor in anchors),
        key=lambda item: (-item["candidate_similarity"], item["snapshot_document_frequency"]),
    )


def _localized_evidence(candidate_source: str, language: str, boundary_pairs, side: str, args) -> dict:
    filename = f"candidate.{ 'ts' if language == 'typescript' else 'tsx' if language == 'tsx' else 'js'}"
    functions = extract_function_units(candidate_source, filename=filename)
    outer_function = max(functions, key=lambda unit: unit.end_byte - unit.start_byte, default=None)
    candidates = enumerate_candidate_regions(
        candidate_source,
        candidate_id="specificity-litmus",
        function_name=outer_function.name if outer_function is not None else None,
        filename=filename,
    )
    by_granularity = {pair.vulnerable_region.granularity: pair for pair in boundary_pairs}
    rows = []
    for candidate in candidates:
        pair = by_granularity.get(candidate.region.granularity)
        if pair is None:
            continue
        verification = verify_region_pair(
            candidate.region,
            pair,
            retrieval_similarity=0.0,
            config=RegionVerifierConfig(),
            use_embedding_alignment=False,
            language=language,
        )
        edit = score_edit_distance(
            candidate.region.source,
            compute_diagnostic_lines(
                pair.vulnerable_region.source,
                pair.patched_region.source,
                language=language,
            ),
        )
        correspondence = (
            getattr(verification, f"structural_{side}") >= args.minimum_structure
            and getattr(verification, f"token_{side}") >= args.minimum_token
        )
        direction = edit.margin if side == "vulnerable" else -edit.margin
        edit_passed = getattr(edit, side) >= args.minimum_e_side and direction >= args.minimum_e_margin
        rows.append({
            "candidate_region_id": candidate.region.region_id,
            "candidate_function_name": candidate.function_name,
            "granularity": candidate.region.granularity,
            "source": candidate.region.source,
            "structural": getattr(verification, f"structural_{side}"),
            "token": getattr(verification, f"token_{side}"),
            "edit_side": getattr(edit, side),
            "edit_margin_toward_decision": direction,
            "correspondence_passed": correspondence,
            "edit_passed": edit_passed,
            "same_region_passed": correspondence and edit_passed,
        })
    passing = [row for row in rows if row["same_region_passed"]]
    context_granularities = sorted({
        row["granularity"] for row in rows
        if row["correspondence_passed"] and row["granularity"] in {"block", "context", "function"}
    })
    return {
        "same_region_gate_passed": bool(passing),
        "passing_region_count": len(passing),
        "passing_granularities": sorted({row["granularity"] for row in passing}),
        "context_correspondence_granularities": context_granularities,
        "context_correspondence_passed": bool(context_granularities),
        "candidate_function_names": sorted({
            candidate.function_name for candidate in candidates if candidate.function_name
        }),
        "best_regions": sorted(
            rows,
            key=lambda row: (
                not row["same_region_passed"],
                -min(row["structural"], row["token"]),
                -row["edit_side"],
            ),
        )[:5],
    }


def main() -> int:
    args = _parser().parse_args()
    inputs = args.inputs or list(DEFAULT_INPUTS)
    result_files = args.result_files or list(DEFAULT_RESULTS)
    records = _load_jsonl(inputs)
    entries = load_entries(args.snapshot)
    corpus_snapshots = _corpus_snapshots(entries)
    pairs = extract_corpus_region_pairs(entries)
    pairs_by_boundary = defaultdict(list)
    for pair in pairs:
        pairs_by_boundary[pair.fix_boundary_id].append(pair)
    # The wider tests were intentionally built from their embedded references.
    # Keep corpus-frequency statistics tied to the production snapshot, but add
    # those fixture boundaries to the lookup used for local signal analysis.
    snapshot_boundary_ids = set(pairs_by_boundary)
    for pair in extract_corpus_region_pairs(_fixture_entries(list(records.values()))):
        if pair.fix_boundary_id not in snapshot_boundary_ids:
            pairs_by_boundary[pair.fix_boundary_id].append(pair)

    frequency_cache: dict[tuple[str, str], list[dict]] = {}
    rows = []
    skipped = Counter()
    for result_path in result_files:
        if not result_path.exists():
            skipped["missing_result_file"] += 1
            continue
        payload = json.loads(result_path.read_text(encoding="utf-8"))
        for result in payload.get("results", []):
            record = records.get(result["candidate_id"])
            if record is None:
                skipped["missing_candidate_source"] += 1
                continue
            for decision in result.get("e_decisions", []):
                side = decision.get("e_status")
                if side not in {"vulnerable", "patched"}:
                    continue
                boundary_id = decision["fix_boundary_id"]
                boundary_pairs = pairs_by_boundary.get(boundary_id)
                if not boundary_pairs:
                    skipped["missing_boundary"] += 1
                    continue
                function_pair = next(
                    (pair for pair in boundary_pairs if pair.vulnerable_region.granularity == "function"),
                    boundary_pairs[0],
                )
                cache_key = (boundary_id, side)
                if cache_key not in frequency_cache:
                    diagnostics = compute_diagnostic_lines(
                        function_pair.vulnerable_region.source,
                        function_pair.patched_region.source,
                        language=function_pair.source_language,
                    )
                    frequency_cache[cache_key] = _corpus_anchor_frequency(
                        corpus_snapshots,
                        _anchors(diagnostics, side),
                    )
                anchor_matches = _best_anchor_matches(
                    frequency_cache[cache_key],
                    record["candidate_source"],
                )
                localized = _localized_evidence(
                    record["candidate_source"],
                    function_pair.source_language,
                    boundary_pairs,
                    side,
                    args,
                )
                candidate_names = localized["candidate_function_names"]
                function_conflict = (
                    bool(function_pair.function_name)
                    and bool(candidate_names)
                    and function_pair.function_name not in candidate_names
                )
                best_anchor = anchor_matches[0] if anchor_matches else None
                insufficient_identity = (
                    best_anchor is not None
                    and not best_anchor["identity_tokens"]
                    and not localized["context_correspondence_passed"]
                    and function_conflict
                )
                rows.append({
                    "source_result": result_path.name,
                    "candidate_id": result["candidate_id"],
                    "expected_status": result["expected_status"],
                    "original_priority": result["priority"],
                    "original_outcome": result["outcome"],
                    "fix_boundary_id": boundary_id,
                    "ghsa_id": decision.get("ghsa_id"),
                    "reference_function_name": function_pair.function_name,
                    "decision_side": side,
                    "expected_boundary": boundary_id in {
                        pair_id.rsplit(":", 1)[0]
                        for pair_id in result.get("expected_pair_ids", [])
                    },
                    "explicit_function_conflict": function_conflict,
                    "observational_insufficient_identity": insufficient_identity,
                    "staged_scores": {
                        key: decision.get(key)
                        for key in (
                            "structural_vulnerable", "structural_patched",
                            "token_vulnerable", "token_patched",
                            "edit_vulnerable", "edit_patched", "edit_margin",
                        )
                    },
                    "anchors": anchor_matches,
                    "best_anchor": best_anchor,
                    "localized": localized,
                })

    groups = defaultdict(list)
    for row in rows:
        groups[row["original_outcome"]].append(row)
    summary = {}
    for outcome, values in sorted(groups.items()):
        frequencies = [
            row["best_anchor"]["snapshot_document_frequency"]
            for row in values if row["best_anchor"] is not None
        ]
        summary[outcome] = {
            "decisive_boundary_count": len(values),
            "same_region_gate_pass_count": sum(row["localized"]["same_region_gate_passed"] for row in values),
            "context_correspondence_count": sum(row["localized"]["context_correspondence_passed"] for row in values),
            "explicit_function_conflict_count": sum(
                row["explicit_function_conflict"]
                for row in values
            ),
            "insufficient_identity_count": sum(
                row["observational_insufficient_identity"] for row in values
            ),
            "insufficient_identity_expected_boundary_count": sum(
                row["observational_insufficient_identity"] and row["expected_boundary"]
                for row in values
            ),
            "best_anchor_document_frequency": {
                "minimum": min(frequencies) if frequencies else None,
                "median": sorted(frequencies)[len(frequencies) // 2] if frequencies else None,
                "maximum": max(frequencies) if frequencies else None,
            },
        }
    output = {
        "schema": "boundary_specificity_litmus_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "observational_only": True,
        "configuration": {
            "minimum_structure": args.minimum_structure,
            "minimum_token": args.minimum_token,
            "minimum_e_side": args.minimum_e_side,
            "minimum_e_margin": args.minimum_e_margin,
            "corpus_snapshot_count": len(corpus_snapshots),
        },
        "skipped": dict(skipped),
        "summary": summary,
        "results": rows,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
