"""Generate Klaban positive and negative fixtures for verification evaluation.

The benchmark contains transformed vulnerable functions as positives, their
corresponding patched functions as negatives, and patched functions from other
Klaban entries as benign/similar controls.

Run from the repository root:

    PYTHONPATH=. .venv/bin/python scripts/generate_klaban_verification_subset.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from corpus.controller.klaban import KLABAN_ID_PREFIX
from corpus.controller.store import DEFAULT_DB_PATH, load_entries
from corpus.models.corpus import CorpusEntry
from scripts.generate_candidate_subset import (
    digest,
    entry_key,
    insert_dead_branch,
    reformat_source,
    validate_candidate,
)


DEFAULT_POSITIVE_OUTPUT = Path("eval/klaban_verification_positive.jsonl")
DEFAULT_NEGATIVE_OUTPUT = Path("eval/klaban_verification_negative.jsonl")


def _identity(entry: CorpusEntry) -> tuple[str, str, str, str]:
    return (
        entry.advisory.ghsa_id,
        entry.origin.fix_commit_sha,
        entry.origin.file_path,
        entry.origin.function_name or "",
    )


def _transform(source: str) -> str:
    """Apply a generic semantics-preserving transformation to JavaScript."""
    transformed = insert_dead_branch(source)
    validate_candidate(transformed, source)
    return transformed


def _eligible(entry: CorpusEntry, max_source_bytes: int) -> bool:
    if not entry.advisory.ghsa_id.startswith(KLABAN_ID_PREFIX):
        return False
    if not entry.vulnerable_function.strip() or not entry.patched_function.strip():
        return False
    if entry.vulnerable_function == entry.patched_function:
        return False
    if max(
        len(entry.vulnerable_function.encode("utf-8")),
        len(entry.patched_function.encode("utf-8")),
    ) > max_source_bytes:
        return False
    try:
        _transform(entry.vulnerable_function)
        validate_candidate(entry.patched_function, entry.vulnerable_function)
    except ValueError:
        return False
    return True


def _select_diverse(entries: list[CorpusEntry], count: int) -> list[CorpusEntry]:
    """Prefer distinct Klaban advisories, then fill from remaining functions."""
    ordered = sorted(entries, key=_identity)
    selected: list[CorpusEntry] = []
    deferred: list[CorpusEntry] = []
    seen_advisories: set[str] = set()
    for entry in ordered:
        if entry.advisory.ghsa_id in seen_advisories:
            deferred.append(entry)
        else:
            selected.append(entry)
            seen_advisories.add(entry.advisory.ghsa_id)
    selected.extend(deferred)
    if len(selected) < count:
        raise RuntimeError(
            f"Requested {count} Klaban cases, but only {len(selected)} eligible paired functions exist"
        )
    return selected[:count]


def _base_record(entry: CorpusEntry, candidate_source: str) -> dict:
    return {
        "corpus_entry": entry_key(entry),
        "package_name": entry.advisory.package_name,
        "ecosystem": entry.advisory.ecosystem,
        "osv_id": entry.advisory.osv_id,
        "affected_versions": entry.advisory.affected_versions,
        "fixed_versions": entry.advisory.fixed_versions,
        "severity": entry.advisory.severity,
        "cwes": [c.model_dump() for c in entry.advisory.cwes],
        "osv_confirmed": entry.osv_confirmed,
        "vulnerable_source_sha256": digest(entry.vulnerable_function),
        "patched_source_sha256": digest(entry.patched_function),
        "candidate_source_sha256": hashlib.sha256(candidate_source.encode("utf-8")).hexdigest(),
        "vulnerable_function": entry.vulnerable_function,
        "patched_function": entry.patched_function,
        "diagnostic_lines": [line.model_dump() for line in entry.diagnostic_lines],
        "candidate_source": candidate_source,
    }


def _write_jsonl(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")


def generate_fixtures(
    entries: list[CorpusEntry],
    *,
    count: int = 30,
    max_source_bytes: int = 50_000,
) -> tuple[list[dict], list[dict]]:
    if count < 1:
        raise ValueError("count must be at least 1")

    eligible = [entry for entry in entries if _eligible(entry, max_source_bytes)]
    positives = _select_diverse(eligible, count)
    positive_keys = {_identity(entry) for entry in positives}

    positive_records: list[dict] = []
    negative_records: list[dict] = []
    for index, entry in enumerate(positives, start=1):
        candidate = _transform(entry.vulnerable_function)
        positive_records.append(
            {
                "candidate_id": f"K-C{index:02d}",
                "expected_status": "flagged",
                "generation_method": "dead_branch_insertion",
                "transformation_family": "dead_branch",
                **_base_record(entry, candidate),
            }
        )

        try:
            patched_candidate = _transform(entry.patched_function)
            patched_method = "same_transform_as_positive:dead_branch"
        except ValueError:
            patched_candidate = entry.patched_function
            patched_method = "exact_patched_corpus_snapshot"
        negative_records.append(
            {
                "candidate_id": f"K-NP{index:02d}",
                "expected_status": "cleared",
                "negative_category": "patched",
                "generation_method": patched_method,
                "control_source_type": "fixed_snapshot_for_positive_entry",
                "matched_positive_candidate_id": f"K-C{index:02d}",
                **_base_record(entry, patched_candidate),
            }
        )

    controls = [entry for entry in eligible if _identity(entry) not in positive_keys]
    if len(controls) < count:
        raise RuntimeError(
            f"Need {count} distinct Klaban controls, but only {len(controls)} are available"
        )

    used_controls: set[tuple[str, str, str, str]] = set()
    for index, target in enumerate(positives, start=1):
        target_size = len(target.vulnerable_function.encode("utf-8"))
        control = min(
            (entry for entry in controls if _identity(entry) not in used_controls),
            key=lambda entry: (
                abs(len(entry.patched_function.encode("utf-8")) - target_size),
                _identity(entry),
            ),
        )
        used_controls.add(_identity(control))
        candidate = reformat_source(control.patched_function)
        method = "similar_fixed_control:reformat"
        if candidate == control.patched_function:
            candidate = control.patched_function
            method = "exact_patched_corpus_snapshot"
        else:
            try:
                validate_candidate(candidate, control.patched_function)
            except ValueError:
                candidate = control.patched_function
                method = "exact_patched_corpus_snapshot"
        negative_records.append(
            {
                "candidate_id": f"K-NB{index:02d}",
                "expected_status": "cleared",
                "negative_category": "benign_similar",
                "generation_method": method,
                "control_source_type": "different_klaban_fixed_snapshot_size_matched",
                "matched_positive_candidate_id": f"K-C{index:02d}",
                **_base_record(control, candidate),
            }
        )

    return positive_records, negative_records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", type=Path, default=DEFAULT_DB_PATH)
    parser.add_argument("--positive-output", type=Path, default=DEFAULT_POSITIVE_OUTPUT)
    parser.add_argument("--negative-output", type=Path, default=DEFAULT_NEGATIVE_OUTPUT)
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--max-source-bytes", type=int, default=50_000)
    args = parser.parse_args()

    entries = load_entries(args.db_path)
    positives, negatives = generate_fixtures(
        entries,
        count=args.count,
        max_source_bytes=args.max_source_bytes,
    )
    _write_jsonl(args.positive_output, positives)
    _write_jsonl(args.negative_output, negatives)

    print(f"Wrote {len(positives)} Klaban positives to {args.positive_output}")
    print(f"Wrote {len(negatives)} Klaban negatives to {args.negative_output}")
    print(f"  patched: {sum(row['negative_category'] == 'patched' for row in negatives)}")
    print(
        "  benign_similar: "
        f"{sum(row['negative_category'] == 'benign_similar' for row in negatives)}"
    )


if __name__ == "__main__":
    main()
