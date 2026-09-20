"""Generate 30 patched and 30 benign/similar negative controls.

The negative fixture is deliberately separate from the positive-only
"candidate_subset_30.jsonl" benchmark. Both negative categories use fixed
corpus snapshots as auditable safe controls:

* patched: the fixed snapshot corresponding to each positive candidate, with
  the same deterministic source transformation when it can be applied;
* benign_similar: fixed snapshots from different corpus entries selected by
  AST/size similarity to the positive functions, with light transformations.

These are fixed-corpus controls, not a runtime proof that every function is
safe in every context. Run from the repository root:

    PYTHONPATH=. .venv/bin/python scripts/generate_negative_subset.py
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from corpus.controller.store import load_entries
from corpus.models.corpus import CorpusEntry
from pipeline.controller.parsing import parse_source
from eval.fixtures.generate_candidate_subset import (
    BASE_FAMILIES,
    BASE_ROW_IDS,
    EXTRA_VARIANTS,
    apply_transformation,
    digest,
    entry_key,
    insert_dead_branch,
    reformat_source,
    validate_candidate,
)

OUTPUT_PATH = Path(__file__).resolve().parents[2] / "eval" / "negative_subset_60.jsonl"


def _positive_specs() -> list[tuple[int, str]]:
    return [(row_id, BASE_FAMILIES[row_id]) for row_id in BASE_ROW_IDS] + list(EXTRA_VARIANTS)


def _source_stats(source: str) -> tuple[int, int, int]:
    """Return named-node count, byte length, and line count."""
    tree = parse_source(source)
    if tree.root_node.has_error:
        wrapped = "class __NegativeControlWrapper {\n" + source + "\n}\n"
        tree = parse_source(wrapped)
    nodes = 0

    def walk(node) -> None:
        nonlocal nodes
        if node.is_named:
            nodes += 1
        for child in node.named_children:
            walk(child)

    walk(tree.root_node)
    return nodes, len(source.encode("utf-8")), len(source.splitlines())


def _record(
    candidate_id: str,
    entry: CorpusEntry,
    candidate_source: str,
    category: str,
    generation_method: str,
    control_source_type: str,
    matched_positive_id: str | None = None,
) -> dict:
    return {
        "candidate_id": candidate_id,
        "expected_status": "cleared",
        "negative_category": category,
        "generation_method": generation_method,
        "control_source_type": control_source_type,
        "matched_positive_candidate_id": matched_positive_id,
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


def _transformed_fixed_source(entry: CorpusEntry, row_id: int, family: str) -> tuple[str, str]:
    try:
        source = apply_transformation(entry.patched_function, row_id, family)
        validate_candidate(source, entry.patched_function)
        return source, f"same_transform_as_positive:{family}"
    except ValueError:
        # A patch can legitimately remove the exact syntax targeted by a
        # positive fixture transformation. Keep the fixed snapshot as a valid
        # negative instead of inventing a source rewrite.
        return entry.patched_function, "exact_patched_corpus_snapshot"


def _similarity_distance(left: tuple[int, int, int], right: tuple[int, int, int]) -> int:
    left_nodes, left_bytes, left_lines = left
    right_nodes, right_bytes, right_lines = right
    return (
        abs(left_nodes - right_nodes) * 100
        + abs(left_bytes - right_bytes) // 20
        + abs(left_lines - right_lines) * 10
    )


def main() -> None:
    entries = load_entries()
    by_row_id = {index + 1: entry for index, entry in enumerate(entries)}
    specs = _positive_specs()
    if len(specs) != 30:
        raise AssertionError(f"Expected 30 positive specifications, found {len(specs)}")

    records: list[dict] = []
    positive_keys = {
        (
            entry.advisory.ghsa_id,
            entry.origin.fix_commit_sha,
            entry.origin.file_path,
            entry.origin.function_name,
        )
        for entry in (by_row_id[row_id] for row_id, _ in specs)
    }

    # Category 1: fixed versions corresponding to every positive candidate.
    for index, (row_id, family) in enumerate(specs, start=1):
        entry = by_row_id[row_id]
        candidate, method = _transformed_fixed_source(entry, row_id, family)
        records.append(
            _record(
                f"N-P{index:02d}",
                entry,
                candidate,
                "patched",
                method,
                "fixed_snapshot_for_positive_entry",
                matched_positive_id=f"C{index:02d}",
            )
        )

    # Category 2: different fixed corpus functions selected by deterministic
    # AST/size similarity to the positive vulnerable functions.
    controls = [
        (row_id, entry)
        for row_id, entry in sorted(by_row_id.items())
        if (
            entry.advisory.ghsa_id,
            entry.origin.fix_commit_sha,
            entry.origin.file_path,
            entry.origin.function_name,
        )
        not in positive_keys
    ]
    available = {row_id: entry for row_id, entry in controls}
    used_control_ids: set[int] = set()

    for index, (positive_row_id, _) in enumerate(specs, start=1):
        target = by_row_id[positive_row_id]
        target_stats = _source_stats(target.vulnerable_function)
        ranked = sorted(
            (
                _similarity_distance(target_stats, _source_stats(entry.patched_function)),
                row_id,
                entry,
            )
            for row_id, entry in available.items()
            if row_id not in used_control_ids
        )
        if not ranked:
            raise AssertionError("Ran out of distinct corpus controls")
        distance, control_row_id, control = ranked[0]
        used_control_ids.add(control_row_id)

        candidate = reformat_source(control.patched_function)
        method = "similar_fixed_control:reformat"
        if index % 2 == 0:
            try:
                candidate = insert_dead_branch(candidate)
                method = "similar_fixed_control:dead_branch+reformat"
            except ValueError:
                method = "similar_fixed_control:reformat"
        if candidate != control.patched_function:
            try:
                validate_candidate(candidate, control.patched_function)
            except ValueError:
                candidate = control.patched_function
                method = "exact_patched_corpus_snapshot"
        else:
            method = "exact_patched_corpus_snapshot"
        records.append(
            _record(
                f"N-B{index:02d}",
                control,
                candidate,
                "benign_similar",
                method,
                f"fixed_corpus_control_ast_distance:{distance}",
                matched_positive_id=f"C{index:02d}",
            )
        )

    if len(records) != 60:
        raise AssertionError(f"Expected 60 negatives, generated {len(records)}")
    if len({record["candidate_id"] for record in records}) != 60:
        raise AssertionError("Negative candidate IDs are not unique")

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT_PATH.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")

    print(f"Wrote {len(records)} negative controls to {OUTPUT_PATH}")
    print("  patched: 30")
    print("  benign_similar: 30")
    print(f"  distinct benign/similar source entries: {len(used_control_ids)}")


if __name__ == "__main__":
    main()
