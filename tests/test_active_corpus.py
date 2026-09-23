import hashlib
import json

from eval.active import (ROOT, SUMMARY, TIER1_CORPUS, TIER1_LABELS, TIER2_CASES,
                         TIER2_ELIGIBLE_PAIRS, TIER2_PRUNED)
from provtrail.corpus.integrations.sqlite_store import load_entries


def _rows(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_active_tiers_have_600_cases_and_retain_eligible_pairs():
    tier1 = _rows(TIER1_LABELS)
    tier2 = _rows(TIER2_CASES)
    pairs = _rows(TIER2_ELIGIBLE_PAIRS)
    pruned = _rows(TIER2_PRUNED)
    assert len(tier1) == len(tier2) == 600
    assert sum(row["expected_status"] == "flagged" for row in tier1) == 300
    assert len(load_entries(TIER1_CORPUS)) == 327
    assert len({row["candidate_id"] for row in tier2}) == 600
    assert len(pairs) == 247
    active_ids = {row["candidate_id"] for row in tier2}
    assert all(set(pair["candidate_ids"].values()) <= active_ids for pair in pairs)
    assert {row["candidate_id"] for row in pruned} == {"L101", "L110"}
    assert len({row["candidate_source_sha256"] for row in pruned}) == 1
    assert not {row["candidate_id"] for row in pruned} & active_ids


def test_active_tier1_new_labels_resolve_to_exact_reference_sources():
    entries = load_entries(TIER1_CORPUS)
    by_origin = {(entry.advisory.ghsa_id, entry.origin.fix_commit_sha,
                  entry.origin.file_path, entry.origin.function_name): entry for entry in entries}
    new_ids = {row["pair_id"] for row in _rows(ROOT.parent / "frozen/tier1-expansion-v1/pairs.jsonl")}
    assert len(new_ids) == 26
    replacement_ghsas = {row["advisory_id"] for row in _rows(ROOT.parent / "frozen/tier1-expansion-v1/pairs.jsonl")}
    new_labels = [row for row in _rows(TIER1_LABELS) if row["ghsa_id"] in replacement_ghsas]
    assert len(new_labels) == 52
    for row in new_labels:
        key = (row["ghsa_id"], row["corpus_entry"]["fix_commit_sha"],
               row["corpus_file_path"], row["corpus_entry"]["function_name"])
        entry = by_origin[key]
        source = entry.vulnerable_function if row["expected_status"] == "flagged" else entry.patched_function
        assert hashlib.sha256(source.encode()).hexdigest() == row["target_source_sha256"]
        assert row["source_commit"]


def test_active_summary_and_lock():
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    assert summary["tier1_valid_cases"] == summary["tier2_active_valid_cases"] == 600
    assert summary["tier2_eligible_pairs"] == 247
    assert summary["total_active_validated_cases"] == 1200
    lock = json.loads((ROOT / "lock.json").read_text(encoding="utf-8"))
    for name, digest in lock.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest
