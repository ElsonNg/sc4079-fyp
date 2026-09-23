"""Materialize the current Tier 1 and Tier 2 validated evaluation inputs."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path

from eval.active import ROOT, TIER1_CORPUS, TIER1_LABELS, TIER2_CASES, TIER2_ELIGIBLE_PAIRS
from eval.common import DEFAULT_SNAPSHOT_DB, category_for
from provtrail.corpus.controller.deduplication import fingerprint_entry
from provtrail.corpus.integrations.sqlite_store import load_entries, save_entries
from provtrail.corpus.models.corpus import CorpusEntry


EVAL = ROOT.parent
ORIGINAL_LABELS = EVAL / "tier1_curated_labels.jsonl"
TIER1_AUDIT = EVAL / "frozen/tier1-advisory-audit-v1/cases.jsonl"
TIER1_EXPANSION = EVAL / "frozen/tier1-expansion-v1"
TIER2_EXPANSION = EVAL / "frozen/tier2-alpha-expansion-v1"
TIER1_CANDIDATES = EVAL / "frozen/tier1-replacement-candidates-v1/pairs.jsonl"
TIER2_PRUNE_IDS = {"L101", "L110"}


def _read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def _original_label_key(row: dict) -> tuple:
    entry = row["corpus_entry"]
    return (row["ghsa_id"], entry["fix_commit_sha"], entry["file_path"],
            entry["function_name"], row["version"],
            "vulnerable" if row["kind"] == "vulnerable" else "patched",
            row["target_source_sha256"])


def _original_case_key(row: dict) -> tuple:
    return (*row["origin"], row["version"], row["reference_side"],
            row["target_source_sha256"])


def _new_entry(pair: dict, candidate: dict, release: dict[str, dict]) -> CorpusEntry:
    vulnerable = release["vulnerable"]
    fixed = release["patched"]
    entry = CorpusEntry(
        ghsa_id=pair["advisory_id"],
        advisory_title=pair["advisory_title"],
        advisory_description=candidate["advisory_description"],
        advisory_url=pair["advisory_url"],
        advisory_references=candidate["advisory_references"],
        package_name=pair["package"],
        ecosystem="npm",
        affected_versions=[pair["vulnerable_version"]],
        fixed_versions=[v["first_patched_version"] for v in candidate["vulnerabilities"] if v.get("first_patched_version")],
        repo=pair["repo"],
        fix_commit_sha=pair["fix_commit_sha"],
        file_path=pair["file_path"],
        function_name=pair["function_name"],
        source_language="javascript",
        vulnerable_function=pair["vulnerable_function"],
        patched_function=pair["patched_function"],
        diagnostic_lines=pair["changed_lines"],
        patch_hunk=candidate["patch_hunk"],
        release_boundary={
            "last_affected": pair["vulnerable_version"],
            "first_fixed": pair["fixed_version"],
            "vulnerable_tarball": vulnerable["tarball_url"],
            "vulnerable_artifact_sha256": pair["vulnerable_tarball_sha256"],
            "fixed_tarball": fixed["tarball_url"],
            "fixed_artifact_sha256": pair["fixed_tarball_sha256"],
            "last_affected_commit": vulnerable["source_commit"],
            "first_fixed_commit": fixed["source_commit"],
        },
        osv_confirmed=False,
        evidence_label="advisory-cited fix and exact vulnerable/fixed npm release source",
    )
    return fingerprint_entry(entry)


def build() -> dict:
    audit = _read(TIER1_AUDIT)
    valid_old = {_original_case_key(row) for row in audit if row["verdict"].startswith("valid_")}
    old_labels = [row for row in _read(ORIGINAL_LABELS) if _original_label_key(row) in valid_old]
    assert len(old_labels) == len(valid_old) == 548

    pairs = _read(TIER1_EXPANSION / "pairs.jsonl")
    candidates = _read(TIER1_CANDIDATES)
    release_rows = _read(TIER1_EXPANSION / "release-commits.jsonl")
    release_by_pair: dict[str, dict[str, dict]] = {}
    for row in release_rows:
        assert row["source_exact_at_commit"] and row["source_commit"]
        release_by_pair.setdefault(row["pair_id"], {})[row["side"]] = row
    assert len(pairs) == 26 and len(release_rows) == 52

    new_entries = []
    new_labels = []
    for pair in pairs:
        release = release_by_pair[pair["pair_id"]]
        assert set(release) == {"vulnerable", "patched"}
        candidate = candidates[pair["candidate_index"]]
        new_entries.append(_new_entry(pair, candidate, release))
        corpus_key = {
            "ghsa_id": pair["advisory_id"], "fix_commit_sha": pair["fix_commit_sha"],
            "file_path": pair["file_path"], "function_name": pair["function_name"],
        }
        for side, kind, status, source_hash, tarball_hash in (
            ("vulnerable", "vulnerable", "flagged", pair["vulnerable_function_sha256"], pair["vulnerable_tarball_sha256"]),
            ("patched", "fixed", "cleared", pair["patched_function_sha256"], pair["fixed_tarball_sha256"]),
        ):
            release_row = release[side]
            new_labels.append({
                "ghsa_id": pair["advisory_id"],
                "package_name": pair["package"],
                "category": category_for(pair["package"]),
                "source_language": "javascript",
                "kind": kind,
                "version": release_row["version"],
                "tarball_url": release_row["tarball_url"],
                "expected_sha256": tarball_hash,
                "expected_status": status,
                "source_repo": pair["repo"],
                "source_commit": release_row["source_commit"],
                "tier1_applicable": True,
                "corpus_file_path": pair["file_path"],
                "corpus_entry": corpus_key,
                "target_source_sha256": source_hash,
            })
    assert len(new_labels) == 52
    labels = old_labels + new_labels
    assert len(labels) == 600
    assert Counter(row["expected_status"] for row in labels) == {"flagged": 300, "cleared": 300}
    assert len({_original_label_key(row) for row in labels}) == 600

    base_entries = load_entries(DEFAULT_SNAPSHOT_DB)
    assert len(base_entries) == 301
    corpus_entries = base_entries + new_entries
    assert len(corpus_entries) == 327
    db_tmp = ROOT / "corpus.building.db"
    if db_tmp.exists():
        db_tmp.unlink()
    save_entries(corpus_entries, db_tmp)
    assert len(load_entries(db_tmp)) == 327
    db_tmp.replace(TIER1_CORPUS)
    _write(TIER1_LABELS, labels)

    tier2_source_cases = _read(TIER2_EXPANSION / "combined_admitted.jsonl")
    tier2_pairs = _read(TIER2_EXPANSION / "combined_eligible_pairs.jsonl")
    assert len(tier2_source_cases) == len({row["candidate_id"] for row in tier2_source_cases}) == 602
    assert len(tier2_pairs) == 247
    eligible_ids = {case_id for row in tier2_pairs for case_id in row["candidate_ids"].values()}
    pruned = [row for row in tier2_source_cases if row["candidate_id"] in TIER2_PRUNE_IDS]
    assert len(pruned) == 2 and all(row["candidate_id"] not in eligible_ids for row in pruned)
    assert len({row["candidate_source_sha256"] for row in pruned}) == 1
    tier2_cases = [row for row in tier2_source_cases if row["candidate_id"] not in TIER2_PRUNE_IDS]
    assert len(tier2_cases) == 600
    case_ids = {row["candidate_id"] for row in tier2_cases}
    assert all(set(row["candidate_ids"].values()) <= case_ids for row in tier2_pairs)
    _write(TIER2_CASES, tier2_cases)
    _write(TIER2_ELIGIBLE_PAIRS, tier2_pairs)
    _write(ROOT / "tier2_pruned.jsonl", [{
        "candidate_id": row["candidate_id"],
        "expected_status": row["expected_status"],
        "candidate_source_sha256": row["candidate_source_sha256"],
        "origin": row["corpus_entry"],
        "reason": "Pair-ineligible flagged duplicate source; omitted to make the active Tier 2 cohort exactly 600.",
    } for row in pruned])

    summary = {
        "tier1_valid_cases": 600,
        "tier1_vulnerable_cases": 300,
        "tier1_fixed_cases": 300,
        "tier1_reference_entries": 327,
        "tier1_new_reference_entries": 26,
        "tier2_source_verified_cases": 602,
        "tier2_active_valid_cases": 600,
        "tier2_pruned_cases": 2,
        "tier2_eligible_pairs": 247,
        "tier2_eligible_cases": 494,
        "tier2_active_not_pair_eligible": 106,
        "total_active_validated_cases": 1200,
    }
    (ROOT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lock = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (TIER1_LABELS, TIER1_CORPUS, TIER2_CASES, TIER2_ELIGIBLE_PAIRS,
                         ROOT / "tier2_pruned.jsonl", ROOT / "summary.json")}
    (ROOT / "lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    return summary


if __name__ == "__main__":
    print(json.dumps(build(), indent=2))
