"""Freeze 26 line-reviewed, npm-release-confirmed Tier 1 replacement pairs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from provtrail.corpus.controller.extraction import compute_diagnostic_lines
from provtrail.corpus.integrations.sqlite_store import load_entries


ROOT = Path("eval/frozen")
CANDIDATES = ROOT / "tier1-replacement-candidates-v1/pairs.jsonl"
RELEASE_CHECKS = ROOT / "tier1-replacement-candidates-v1/release-checks.jsonl"
ORIGINAL = ROOT / "tier1-advisory-audit-v1/cases.jsonl"
OUTPUT = ROOT / "tier1-expansion-v1"

# These changes directly affect the advisory-described boundary in the named
# function. The audit excludes incidental wrappers, duplicate backports,
# mismatched function pairing, non-shipped source and formatting-only edits.
REVIEWS = {
    0: "Replaces the whitespace-trimming regex responsible for the advisory's complexity issue.",
    27: "Handles malformed host parsing in the request host-validation function.",
    38: "Removes untrusted redirect URL insertion into the generated HTML response.",
    40: "Preserves the URL authority before encoding the redirect location.",
    42: "Adds path checks to the unset operation described by the advisory.",
    43: "Routes numeric string trimming away from the vulnerable regex.",
    45: "Replaces trailing-whitespace regex trimming with index-based trimming.",
    78: "Normalizes parent-directory reservations used by the symlink-protection logic.",
    87: "Strips Windows absolute path roots before archive extraction.",
    88: "Checks extracted paths for Windows traversal forms.",
    93: "Uses the absolute-path stripping helper on archive entry paths.",
    99: "Counts URL-encoded parameters without splitting the whole request body.",
    101: "Changes URL-encoded parsing from unlimited depth to the configured depth.",
    102: "Enforces the array limit on the bracket-key parsing path.",
    104: "Checks the type of attacker-controlled isBuffer before calling it.",
    106: "Preserves overflow handling while building parsed arrays.",
    107: "Applies overflow handling in the merge path.",
    108: "Implements bounded array combination for the array-limit advisory.",
    111: "Updates the route-token regex construction path affected by backtracking.",
    117: "Restricts generated route patterns to avoid backtracking in the 1.x branch.",
    120: "Restricts generated route patterns to avoid backtracking in the 3.x branch.",
    130: "Replaces the inefficient localhost-host regex with direct string checks.",
    134: "Avoids the array-like object operation responsible for CPU exhaustion.",
    135: "Validates the serialized Date string before embedding it in generated code.",
    136: "Serializes URL text before embedding it in generated JavaScript.",
    138: "Guards placeholder substitution in generated JavaScript.",
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")


def main() -> None:
    candidates = [json.loads(line) for line in CANDIDATES.open(encoding="utf-8")]
    release_checks = {
        row["candidate_index"]: row
        for row in (json.loads(line) for line in RELEASE_CHECKS.open(encoding="utf-8"))
    }
    previous = [json.loads(line) for line in ORIGINAL.open(encoding="utf-8")]
    original_valid = [row for row in previous if row["verdict"].startswith("valid_")]
    assert len(original_valid) == 548
    existing_origins = {tuple(row["origin"]) for row in previous}
    existing_source_pairs = {
        (_sha(entry.vulnerable_function), _sha(entry.patched_function))
        for entry in load_entries("corpus/data/corpus.db")
    }
    pairs: list[dict] = []
    cases: list[dict] = []
    seen_origins: set[tuple] = set()
    seen_source_pairs: set[tuple[str, str]] = set()

    for index, reason in REVIEWS.items():
        candidate = candidates[index]
        assert candidate["source_language"] == "javascript"
        assert any(
            ref.rstrip("/").endswith("/commit/" + candidate["fix_commit_sha"])
            for ref in candidate["advisory_references"]
        )
        origin = (
            candidate["advisory_id"], candidate["fix_commit_sha"],
            candidate["file_path"], candidate["function_name"],
        )
        assert origin not in existing_origins and origin not in seen_origins
        seen_origins.add(origin)
        vulnerable_sha = _sha(candidate["vulnerable_function"])
        patched_sha = _sha(candidate["patched_function"])
        assert vulnerable_sha != patched_sha
        source_pair = vulnerable_sha, patched_sha
        assert source_pair not in seen_source_pairs and source_pair not in existing_source_pairs
        seen_source_pairs.add(source_pair)
        changed = compute_diagnostic_lines(
            candidate["vulnerable_function"], candidate["patched_function"],
            language="javascript",
        )
        assert any(line.kind == "removed" for line in changed)
        assert any(line.kind == "added" for line in changed)
        eligible = [
            row for row in release_checks[index]["release_checks"]
            if row.get("vulnerable_function_exact") and row.get("patched_function_exact")
        ]
        assert eligible, index
        selected = eligible[0]
        pair_id = "T1R-" + _sha("|".join(str(item) for item in origin))[:20]
        pairs.append({
            "pair_id": pair_id,
            "candidate_index": index,
            "advisory_id": candidate["advisory_id"],
            "advisory_url": candidate["advisory_url"],
            "advisory_title": candidate["advisory_title"],
            "package": candidate["package"],
            "repo": candidate["repo"],
            "fix_commit_sha": candidate["fix_commit_sha"],
            "fix_commit_url": "https://github.com/" + candidate["repo"] + "/commit/" + candidate["fix_commit_sha"],
            "file_path": candidate["file_path"],
            "function_name": candidate["function_name"],
            "origin": list(origin),
            "line_review": reason,
            "vulnerable_version": selected["vulnerable_version"],
            "fixed_version": selected["fixed_version"],
            "vulnerable_tarball_sha256": selected["vulnerable_tarball_sha256"],
            "fixed_tarball_sha256": selected["fixed_tarball_sha256"],
            "vulnerable_release_file_sha256": selected["vulnerable_source_sha256"],
            "fixed_release_file_sha256": selected["fixed_source_sha256"],
            "vulnerable_function_sha256": vulnerable_sha,
            "patched_function_sha256": patched_sha,
            "vulnerable_function": candidate["vulnerable_function"],
            "patched_function": candidate["patched_function"],
            "changed_lines": [line.model_dump() for line in changed],
            "validation_scope": "advisory/commit/function/release-source identity; no exploitability claim",
        })
        for side, version, source_sha, tarball_sha in (
            ("vulnerable", selected["vulnerable_version"], vulnerable_sha, selected["vulnerable_tarball_sha256"]),
            ("patched", selected["fixed_version"], patched_sha, selected["fixed_tarball_sha256"]),
        ):
            cases.append({
                "candidate_id": pair_id + ("-V" if side == "vulnerable" else "-F"),
                "pair_id": pair_id,
                "verdict": "valid_advisory_reference",
                "advisory_id": candidate["advisory_id"],
                "advisory_url": candidate["advisory_url"],
                "package": candidate["package"],
                "version": version,
                "reference_side": side,
                "origin": list(origin),
                "fix_commit": candidate["fix_commit_sha"],
                "fix_commit_reference": "https://github.com/" + candidate["repo"] + "/commit/" + candidate["fix_commit_sha"],
                "release_tarball_sha256": tarball_sha,
                "target_source_sha256": source_sha,
                "current_reference_sha256": source_sha,
                "checks": {
                    "advisory_id": True,
                    "package": True,
                    "file_path": True,
                    "fix_commit_cited": True,
                    "nonempty_reference_change": True,
                    "version_side": True,
                    "source_exact_in_release_tarball": True,
                },
                "line_review": reason,
                "limitation": "Advisory/source identity only; no exploitability claim.",
            })

    assert len(pairs) == 26 and len(cases) == 52
    combined = sorted(original_valid + cases, key=lambda row: row["candidate_id"])
    assert len(combined) == 600
    assert len({row["candidate_id"] for row in combined}) == 600
    OUTPUT.mkdir(parents=True, exist_ok=True)
    _write_jsonl(OUTPUT / "pairs.jsonl", pairs)
    _write_jsonl(OUTPUT / "cases.jsonl", cases)
    _write_jsonl(OUTPUT / "combined-valid-cases.jsonl", combined)
    summary = {
        "original_valid_cases": 548,
        "replacement_pairs": len(pairs),
        "replacement_cases": len(cases),
        "combined_valid_cases": len(combined),
        "excluded_original_cases_retained": 52,
        "distinct_replacement_advisories": len({row["advisory_id"] for row in pairs}),
        "distinct_replacement_source_pairs": len(seen_source_pairs),
        "release_source_exact_pairs": len(pairs),
        "scope": "advisory-cited fix, direct function change, exact source in vulnerable and first-fixed npm tarballs",
    }
    (OUTPUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lock = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (OUTPUT / "pairs.jsonl", OUTPUT / "cases.jsonl", OUTPUT / "combined-valid-cases.jsonl", OUTPUT / "summary.json")
    }
    (OUTPUT / "lock.json").write_text(json.dumps(lock, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
