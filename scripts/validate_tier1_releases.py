"""Tier-1 self-check: scan exact same-language source at release commits.

For every label row, the source file is fetched from the package repository at the
recorded vulnerable or fixed release commit and scanned against the corpus. Only
the labeled source file/function contributes to the expected GHSA outcome. No
package code is executed.

Run from the repo root:
    $env:PYTHONPATH="."; .venv\\Scripts\\python.exe scripts\\validate_tier1_releases.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
import requests
from dotenv import load_dotenv

from corpus.controller.github import fetch_source_tree
from corpus.controller.store import load_entries
from eval.common import DEFAULT_SNAPSHOT_DB, extract_ghsa_ids
from eval.metrics import classification_outcome, detection_rank, expected_retrieval_fields, summarize_evaluation
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector
from pipeline.controller.parsing import SUPPORTED_SOURCE_EXTENSIONS, extract_function_units
from pipeline.controller.scanning import ScanConfig, corpus_fingerprint, scan_directory

DEFAULT_LABELS = Path(__file__).resolve().parent.parent / "eval" / "tier1_release_labels.jsonl"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "tier1_release_results.json"
SANDBOX_ROOT = Path(__file__).resolve().parent.parent / "eval" / "tier1_source_sandbox"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _safe_name(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-._@" else "_" for c in text)


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _count_functions(path: Path) -> int:
    try:
        return len(extract_function_units(path.read_text(encoding="utf-8"), filename=str(path)))
    except (OSError, RuntimeError, ValueError):
        return 0


def _apply_function_cap_legacy(dest: Path, target_paths: set[str], max_functions: int) -> tuple[int, int]:
    """Deprecated compatibility helper; Tier 1 now scans the eligible source tree."""
    # The implementation is retained for callers importing the old helper.
    """Delete source files so at most ~max_functions functions remain, but ALWAYS keep
    files matching a target advisory's corpus file_path (so recall is never lost to the
    cap). Returns (kept_functions, removed_files). Purely deletes files — runs nothing.
    """
    files = [
        p for p in dest.rglob("*")
        if p.is_file() and p.suffix.lower() in SUPPORTED_SOURCE_EXTENSIONS
    ]
    normalized_targets = {t.replace("\\", "/") for t in target_paths}

    def is_target(path: Path) -> bool:
        s = str(path).replace("\\", "/")
        return any(s.endswith(t) for t in normalized_targets)

    counts = {p: _count_functions(p) for p in files}
    targets = [p for p in files if is_target(p)]
    others = sorted((p for p in files if p not in targets), key=lambda p: counts[p])

    kept = set(targets)
    total = sum(counts[p] for p in targets)
    for path in others:  # smallest files first, until the budget is used up
        if counts[path] == 0:
            continue  # a file with no functions yields nothing to scan -- drop it
        if total >= max_functions:
            break
        kept.add(path)
        total += counts[path]

    removed = 0
    for path in files:
        if path not in kept:
            path.unlink(missing_ok=True)
            removed += 1
    return total, removed


def _make_scan_progress(label: str):
    """Per-file / heartbeat progress so a long single-package scan is never silent."""
    counter = {"functions": 0}

    def callback(event: dict) -> None:
        phase = event["phase"]
        if phase == "snapshot_complete":
            _log(f"      [{label}] {event['total_files']} source file(s) to scan")
        elif phase == "file_start":
            _log(
                f"      [{label}] file {event['completed_files'] + 1}/{event['total_files']}: "
                f"{event['path']} ({event['function_count']} fn)"
            )
        elif phase == "function_start":
            # Print a marker before a heavy function so a hang is attributable to it.
            if event["function_count"] >= 40 and event["function_index"] % 25 == 1:
                _log(
                    f"      [{label}]   ...fn {event['function_index']}/{event['function_count']} "
                    f"({event['name'] or '<anon>'})"
                )
        elif phase == "function_complete":
            counter["functions"] += 1
            if counter["functions"] % 100 == 0:
                _log(f"      [{label}]   {counter['functions']} functions scanned so far")

    return callback


def _finding_matches_target(
    finding: dict,
    source_path: str,
    function_name: str | None,
    target_source_sha256: str | None = None,
) -> bool:
    if finding.get("path", "").replace("\\", "/") != source_path.replace("\\", "/"):
        return False
    if function_name is not None:
        return finding.get("name") == function_name
    if target_source_sha256:
        return finding.get("function_hash") == target_source_sha256
    return True


def _package_path(source_path: str) -> str:
    parts = source_path.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] in {"packages", "package", "plugins", "apps"}:
        return "/".join(parts[:2])
    return ""


def _scan_source_package(source_repo, source_commit, source_path, function_name,
                         target_source_sha256, dest, detector, entries, corpus_version,
                         label=""):
    """Fetch and scan the eligible same-language source package at one commit."""
    started = time.time()
    if "/" not in source_repo:
        raise ValueError(f"invalid GitHub repository: {source_repo}")
    owner, repo = source_repo.split("/", 1)
    _log(f"    [{label}] fetching source tree {source_repo}@{source_commit} "
         f"(target {source_path})")
    if dest.exists():
        shutil.rmtree(dest)
    sources = fetch_source_tree(owner, repo, source_commit, package_path=_package_path(source_path))
    if source_path not in sources:
        raise FileNotFoundError(f"source path not found at commit: {source_path}")
    target_units = extract_function_units(sources[source_path], filename=source_path)
    hash_present = any(
        target_source_sha256 and hashlib.sha256(unit.source.encode("utf-8")).hexdigest() == target_source_sha256
        for unit in target_units
    )
    target_locator_hash = target_source_sha256 if hash_present else None
    function_present = any(
        (function_name is not None and unit.name == function_name)
        or (target_locator_hash and hashlib.sha256(unit.source.encode("utf-8")).hexdigest() == target_locator_hash)
        for unit in target_units
    ) if function_name is not None or target_locator_hash else True
    for relative_path, source in sources.items():
        target = dest / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(source, encoding="utf-8")
    summary = scan_directory(
        dest,
        detector=detector,
        entries=entries,
        config=ScanConfig(corpus_version=corpus_version, state_path=dest.parent / f"{dest.name}-state.json"),
        progress_callback=_make_scan_progress(label),
    )
    _log(f"    [{label}] scan finished in {time.time() - started:.0f}s")
    flagged, review, noise = set(), set(), []
    target_findings = []
    for finding in summary.findings:
        result = finding["result"]
        ghsas = extract_ghsa_ids(result)
        is_target = _finding_matches_target(
            finding, source_path, function_name, target_locator_hash
        )
        if is_target:
            target_findings.append(finding)
            if result.get("priority") == "automatic_vulnerability":
                flagged |= ghsas
            elif result.get("priority") == "manual_review":
                review |= ghsas
        elif ghsas:
            noise.append({
                "path": finding.get("path"), "name": finding.get("name"),
                "function_hash": finding.get("function_hash"),
                "priority": result.get("priority"), "ghsa_ids": sorted(ghsas),
            })
    return flagged, review, summary.total_functions, function_present, noise, target_findings


def _result_identity(row: dict) -> dict:
    return {
        k: row[k]
        for k in ("ghsa_id", "package_name", "kind", "version",
                  "source_language", "category", "expected_status")
        if k in row
    }


def _source_fields(row: dict, entries: list) -> tuple[str | None, str | None, str, str | None, str | None]:
    """Return repo, commit, path, target function, and target source hash."""
    if row.get("source_repo") and row.get("source_commit"):
        return (
            row["source_repo"], row["source_commit"], row["corpus_file_path"],
            row.get("corpus_entry", {}).get("function_name"), row.get("target_source_sha256")
        )
    identity = row.get("corpus_entry", {})
    entry = next(
        (
            item for item in entries
            if item.ghsa_id == row.get("ghsa_id")
            and item.file_path == row.get("corpus_file_path")
            and item.function_name == identity.get("function_name")
        ),
        None,
    )
    if entry is None:
        return None, None, row.get("corpus_file_path", ""), identity.get("function_name"), row.get("target_source_sha256")
    rb = entry.release_boundary or {}
    commit_key = "last_affected_commit" if row.get("kind") == "vulnerable" else "first_fixed_commit"
    source = entry.vulnerable_function if row.get("kind") == "vulnerable" else entry.patched_function
    return entry.repo, rb.get(commit_key), entry.file_path, entry.function_name, hashlib.sha256(source.encode("utf-8")).hexdigest()


def main() -> int:
    # Load the repository .env before any GitHub request so GITHUB_TOKEN is used
    # for authenticated API calls and the higher GitHub rate limit.
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--max-functions", type=int, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()

    rows = _load(args.labels)
    if args.limit:
        rows = rows[: args.limit]
    entries = load_entries(args.snapshot)
    corpus_version = corpus_fingerprint(entries)
    print(f"Corpus: {len(entries)} entries; label rows: {len(rows)}")
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

    grouped: dict[tuple, list[dict]] = defaultdict(list)
    resolved_fields: dict[int, tuple[str | None, str | None, str, str | None, str | None]] = {}
    for index, row in enumerate(rows):
        fields = _source_fields(row, entries)
        resolved_fields[index] = fields
        grouped[fields].append(row)

    scan_cache: dict[tuple, tuple[set, set, int, bool, list, list]] = {}
    fetch_failures: dict[tuple, str] = {}
    total_sources = len(grouped)
    for index, (key, source_rows) in enumerate(grouped.items(), start=1):
        source_repo, source_commit, source_path, function_name, target_source_sha256 = key
        sample = source_rows[0]
        label = f"{index}/{total_sources} {sample['package_name']}@{sample['version']} {sample['kind']}"
        dest = SANDBOX_ROOT / _safe_name(
            f"{sample['package_name']}@{sample['version']}-{sample['kind']}-{source_path}"
        )
        try:
            if not source_repo or not source_commit:
                raise ValueError("source release commit is unavailable")
            scan_cache[key] = _scan_source_package(
                source_repo, source_commit, source_path, function_name, target_source_sha256,
                dest, detector, entries, corpus_version, label=label,
            )
            print(
                f"scanned [{label}]: flagged={len(scan_cache[key][0])}, "
                f"review={len(scan_cache[key][1])}, functions={scan_cache[key][2]}, "
                f"target_function_present={scan_cache[key][3]}, "
                f"background_noise={len(scan_cache[key][4])}",
                flush=True,
            )
        except (OSError, ValueError, requests.RequestException) as exc:
            fetch_failures[key] = type(exc).__name__
            print(f"SOURCE FAIL [{label}]: {type(exc).__name__}: {exc}", flush=True)

    confusion: Counter = Counter()
    by_language: dict[str, Counter] = defaultdict(Counter)
    results = []
    for row_index, row in enumerate(rows):
        expected = row["expected_status"]
        ghsa = row["ghsa_id"]
        key = resolved_fields[row_index]
        target_presence = "unknown"
        retrieval_rank = None
        hash_retrieval_hit = False
        if not row.get("tier1_applicable", True):
            outcome = "not_applicable"
            target_presence = "not_applicable"
        elif key in fetch_failures:
            outcome = "source_fetch_error"
            target_presence = "source_unavailable"
        else:
            flagged, review, _, function_present, _, target_findings = scan_cache[key]
            if not function_present:
                outcome = "function_absent"
                target_presence = "source_present_function_absent"
                confusion[outcome] += 1
                by_language[row["source_language"]][outcome] += 1
                results.append({**_result_identity(row), "outcome": outcome,
                                "target_presence": target_presence,
                                "source_repo": key[0], "source_commit": key[1],
                                "source_path": key[2], "target_function": key[3],
                                "target_source_sha256": key[4],
                                "retrieval_rank": retrieval_rank,
                                "hash_retrieval_hit": hash_retrieval_hit})
                continue
            target_presence = "source_present"
            present_flagged = ghsa in flagged
            present_review = ghsa in review
            priority = "automatic_vulnerability" if present_flagged else (
                "manual_review" if present_review else "none")
            outcome = classification_outcome(expected, priority)
            expected_fields = expected_retrieval_fields(row)
            target_ranks = [
                detection_rank(finding["result"], expected_fields, detector.pairs)
                for finding in target_findings
                if ghsa in extract_ghsa_ids(finding["result"])
            ]
            target_ranks = [rank for rank in target_ranks if rank is not None]
            retrieval_rank = min(target_ranks) if target_ranks else None
            hash_retrieval_hit = any(
                bool(finding["result"].get("hash_matches"))
                for finding in target_findings
                if ghsa in extract_ghsa_ids(finding["result"])
            )
        confusion[outcome] += 1
        by_language[row["source_language"]][outcome] += 1
        results.append({**_result_identity(row), "outcome": outcome,
                        "target_presence": target_presence,
                        "source_repo": key[0], "source_commit": key[1],
                        "source_path": key[2], "target_function": key[3],
                        "target_source_sha256": key[4],
                        "retrieval_rank": retrieval_rank,
                        "hash_retrieval_hit": hash_retrieval_hit})

    _excluded = {"source_fetch_error", "not_applicable", "source_absent", "function_absent"}
    vulnerable_rows = [r for r in results if r["expected_status"] == "flagged" and r["outcome"] not in _excluded]
    fixed_rows = [r for r in results if r["expected_status"] == "cleared" and r["outcome"] not in _excluded]

    def _rate(rows_, predicate):
        return (sum(predicate(r) for r in rows_) / len(rows_)) if rows_ else None

    noise = [item for key, value in scan_cache.items() for item in value[4]]
    summary = {
        "label_rows": len(rows),
        "unique_source_targets": len(grouped),
        "source_fetch_failures": len(fetch_failures),
        "outcome_counts": dict(confusion),
        "target_presence_counts": dict(Counter(result.get("target_presence", "unknown") for result in results)),
        "outcomes_by_language": {k: dict(v) for k, v in sorted(by_language.items())},
        **summarize_evaluation(results, strata=("source_language",)),
        "background_noise": {
            "finding_count": len(noise),
            "ghsa_count": len({ghsa for item in noise for ghsa in item["ghsa_ids"]}),
            "priority_counts": dict(Counter(item["priority"] for item in noise)),
        },
    }
    output = {
        "schema": "evaluation_results_v3",
        "tier": "tier1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "labels_input": str(args.labels),
        "summary": summary,
        "background_noise": noise,
        "results": results,
    }
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print("\nSummary:")
    print(json.dumps(summary, indent=2))
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
