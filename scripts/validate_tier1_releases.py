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

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from corpus.controller.github import GitHubRateLimitError, fetch_source_tree
from corpus.controller.store import load_entries
from eval.common import DEFAULT_SNAPSHOT_DB, extract_ghsa_ids
from eval.metrics import (
    METRICS_SCHEMA,
    classification_outcome,
    detection_rank,
    expected_hash_match_types,
    expected_retrieval_fields,
    summarize_evaluation,
)
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector
from pipeline.controller.parsing import SUPPORTED_SOURCE_EXTENSIONS, extract_function_units
from pipeline.controller.scanning import (
    RESULT_CACHE_SCHEMA_VERSION,
    ScanConfig,
    corpus_fingerprint,
    scan_directory,
)

DEFAULT_LABELS = Path(__file__).resolve().parent.parent / "eval" / "tier1_release_labels.jsonl"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "tier1_release_results.json"
SANDBOX_ROOT = Path(__file__).resolve().parent.parent / "eval" / "tier1_source_sandbox"

_AUDITED_ABSENT_BOUNDARIES = {
    (
        "GHSA-ghcm-xqfw-q4vr",
        "4e2d512bf5bf6f9de1a8f0a48da78dc4d09ac4f3",
        "packages/mermaid/src/mermaidAPI.ts",
        "cssImportantStyles",
    ),
}

def _boundary_identity(row: dict) -> tuple:
    identity = row.get("corpus_entry") or {}
    return (
        row.get("ghsa_id"),
        identity.get("fix_commit_sha"),
        identity.get("file_path"),
        identity.get("function_name"),
    )


def _row_is_tier1_applicable(row: dict, excluded_boundaries: set[tuple] | None = None) -> bool:
    return row.get("tier1_applicable", True) and _boundary_identity(row) not in (excluded_boundaries or set())


def _finding_hashes(scan_record: tuple) -> set[str]:
    """Return every target-file function digest retained by a scan checkpoint."""
    _, _, _, _, noise, target_findings, _ = scan_record
    return {
        item.get("function_hash")
        for item in [*target_findings, *noise]
        if item.get("function_hash")
    }


def _release_boundary_exclusion_reason(
    vulnerable_hash: str | None,
    patched_hash: str,
    actual_hashes: set[str],
) -> str | None:
    if vulnerable_hash not in actual_hashes and patched_hash in actual_hashes:
        return "vulnerable_boundary_absent_patched_present"
    return None


def _checkpoint_key(key: tuple) -> str:
    return json.dumps(list(key), separators=(",", ":"), ensure_ascii=True)


def _checkpoint_config(labels: Path, corpus_version: str,
                      max_functions: int | None,
                      max_background_source_bytes: int | None,
                      include_local_correspondence: bool = False,
                      target_functions_only: bool = False) -> dict:
    """Return settings that must remain stable for checkpoint reuse.

    The requested label limit is intentionally excluded: a run with ``--limit 100``
    can safely reuse completed targets from an earlier ``--limit 50`` run.
    """
    return {
        "labels_sha256": hashlib.sha256(labels.read_bytes()).hexdigest(),
        "corpus_version": corpus_version,
        "max_functions": max_functions,
        "max_background_source_bytes": max_background_source_bytes,
        "result_cache_schema": RESULT_CACHE_SCHEMA_VERSION,
        "include_local_correspondence": include_local_correspondence,
        "target_functions_only": target_functions_only,
    }


def _load_checkpoint(path: Path, config: dict) -> dict[str, dict]:
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        _log(f"Ignoring unreadable checkpoint: {path}")
        return {}
    stored_config = payload.get("config") or {}
    # Checkpoints created before bounded background downloads have no value for
    # this field. Their completed target scans remain valid and are worth
    # preserving; the checkpoint is upgraded on the next save.
    # Completed scans are content-addressed by repository, commit, target path,
    # function and source digest. Regenerating or reordering the label manifest
    # therefore does not invalidate matching scan records.
    def invalidates_scan(key: str, value) -> bool:
        if key == "labels_sha256":
            return False
        if key == "max_background_source_bytes" and key not in stored_config:
            return False
        return stored_config.get(key) != value

    if any(
        invalidates_scan(key, value)
        for key, value in config.items()
    ):
        _log(f"Ignoring checkpoint with mismatched labels/corpus/settings: {path}")
        return {}
    completed = payload.get("completed")
    if not isinstance(completed, dict):
        return {}
    return completed


def _save_checkpoint(path: Path, config: dict, completed: dict[str, dict]) -> None:
    payload = {
        "schema": "tier1_evaluation_checkpoint_v1",
        "updated_at_utc": datetime.now(timezone.utc).isoformat(),
        "config": config,
        "completed": completed,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload), encoding="utf-8")
    temporary.replace(path)


def _scan_cache_record(value: tuple) -> dict:
    flagged, review, total_functions, function_present, noise, target_findings, capped = value
    return {
        "flagged": sorted(flagged),
        "review": sorted(review),
        "total_functions": total_functions,
        "function_present": function_present,
        "noise": noise,
        "target_findings": target_findings,
        "background_capped": capped,
    }


def _scan_cache_value(record: dict) -> tuple:
    return (
        set(record.get("flagged", [])),
        set(record.get("review", [])),
        int(record.get("total_functions", 0)),
        bool(record.get("function_present", False)),
        list(record.get("noise", [])),
        list(record.get("target_findings", [])),
        bool(record.get("background_capped", False)),
    )


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


def _select_source_files(
    sources: dict[str, str], target_path: str, max_functions: int | None
) -> tuple[dict[str, str], int, bool]:
    """Keep the target file and cap background functions per package release."""
    if max_functions is None:
        return sources, sum(
            len(extract_function_units(source, filename=path))
            for path, source in sources.items()
        ), False

    counts = {
        path: len(extract_function_units(source, filename=path))
        for path, source in sources.items()
    }
    selected = {target_path: sources[target_path]}
    total = counts[target_path]
    remaining = sorted(
        ((path, count) for path, count in counts.items() if path != target_path and count),
        key=lambda item: (item[1], item[0]),
    )
    for path, count in remaining:
        if total >= max_functions:
            break
        selected[path] = sources[path]
        total += count
    return selected, total, len(selected) < len(sources)


def _apply_function_cap_legacy(dest: Path, target_paths: set[str], max_functions: int) -> tuple[int, int]:
    """Deprecated compatibility helper retained for old imports."""
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
            source_chars = event.get("source_chars", 0)
            if source_chars >= 100_000:
                _log(
                    f"      [{label}]   large fn {event['function_index']}/"
                    f"{event['function_count']} ({event['name'] or '<anon>'}, "
                    f"{source_chars:,} chars)"
                )
            elif event["function_count"] >= 40 and event["function_index"] % 25 == 1:
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
    # Prefer the content-addressed locator. An isolated assignment or arrow
    # function can lose its inferred name when reparsed, but its exact source
    # digest remains stable and unambiguous.
    if target_source_sha256:
        return finding.get("function_hash") == target_source_sha256
    if function_name is not None:
        return finding.get("name") == function_name
    return True


def _package_path(source_path: str) -> str:
    parts = source_path.replace("\\", "/").split("/")
    if len(parts) >= 2 and parts[0] in {"packages", "package", "plugins", "apps"}:
        return "/".join(parts[:2])
    return ""


def _scan_source_package(source_repo, source_commit, source_path, function_name,
                         target_source_sha256, dest, detector, entries, corpus_version,
                         max_functions=None, max_background_source_bytes=1_000_000,
                         fetch_workers=8, label="", target_functions_only=False):
    """Fetch and scan the eligible same-language source package at one commit."""
    started = time.time()
    if "/" not in source_repo:
        raise ValueError(f"invalid GitHub repository: {source_repo}")
    owner, repo = source_repo.split("/", 1)
    _log(f"    [{label}] fetching source tree {source_repo}@{source_commit} "
         f"(target {source_path})")
    if dest.exists():
        shutil.rmtree(dest)
    sources = fetch_source_tree(
        owner,
        repo,
        source_commit,
        package_path=_package_path(source_path),
        required_paths={source_path},
        max_background_blob_bytes=max_background_source_bytes,
        max_workers=fetch_workers,
    )
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
        or (target_source_sha256 and hashlib.sha256(unit.source.encode("utf-8")).hexdigest() == target_source_sha256)
        for unit in target_units
    ) if function_name is not None or target_source_sha256 else True
    direct_units = []
    if target_functions_only and (function_name is not None or target_source_sha256):
        matched_units = [
            unit for unit in target_units
            if (target_locator_hash and hashlib.sha256(unit.source.encode("utf-8")).hexdigest() == target_locator_hash)
            or (target_locator_hash is None and function_name is not None and unit.name == function_name)
        ]
        if matched_units:
            direct_units = matched_units
            sources = {source_path: "\n\n".join(unit.source for unit in matched_units)}
            selected_functions = len(matched_units)
            background_capped = True
        else:
            _log(f"    [{label}] labelled function locator not found; skipping unrelated siblings")
            return set(), set(), 0, False, [], [], True
    else:
        sources, selected_functions, background_capped = _select_source_files(
            sources, source_path, max_functions
        )
    _log(f"    [{label}] selected {len(sources)} source file(s), "
         f"~{selected_functions} functions"
         + (" (background capped)" if background_capped else ""))
    if direct_units:
        findings = []
        for unit in direct_units:
            result = detector.detect(
                unit.source,
                candidate_id=source_path,
                language=unit.language,
                candidate_function_name=unit.name,
            )
            findings.append({
                "path": source_path,
                "name": unit.name,
                "function_hash": hashlib.sha256(unit.source.encode("utf-8")).hexdigest(),
                "result": result.model_dump(mode="json"),
            })
        total_functions = len(direct_units)
    else:
        for relative_path, source in sources.items():
            target = dest / relative_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(source, encoding="utf-8")
        summary = scan_directory(
            dest,
            detector=detector,
            entries=entries,
            config=ScanConfig(
                detector=detector.config,
                corpus_version=corpus_version,
                state_path=dest.parent / f"{dest.name}-state.json",
            ),
            progress_callback=_make_scan_progress(label),
        )
        findings = summary.findings
        total_functions = summary.total_functions
    _log(f"    [{label}] scan finished in {time.time() - started:.0f}s")
    flagged, review, noise = set(), set(), []
    target_findings = []
    for finding in findings:
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
    return flagged, review, total_functions, function_present, noise, target_findings, background_capped


def _result_identity(row: dict) -> dict:
    identity = {
        k: row[k]
        for k in ("ghsa_id", "package_name", "kind", "version",
                  "source_language", "category", "expected_status")
        if k in row
    }
    identity["corpus_entry"] = row.get("corpus_entry", {})
    return identity


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
            if item.advisory.ghsa_id == row.get("ghsa_id")
            and item.origin.file_path == row.get("corpus_file_path")
            and item.origin.function_name == identity.get("function_name")
        ),
        None,
    )
    if entry is None:
        return None, None, row.get("corpus_file_path", ""), identity.get("function_name"), row.get("target_source_sha256")
    rb = entry.release_boundary or {}
    commit_key = "last_affected_commit" if row.get("kind") == "vulnerable" else "first_fixed_commit"
    source = entry.vulnerable_function if row.get("kind") == "vulnerable" else entry.patched_function
    return entry.origin.repo, rb.get(commit_key), entry.origin.file_path, entry.origin.function_name, hashlib.sha256(source.encode("utf-8")).hexdigest()


def main() -> int:
    # Load the repository .env before any GitHub request so GITHUB_TOKEN is used
    # for authenticated API calls and the higher GitHub rate limit.
    load_dotenv()
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--checkpoint", type=Path, default=None,
        help="Persistent per-source checkpoint; defaults to <output>.checkpoint.json.",
    )
    parser.add_argument(
        "--no-resume", action="store_true",
        help="Ignore and replace any existing checkpoint for this evaluation.",
    )
    parser.add_argument(
        "--max-functions", type=int, default=1000,
        help="Maximum functions scanned per package release; target file is always kept. "
             "Use 0 for unlimited background scanning.",
    )
    parser.add_argument(
        "--fetch-workers", type=int, default=8,
        help="Concurrent GitHub source downloads per source tree (default: 8).",
    )
    parser.add_argument(
        "--max-background-source-bytes", type=int, default=1_000_000,
        help="Skip non-target source blobs larger than this many bytes (default: 1000000); "
             "the target is always fetched. Use 0 for unlimited.",
    )
    parser.add_argument(
        "--experimental-local-correspondence",
        action="store_true",
        help="Enable the default-off bounded regex/guard/order fallback.",
    )
    parser.add_argument(
        "--target-functions-only",
        action="store_true",
        help="Scan only the labelled function source; excludes sibling/background findings.",
    )
    args = parser.parse_args()
    if args.max_functions == 0:
        args.max_functions = None
    elif args.max_functions < 0:
        parser.error("--max-functions must be non-negative")
    if args.fetch_workers < 1:
        parser.error("--fetch-workers must be at least 1")
    if args.max_background_source_bytes == 0:
        args.max_background_source_bytes = None
    elif args.max_background_source_bytes < 0:
        parser.error("--max-background-source-bytes must be non-negative")

    rows = _load(args.labels)
    if args.limit:
        rows = rows[: args.limit]
    entries = load_entries(args.snapshot)
    corpus_version = corpus_fingerprint(entries)
    checkpoint_path = args.checkpoint or args.output.with_suffix(".checkpoint.json")
    checkpoint_config = _checkpoint_config(
        args.labels,
        corpus_version,
        args.max_functions,
        args.max_background_source_bytes,
        args.experimental_local_correspondence,
        args.target_functions_only,
    )
    completed_checkpoint = {} if args.no_resume else _load_checkpoint(checkpoint_path, checkpoint_config)
    print(f"Corpus: {len(entries)} entries; label rows: {len(rows)}")
    if completed_checkpoint:
        print(f"Resuming: {len(completed_checkpoint)} completed source target(s) loaded from {checkpoint_path}")
    detector = build_region_detector(
        entries,
        config=RegionDetectorConfig(
            retrieval_top_k=10,
            retrieval_threshold=0.0,
            max_verification_candidates=10,
            include_local_correspondence_fallback=args.experimental_local_correspondence,
        ),
    )
    print(f"Detector ready: {len(detector.region_index.pairs)} region pairs")

    grouped: dict[tuple, list[dict]] = defaultdict(list)
    resolved_fields: dict[int, tuple[str | None, str | None, str, str | None, str | None]] = {}
    for index, row in enumerate(rows):
        fields = _source_fields(row, entries)
        resolved_fields[index] = fields
        grouped[fields].append(row)

    scan_cache: dict[tuple, tuple[set, set, int, bool, list, list, bool]] = {}
    fetch_failures: dict[tuple, str] = {}
    total_sources = len(grouped)
    interrupted_by_rate_limit = False
    for index, (key, source_rows) in enumerate(grouped.items(), start=1):
        source_repo, source_commit, source_path, function_name, target_source_sha256 = key
        sample = source_rows[0]
        label = f"{index}/{total_sources} {sample['package_name']}@{sample['version']} {sample['kind']}"
        checkpoint_id = _checkpoint_key(key)
        if checkpoint_id in completed_checkpoint:
            scan_cache[key] = _scan_cache_value(completed_checkpoint[checkpoint_id])
            print(f"resumed [{label}]", flush=True)
            continue
        dest = SANDBOX_ROOT / _safe_name(
            f"{sample['package_name']}@{sample['version']}-{sample['kind']}-{source_path}"
        )
        try:
            if not source_repo or not source_commit:
                raise ValueError("source release commit is unavailable")
            scan_cache[key] = _scan_source_package(
                source_repo, source_commit, source_path, function_name, target_source_sha256,
                dest, detector, entries, corpus_version,
                max_functions=args.max_functions,
                max_background_source_bytes=args.max_background_source_bytes,
                fetch_workers=args.fetch_workers,
                label=label,
                target_functions_only=args.target_functions_only,
            )
            print(
                f"scanned [{label}]: flagged={len(scan_cache[key][0])}, "
                f"review={len(scan_cache[key][1])}, functions={scan_cache[key][2]}, "
                f"target_function_present={scan_cache[key][3]}, "
                f"background_noise={len(scan_cache[key][4])}, "
                f"background_capped={scan_cache[key][6]}",
                flush=True,
            )
            completed_checkpoint[checkpoint_id] = _scan_cache_record(scan_cache[key])
            _save_checkpoint(checkpoint_path, checkpoint_config, completed_checkpoint)
        except GitHubRateLimitError as exc:
            interrupted_by_rate_limit = True
            _save_checkpoint(checkpoint_path, checkpoint_config, completed_checkpoint)
            print(
                f"RATE LIMIT: {exc}\n"
                f"Saved {len(completed_checkpoint)} completed source target(s) to {checkpoint_path}. "
                "Rerun the same command after the reset time to resume.",
                file=sys.stderr,
                flush=True,
            )
            break
        except (OSError, ValueError, requests.RequestException) as exc:
            fetch_failures[key] = type(exc).__name__
            print(f"SOURCE FAIL [{label}]: {type(exc).__name__}: {exc}", flush=True)

    if interrupted_by_rate_limit:
        return 75
    _save_checkpoint(checkpoint_path, checkpoint_config, completed_checkpoint)

    # A package can remain globally vulnerable after one of an advisory's function
    # boundaries has already been patched. Validate every vulnerable release label
    # at function granularity and exclude the whole pair when the vulnerable digest
    # is absent but the exact patched digest is present.
    entries_by_boundary = {
        (entry.advisory.ghsa_id, entry.origin.fix_commit_sha, entry.origin.file_path, entry.origin.function_name): entry
        for entry in entries
    }
    exclusion_reasons = {
        boundary: "audited_vulnerable_boundary_absent"
        for boundary in _AUDITED_ABSENT_BOUNDARIES
    }
    excluded_boundaries: set[tuple] = set(exclusion_reasons)
    for row_index, row in enumerate(rows):
        if row.get("expected_status") != "flagged" or not row.get("tier1_applicable", True):
            continue
        key = resolved_fields[row_index]
        scan_record = scan_cache.get(key)
        entry = entries_by_boundary.get(_boundary_identity(row))
        if scan_record is None or entry is None or not scan_record[3]:
            continue
        actual_hashes = _finding_hashes(scan_record)
        vulnerable_hash = key[4]
        patched_hash = hashlib.sha256(entry.patched_function.encode("utf-8")).hexdigest()
        reason = _release_boundary_exclusion_reason(
            vulnerable_hash, patched_hash, actual_hashes
        )
        if reason:
            boundary = _boundary_identity(row)
            excluded_boundaries.add(boundary)
            exclusion_reasons[boundary] = reason

    if excluded_boundaries:
        print(
            f"Excluded {len(excluded_boundaries)} release boundary pair(s): "
            "labelled vulnerable source contains the exact patched function",
            flush=True,
        )

    confusion: Counter = Counter()
    by_language: dict[str, Counter] = defaultdict(Counter)
    results = []
    for row_index, row in enumerate(rows):
        expected = row["expected_status"]
        ghsa = row["ghsa_id"]
        key = resolved_fields[row_index]
        target_presence = "unknown"
        retrieval_rank = None
        ranked_retrieval_rank = None
        hash_retrieval_hit = False
        exact_hash_retrieval_hit = False
        abstracted_hash_retrieval_hit = False
        exclusion_reason = None
        if _boundary_identity(row) in excluded_boundaries:
            exclusion_reason = exclusion_reasons[_boundary_identity(row)]
        if not _row_is_tier1_applicable(row, excluded_boundaries):
            outcome = "not_applicable"
            target_presence = "not_applicable"
        elif key in fetch_failures:
            outcome = "source_fetch_error"
            target_presence = "source_unavailable"
        else:
            flagged, review, _, function_present, noise, target_findings, _ = scan_cache[key]
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
                                "ranked_retrieval_rank": ranked_retrieval_rank,
                                "hash_retrieval_hit": hash_retrieval_hit,
                                "exact_hash_retrieval_hit": exact_hash_retrieval_hit,
                                "abstracted_hash_retrieval_hit": abstracted_hash_retrieval_hit})
                continue
            target_presence = "source_present"
            # Checkpoints produced before hash-first attribution stored an exact
            # anonymous target as background noise. Recover that content-addressed
            # evidence without requiring a network refetch.
            cached_exact_target = [
                item for item in noise
                if key[4]
                and item.get("path", "").replace("\\", "/") == key[2].replace("\\", "/")
                and item.get("function_hash") == key[4]
                and ghsa in item.get("ghsa_ids", [])
            ]
            present_flagged = ghsa in flagged or any(
                item.get("priority") == "automatic_vulnerability"
                for item in cached_exact_target
            )
            present_review = ghsa in review or any(
                item.get("priority") == "manual_review"
                for item in cached_exact_target
            )
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
            ranked_retrieval_rank = min(target_ranks) if target_ranks else None
            hash_match_types = set().union(*(
                expected_hash_match_types(finding["result"], expected_fields)
                for finding in target_findings
            )) if target_findings else set()
            exact_hash_retrieval_hit = "exact" in hash_match_types
            abstracted_hash_retrieval_hit = "abstracted" in hash_match_types
            hash_retrieval_hit = bool(hash_match_types)
            retrieval_rank = 1 if hash_retrieval_hit else ranked_retrieval_rank
            if cached_exact_target:
                exact_hash_retrieval_hit = True
                hash_retrieval_hit = True
                retrieval_rank = 1
        confusion[outcome] += 1
        by_language[row["source_language"]][outcome] += 1
        results.append({**_result_identity(row), "outcome": outcome,
                        "target_presence": target_presence,
                        "exclusion_reason": exclusion_reason,
                        "source_repo": key[0], "source_commit": key[1],
                        "source_path": key[2], "target_function": key[3],
                        "target_source_sha256": key[4],
                        "retrieval_rank": retrieval_rank,
                        "ranked_retrieval_rank": ranked_retrieval_rank,
                        "hash_retrieval_hit": hash_retrieval_hit,
                        "exact_hash_retrieval_hit": exact_hash_retrieval_hit,
                        "abstracted_hash_retrieval_hit": abstracted_hash_retrieval_hit})

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
            "capped_package_count": sum(value[6] for value in scan_cache.values()),
            "max_functions_per_package": args.max_functions,
        },
    }
    output = {
        "schema": "evaluation_results_v4",
        "metrics_schema": METRICS_SCHEMA,
        "tier": "tier1",
        "target_functions_only": args.target_functions_only,
        "experimental_local_correspondence": args.experimental_local_correspondence,
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
