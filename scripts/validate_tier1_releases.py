"""Tier-1 self-check: fetch, verify, extract and statically scan real npm releases.

For every label row, the corresponding npm tarball is downloaded, its sha256 is
verified against the corpus digest, it is unpacked with the guarded extractor, and
scanned with the 301-entry corpus. No package code is executed. A vulnerable
release should flag its GHSA (true positive); the fixed release should not (true
negative). Tarballs shared by several advisories are scanned once.

Run from the repo root:
    $env:PYTHONPATH="."; .venv\\Scripts\\python.exe scripts\\validate_tier1_releases.py
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from corpus.controller.sandbox_fetch import (
    SandboxFetchError,
    download_release,
    prune_built_artifacts,
    safe_extract_tarball,
)
from corpus.controller.store import load_entries
from eval.common import DEFAULT_SNAPSHOT_DB, extract_ghsa_ids
from pipeline.controller.parsing import SUPPORTED_SOURCE_EXTENSIONS, extract_function_units
from pipeline.controller.region_detection import RegionDetectorConfig, build_region_detector
from pipeline.controller.scanning import ScanConfig, corpus_fingerprint, scan_directory

DEFAULT_LABELS = Path(__file__).resolve().parent.parent / "eval" / "tier1_release_labels.jsonl"
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "eval" / "tier1_release_results.json"
SANDBOX_ROOT = Path(__file__).resolve().parent.parent / "eval" / "tier1_sandbox"


def _load(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _safe_name(text: str) -> str:
    return "".join(c if c.isalnum() or c in "-._@" else "_" for c in text)


def _log(message: str) -> None:
    print(message, file=sys.stderr, flush=True)


def _count_functions(path: Path) -> int:
    try:
        source = path.read_text(encoding="utf-8")
        return len(extract_function_units(source, filename=str(path)))
    except (OSError, RuntimeError, ValueError):
        return 0


def _apply_function_cap(dest: Path, target_paths: set[str], max_functions: int) -> tuple[int, int]:
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


def _scan_tarball(url, sha, dest, detector, entries, corpus_version, label="",
                  target_paths=None, max_functions=None):
    """Download+verify+extract+scan one tarball. Returns (flagged, review) ghsa sets
    or raises SandboxFetchError."""
    started = time.time()
    _log(f"    [{label}] downloading {url.rsplit('/', 1)[-1]} ...")
    data = download_release(url, sha)
    report = safe_extract_tarball(data, dest)
    pruned = prune_built_artifacts(dest)
    cap_note = ""
    if max_functions is not None:
        kept_fns, capped_files = _apply_function_cap(dest, target_paths or set(), max_functions)
        cap_note = f"; capped to ~{kept_fns} fn (dropped {capped_files} file(s), vuln file always kept)"
    _log(
        f"    [{label}] extracted {report.files_written} file(s), "
        f"pruned {len(pruned.removed_dirs)} dir(s)/{len(pruned.removed_files)} file(s){cap_note}; scanning..."
    )
    summary = scan_directory(
        dest,
        detector=detector,
        entries=entries,
        config=ScanConfig(corpus_version=corpus_version, state_path=dest.parent / f"{dest.name}-state.json"),
        progress_callback=_make_scan_progress(label),
    )
    _log(f"    [{label}] scan finished in {time.time() - started:.0f}s")
    flagged, review = set(), set()
    for finding in summary.findings:
        result = finding["result"]
        ghsas = extract_ghsa_ids(result)
        if result.get("priority") == "automatic_vulnerability":
            flagged |= ghsas
        elif result.get("priority") == "manual_review":
            review |= ghsas
    return flagged, review, summary.total_functions


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--snapshot", type=Path, default=DEFAULT_SNAPSHOT_DB)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument(
        "--max-functions", type=int, default=None,
        help="Cap total functions scanned per package (the vuln file is always kept in full). "
             "Bounds the cost of large packages; omit to scan the whole package.",
    )
    args = parser.parse_args()

    rows = _load(args.labels)
    if args.limit:
        rows = rows[: args.limit]
    entries = load_entries(args.snapshot)
    corpus_version = corpus_fingerprint(entries)
    print(f"Corpus: {len(entries)} entries; label rows: {len(rows)}")
    detector = build_region_detector(
        entries,
        config=RegionDetectorConfig(retrieval_top_k=10, retrieval_threshold=0.0, max_verification_candidates=10),
    )
    print(f"Detector ready: {len(detector.region_index.pairs)} region pairs")

    # Scan each unique tarball once; a version often covers several advisories.
    by_url: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        by_url[row["tarball_url"]].append(row)

    scan_cache: dict[str, tuple[set, set, int]] = {}
    fetch_failures: dict[str, str] = {}
    total_tarballs = len(by_url)
    for index, (url, url_rows) in enumerate(by_url.items(), start=1):
        sample = url_rows[0]
        label = f"{index}/{total_tarballs} {sample['package_name']}@{sample['version']} {sample['kind']}"
        dest = SANDBOX_ROOT / _safe_name(f"{sample['package_name']}@{sample['version']}-{sample['kind']}")
        # Every advisory sharing this tarball contributes its vuln file, so the cap
        # never drops a function we need to score.
        target_paths = {row["corpus_file_path"] for row in url_rows if row.get("corpus_file_path")}
        try:
            scan_cache[url] = _scan_tarball(
                url, sample["expected_sha256"], dest, detector, entries, corpus_version, label=label,
                target_paths=target_paths, max_functions=args.max_functions,
            )
            print(f"scanned [{label}]: {len(scan_cache[url][0])} flagged ghsa, {scan_cache[url][2]} fns", flush=True)
        except SandboxFetchError as exc:
            fetch_failures[url] = exc.reason_code
            print(f"FETCH FAIL [{label}]: {exc.reason_code}", flush=True)

    confusion: Counter = Counter()
    by_language: dict[str, Counter] = defaultdict(Counter)
    results = []
    for row in rows:
        url = row["tarball_url"]
        expected = row["expected_status"]
        ghsa = row["ghsa_id"]
        if not row.get("tier1_applicable", True):
            outcome = "not_applicable"
        elif url in fetch_failures:
            outcome = "fetch_error"
        else:
            flagged, review, _ = scan_cache[url]
            present_flagged = ghsa in flagged
            present_review = ghsa in review
            if expected == "flagged":
                outcome = "true_positive" if present_flagged else (
                    "abstained_positive" if present_review else "false_negative")
            else:
                outcome = "false_positive" if present_flagged else (
                    "abstained_negative" if present_review else "true_negative")
        confusion[outcome] += 1
        by_language[row["source_language"]][outcome] += 1
        results.append({**{k: row[k] for k in ("ghsa_id", "package_name", "kind", "version",
                                               "source_language", "category", "expected_status")},
                        "outcome": outcome})

    _excluded = {"fetch_error", "not_applicable"}
    vulnerable_rows = [r for r in results if r["expected_status"] == "flagged" and r["outcome"] not in _excluded]
    fixed_rows = [r for r in results if r["expected_status"] == "cleared" and r["outcome"] not in _excluded]

    def _rate(rows_, predicate):
        return (sum(predicate(r) for r in rows_) / len(rows_)) if rows_ else None

    summary = {
        "label_rows": len(rows),
        "unique_tarballs": len(by_url),
        "fetch_failures": len(fetch_failures),
        "outcome_counts": dict(confusion),
        "outcomes_by_language": {k: dict(v) for k, v in sorted(by_language.items())},
        "vulnerable_recall_automatic": _rate(vulnerable_rows, lambda r: r["outcome"] == "true_positive"),
        "vulnerable_recall_including_abstain": _rate(
            vulnerable_rows, lambda r: r["outcome"] in {"true_positive", "abstained_positive"}),
        "fixed_false_positive_rate": _rate(fixed_rows, lambda r: r["outcome"] == "false_positive"),
    }
    output = {
        "schema": "tier1_release_selfcheck_v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "labels_input": str(args.labels),
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
