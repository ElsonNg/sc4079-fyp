"""Command-line interface for provtrail."""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import shutil
from collections import Counter
from pathlib import Path

import numpy as np
import requests

from corpus.controller.build import build_corpus_result, print_attrition_report, probe_packages
from corpus.controller.deduplication import deduplicate_entries
from corpus.controller.snapshot import DEFAULT_SNAPSHOTS_DIR, SnapshotIntegrityError, promote_snapshot
from corpus.controller.klaban import (
    DEFAULT_KLABAN_PATH,
    KLABAN_ID_PREFIX,
    parse_klaban_corpus,
    print_klaban_report,
)
from corpus.controller.store import DEFAULT_DB_PATH, load_entries, replace_entries_by_ghsa_prefix, save_entries
from pipeline.controller import embedding
from pipeline.controller.embedding import DEFAULT_MODEL_ID, EMBEDDING_DEVICE_ENV
from pipeline.controller.region_extraction import extract_corpus_region_pairs
from pipeline.controller.region_retrieval import (
    DEFAULT_REGION_EMBEDDINGS_DIR,
    _region_fingerprint,
)
from pipeline.controller.retrieval import (
    DEFAULT_EMBEDDINGS_DIR,
    INDEX_FORMAT_VERSION,
    _corpus_fingerprint,
    _corpus_windows,
    _match_from_entry,
    _normalized_text,
)
from pipeline.controller.region_detection import RegionDetectorConfig
from pipeline.controller.region_verification import RegionVerifierConfig
from pipeline.controller.review_explanation import (
    DEFAULT_OLLAMA_HOST,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_TIMEOUT,
    OllamaExplanationConfig,
    enrich_manual_review_findings,
    explanation_progress,
)
from pipeline.controller.scanning import (
    ScanConfig,
    build_default_detector_factory,
    corpus_fingerprint,
    scan_directory,
)
from pipeline.controller.reporting import (
    DIVIDER,
    format_attention,
    format_audit_summary,
    format_verbose,
    load_scan_report,
    report_exit_code,
    report_view,
)
from pipeline.controller.html_reporting import build_html_report_data, write_html_report

PROVTRAIL_VERSION = "development"


def _add_db_path(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db-path", type=Path, default=None, help="Corpus SQLite path")


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def _scan_progress(event: dict) -> None:
    """Render live scan progress without contaminating JSON stdout."""
    phase = event["phase"]
    if phase == "snapshot_start":
        message = f"scan: discovering JavaScript/TypeScript files in {event['root']}..."
    elif phase == "snapshot_complete":
        message = f"scan: found {event['total_files']} JavaScript/TypeScript file(s)"
    elif phase == "detector_start":
        message = "detector: loading model and AST-region index..."
    elif phase == "detector_ready":
        message = "detector: ready"
    elif phase == "file_start":
        message = (
            f"[file {event['completed_files'] + 1}/{event['total_files']}] "
            f"{event['path']} ({event['function_count']} function(s))"
        )
    elif phase == "function_start":
        name = event["name"] or "<anonymous>"
        message = (
            f"  [function {event['function_index']}/{event['function_count']}] "
            f"running {name}..."
        )
    elif phase == "function_complete":
        name = event["name"] or "<anonymous>"
        message = (
            f"  [function {event['function_index']}/{event['function_count']}] "
            f"{name}: {event['status']} ({event['source']})"
        )
    elif phase == "file_complete":
        message = (
            f"[file {event['completed_files']}/{event['total_files']}] "
            f"complete: {event['path']} — {event['scanned_count']} scanned, "
            f"{event['reused_count']} reused"
        )
    elif phase == "scan_complete":
        message = (
            f"scan: complete — {event['total_files']} file(s), "
            f"{event['total_functions']} function(s), "
            f"{event['scanned_functions']} scanned, {event['reused_functions']} reused"
        )
    else:
        return
    print(message, file=sys.stderr, flush=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provtrail",
        description="Detect JavaScript vulnerability clones and TypeScript vulnerability clones",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Scan a JavaScript/TypeScript codebase")
    scan.add_argument("path", type=Path)
    _add_db_path(scan)
    scan.add_argument("--state-path", type=Path, default=None)
    scan.add_argument("--output", type=Path, default=None, help="Write structured scan JSON to this path")
    scan.add_argument(
        "--html-output",
        type=Path,
        default=None,
        help="Write the self-contained HTML report to this path",
    )
    scan.add_argument("--embed-model", dest="model", default=None)
    scan.add_argument("--top-k", type=int, default=10)
    scan.add_argument("--retrieval-threshold", type=float, default=0.0)
    scan.add_argument("--min-structure-score", type=float, default=0.70)
    scan.add_argument("--min-token-score", type=float, default=0.70)
    scan.add_argument("--min-edit-side-score", type=float, default=0.90)
    scan.add_argument("--min-edit-margin", type=float, default=0.10)
    scan.add_argument(
        "--experimental-local-correspondence",
        action="store_true",
        help="Enable the default-off bounded regex/guard/order fallback after S/T/E abstains.",
    )
    scan.add_argument(
        "--explain-review",
        action="store_true",
        help="Generate optional local Ollama relevance verdicts for manual-review findings",
    )
    scan.add_argument(
        "--ollama-model",
        default=os.environ.get("PROVTRAIL_OLLAMA_MODEL", DEFAULT_OLLAMA_MODEL),
        help=f"Ollama model used for review explanations (default: {DEFAULT_OLLAMA_MODEL})",
    )
    scan.add_argument(
        "--ollama-host",
        default=os.environ.get("OLLAMA_HOST", DEFAULT_OLLAMA_HOST),
        help=f"Ollama API host (default: {DEFAULT_OLLAMA_HOST})",
    )
    scan.add_argument(
        "--ollama-timeout",
        type=_positive_float,
        default=DEFAULT_OLLAMA_TIMEOUT,
        help=f"Per-request Ollama timeout in seconds (default: {DEFAULT_OLLAMA_TIMEOUT:g})",
    )
    scan.add_argument("--json", action="store_true", help="Print structured JSON instead of the summary")

    report = commands.add_parser("report", help="Inspect a saved scan report without rerunning detection")
    report.add_argument("path", type=Path, help="Scan JSON file or target directory")
    report.add_argument("--verbose", action="store_true", help="Show CVE, version, score, and provenance details")
    report.add_argument(
        "--include-informational", action="store_true",
        help="Include informational lineage and no-match results in detailed output",
    )
    report.add_argument("--json", action="store_true", help="Print the structured report view")

    corpus = commands.add_parser("corpus", help="Manage the vulnerability corpus")
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)
    build = corpus_commands.add_parser("build", help="Build the corpus from advisory sources")
    build.add_argument("--package", action="append", dest="packages", default=None)
    _add_db_path(build)
    build.add_argument("--snapshots-dir", type=Path, default=DEFAULT_SNAPSHOTS_DIR)
    build.add_argument(
        "--append",
        action="store_true",
        help="Merge admitted entries into the current corpus instead of replacing it",
    )
    probe = corpus_commands.add_parser(
        "probe", help="List npm packages ranked by reviewed advisory coverage"
    )
    probe.add_argument("--limit", type=int, default=None, help="Show only the first N ranked packages")
    probe.add_argument("--output", type=Path, default=None, help="Write the probe JSON to this path")
    probe.add_argument("--include-withdrawn", action="store_true")
    stats = corpus_commands.add_parser("stats", help="Show corpus size and metadata coverage")
    _add_db_path(stats)
    ingest_klaban = corpus_commands.add_parser(
        "ingest-klaban",
        help="Import the manually confirmed Klaban corpus and build its indexes",
    )
    ingest_klaban.add_argument("path", nargs="?", type=Path, default=DEFAULT_KLABAN_PATH)
    _add_db_path(ingest_klaban)
    ingest_klaban.add_argument("--embed-model", dest="model", default=DEFAULT_MODEL_ID)
    ingest_klaban.add_argument(
        "--device", choices=("cpu", "mps", "cuda"), default=None,
        help=f"Embedding device (also configurable with {EMBEDDING_DEVICE_ENV})",
    )
    ingest_klaban.add_argument("--embedding-batch-size", type=int, default=1)
    ingest_klaban.add_argument("--skip-index", action="store_true")
    ingest_klaban.add_argument("--skip-region-index", action="store_true")
    ingest_klaban.add_argument("--embeddings-dir", type=Path, default=DEFAULT_EMBEDDINGS_DIR)
    ingest_klaban.add_argument(
        "--region-embeddings-dir", type=Path, default=DEFAULT_REGION_EMBEDDINGS_DIR
    )
    index = corpus_commands.add_parser("index", help="Build function and AST-region embedding indexes")
    _add_db_path(index)
    index.add_argument("--embed-model", dest="model", default=DEFAULT_MODEL_ID)
    index.add_argument(
        "--device", choices=("cpu", "mps", "cuda"), default=None,
        help=f"Embedding device (also configurable with {EMBEDDING_DEVICE_ENV})",
    )
    index.add_argument("--embedding-batch-size", type=int, default=1)
    index.add_argument("--skip-region-index", action="store_true")
    index.add_argument("--embeddings-dir", type=Path, default=DEFAULT_EMBEDDINGS_DIR)
    index.add_argument("--region-embeddings-dir", type=Path, default=DEFAULT_REGION_EMBEDDINGS_DIR)
    return parser


def _scan(args: argparse.Namespace) -> int:
    entries = load_entries(args.db_path) if args.db_path else load_entries()
    verifier = RegionVerifierConfig(
        minimum_structure_score=args.min_structure_score,
        minimum_token_score=args.min_token_score,
        minimum_edit_side_score=args.min_edit_side_score,
        minimum_edit_margin=args.min_edit_margin,
    )
    detector_config = RegionDetectorConfig(
        **({"model_id": args.model} if args.model else {}),
        retrieval_top_k=args.top_k,
        retrieval_threshold=args.retrieval_threshold,
        max_verification_candidates=10,
        include_local_correspondence_fallback=args.experimental_local_correspondence,
        verifier=verifier,
    )
    scan_config = ScanConfig(
        detector=detector_config,
        corpus_version=corpus_fingerprint(entries),
        state_path=args.state_path,
    )
    summary = scan_directory(
        args.path,
        entries=entries,
        config=scan_config,
        detector_factory=build_default_detector_factory(entries, detector_config),
        progress_callback=_scan_progress,
    )
    if args.explain_review:
        cache_path = Path(summary.state_path).with_name("review-explanations.json")
        enrich_manual_review_findings(
            summary,
            entries=entries,
            scan_config=scan_config,
            ollama_config=OllamaExplanationConfig(
                model=args.ollama_model,
                host=args.ollama_host,
                timeout=args.ollama_timeout,
            ),
            cache_path=cache_path,
            progress_callback=explanation_progress,
            warning_callback=lambda message: print(f"warning: {message}", file=sys.stderr),
        )
    payload = summary.to_dict()
    output_path = args.output or args.path.resolve() / ".provtrail" / "latest-scan.json"
    html_output_path = args.html_output or output_path.with_suffix(".html")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.tmp")
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    temporary.replace(output_path)
    html_data = build_html_report_data(
        summary,
        entries=entries,
        config=scan_config,
        tool_version=PROVTRAIL_VERSION,
    )
    write_html_report(html_output_path, html_data)
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(format_audit_summary(payload))
        print("ARTIFACTS")
        print(f"  structured report:     {output_path}")
        print(f"  HTML report:           {html_output_path}")
        print(DIVIDER)
        print(format_attention(payload))
    return report_exit_code(payload)


def _report(args: argparse.Namespace) -> int:
    report_path = args.path
    if report_path.is_dir():
        report_path = report_path / ".provtrail" / "latest-scan.json"
    try:
        payload = load_scan_report(report_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Unable to read scan report: {exc}")
        return 2

    if args.json:
        print(json.dumps(report_view(payload, include_informational=args.include_informational), indent=2))
    elif args.verbose:
        print(format_verbose(payload, include_informational=args.include_informational))
    else:
        print(format_audit_summary(payload))
    return report_exit_code(payload)


def _corpus_build_progress(event: dict) -> None:
    phase = event.get("phase")
    if phase == "discovery_complete":
        print(f"corpus: discovered {event['advisories']} reviewed advisory record(s)", file=sys.stderr, flush=True)
    elif phase == "advisory_start":
        print(
            f"corpus: advisory {event['index']}/{event['total']} {event['ghsa_id']}",
            file=sys.stderr, flush=True,
        )
    elif phase == "package_start":
        print(f"  package: {event['package']} ({event['ghsa_id']})", file=sys.stderr, flush=True)
    elif phase == "candidate_start":
        print(
            f"    resolve: {event['repo']}@{event['commit'][:12]}",
            file=sys.stderr, flush=True,
        )
    elif phase == "candidate_quarantined":
        print(
            f"    quarantine: {event['reason']} — {event['repo']}@{event['commit'][:12]}",
            file=sys.stderr, flush=True,
        )
    elif phase == "candidate_admitted":
        print(
            f"    admitted: {event['pairs']} function pair(s) from {event['repo']}@{event['commit'][:12]}",
            file=sys.stderr, flush=True,
        )


def _corpus_build(args: argparse.Namespace) -> int:
    packages = tuple(args.packages) if args.packages else None
    try:
        result = build_corpus_result(packages=packages, progress_callback=_corpus_build_progress)
    except requests.RequestException as exc:
        print(f"Corpus discovery failed before candidate processing: {exc}", file=sys.stderr)
        print("No snapshot was promoted and the active corpus was not changed.", file=sys.stderr)
        return 2
    database = args.db_path or DEFAULT_DB_PATH
    if args.append and database.exists():
        existing = load_entries(database)
        result.entries, removed = deduplicate_entries(existing + result.entries)
        result.source_manifest["append_base_entries"] = len(existing)
        result.source_manifest["append_duplicates_removed"] = removed
        for report in result.reports:
            report.corpus_entries_final = len(result.entries)
            report.duplicates_removed += removed
            report.high_impact_entries = sum(entry.high_impact for entry in result.entries)
    if not result.entries:
        for report in result.reports:
            print_attrition_report(report)
        print("No corpus entries were admitted; active corpus was not changed.", file=sys.stderr)
        return 2
    try:
        snapshot = promote_snapshot(result, args.snapshots_dir)
    except SnapshotIntegrityError as exc:
        print(f"Corpus snapshot was not promoted: {exc}", file=sys.stderr)
        return 2
    database.parent.mkdir(parents=True, exist_ok=True)
    temporary = database.with_name(f".{database.name}.tmp")
    shutil.copyfile(snapshot / "corpus.db", temporary)
    temporary.replace(database)
    for report in result.reports:
        print_attrition_report(report)
    print(f"Promoted immutable snapshot {snapshot.name} with {len(result.entries)} entries")
    print(f"Active corpus database: {database}")
    return 0


def _corpus_probe(args: argparse.Namespace) -> int:
    try:
        payload = probe_packages(include_withdrawn=args.include_withdrawn)
    except requests.RequestException as exc:
        print(f"Package probe failed: {exc}", file=sys.stderr)
        return 2
    all_packages = payload["packages"]
    packages = all_packages
    if args.limit is not None:
        if args.limit < 1:
            print("--limit must be greater than zero", file=sys.stderr)
            return 2
        packages = packages[: args.limit]
    payload["all_packages"] = all_packages
    payload["packages"] = packages
    payload["selected_packages"] = [item["package"] for item in packages]
    payload["selected_count"] = len(packages)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"Wrote package probe to {args.output}")
    else:
        print(f"Advisories found: {payload['advisories_found']}")
        print(f"Packages found:   {payload['package_count']}")
        print("Rank  Advisories  Package")
        for item in packages:
            print(f"{item['rank']:>4}  {item['advisories']:>10}  {item['package']}")
    return 0


def _corpus_stats(args: argparse.Namespace) -> int:
    entries = load_entries(args.db_path) if args.db_path else load_entries()
    packages = Counter(entry.package_name for entry in entries)
    confirmed = sum(entry.osv_confirmed for entry in entries)
    high_impact = sum(entry.high_impact for entry in entries)
    languages = Counter(entry.source_language for entry in entries)
    print(f"Corpus entries: {len(entries)}")
    print(f"OSV-confirmed:  {confirmed}")
    print(f"High impact:    {high_impact}")
    print(f"Corpus version: {corpus_fingerprint(entries)}")
    print("Packages:")
    for package, count in sorted(packages.items()):
        print(f"  {package}: {count}")
    print("Languages:")
    for language, count in sorted(languages.items()):
        print(f"  {language}: {count}")
    return 0


def _corpus_index(args: argparse.Namespace) -> int:
    os.environ.setdefault("KMP_DUPLICATE_LIB_OK", "TRUE")
    if args.device:
        os.environ[EMBEDDING_DEVICE_ENV] = args.device
    entries = load_entries(args.db_path) if args.db_path else load_entries()
    print(f"Building function index for {len(entries)} corpus entries...")
    function_texts = []
    function_matches = []
    for entry in entries:
        windows = _corpus_windows(entry)
        function_texts.extend(_normalized_text(window) for window in windows)
        function_matches.extend(_match_from_entry(entry) for _ in windows)
    function_vectors = embedding.encode(
        args.model,
        function_texts,
        batch_size=args.embedding_batch_size,
        progress_callback=lambda done, total: print(f"  embedded {done}/{total} functions")
        if done == total or done % 320 == 0 else None,
    )
    args.embeddings_dir.mkdir(parents=True, exist_ok=True)
    function_index_path = args.embeddings_dir / f"{args.model}.faiss"
    function_vector_path = args.embeddings_dir / f".{args.model}.vectors.npy"
    np.save(function_vector_path, function_vectors)
    del function_vectors
    embedding.release_models()
    subprocess.run(
        [sys.executable, "-m", "cli.faiss_builder", str(function_vector_path), str(function_index_path)],
        check=True,
    )
    function_vector_path.unlink()
    function_meta = {
        "model_id": args.model,
        "max_seq_length": embedding.DEFAULT_MAX_SEQ_LENGTH,
        "corpus_fingerprint": _corpus_fingerprint(entries),
        "index_format_version": INDEX_FORMAT_VERSION,
        "entries": [match.model_dump() for match in function_matches],
    }
    (args.embeddings_dir / f"{args.model}.meta.json").write_text(json.dumps(function_meta), encoding="utf-8")
    if args.skip_region_index:
        print(f"Indexed {len(function_matches)} windows from {len(entries)} functions with {args.model}")
        return 0

    pairs = extract_corpus_region_pairs(entries)
    print(f"Building AST-region index for {len(pairs)} vulnerable region pairs...")
    region_vectors = embedding.encode(
        args.model,
        [pair.vulnerable_region.embedding_text for pair in pairs],
        batch_size=args.embedding_batch_size,
        progress_callback=lambda done, total: print(f"  embedded {done}/{total} regions")
        if done == total or done % 320 == 0 else None,
    )
    args.region_embeddings_dir.mkdir(parents=True, exist_ok=True)
    region_index_path = args.region_embeddings_dir / f"{args.model}.faiss"
    region_vector_path = args.region_embeddings_dir / f".{args.model}.vectors.npy"
    np.save(region_vector_path, region_vectors)
    del region_vectors
    embedding.release_models()
    subprocess.run(
        [sys.executable, "-m", "cli.faiss_builder", str(region_vector_path), str(region_index_path)],
        check=True,
    )
    region_vector_path.unlink()
    region_meta = {
        "model_id": args.model,
        "max_seq_length": embedding.DEFAULT_MAX_SEQ_LENGTH,
        "fingerprint": _region_fingerprint(pairs, args.model),
        "pairs": [pair.model_dump() for pair in pairs],
    }
    (args.region_embeddings_dir / f"{args.model}.meta.json").write_text(json.dumps(region_meta), encoding="utf-8")
    print(
        f"Indexed {len(entries)} functions and {len(pairs)} AST regions with {args.model}"
    )
    return 0


def _corpus_ingest_klaban(args: argparse.Namespace) -> int:
    entries, report = parse_klaban_corpus(args.path)
    if args.db_path:
        replace_entries_by_ghsa_prefix(entries, KLABAN_ID_PREFIX, args.db_path)
    else:
        replace_entries_by_ghsa_prefix(entries, KLABAN_ID_PREFIX)
    print_klaban_report(report)
    print(f"Saved {len(entries)} Klaban entries")
    if not args.skip_index:
        return _corpus_index(args)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "report":
        return _report(args)
    if args.corpus_command == "build":
        return _corpus_build(args)
    if args.corpus_command == "probe":
        return _corpus_probe(args)
    if args.corpus_command == "stats":
        return _corpus_stats(args)
    if args.corpus_command == "index":
        return _corpus_index(args)
    return _corpus_ingest_klaban(args)


if __name__ == "__main__":
    raise SystemExit(main())
