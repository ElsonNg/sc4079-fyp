"""Command-line interface for provtrail."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from corpus.controller.build import build_corpus, print_attrition_report
from corpus.controller.store import load_entries, save_entries
from pipeline.controller.region_detection import RegionDetectorConfig
from pipeline.controller.region_verification import RegionVerifierConfig
from pipeline.controller.scanning import (
    ScanConfig,
    build_default_detector_factory,
    corpus_fingerprint,
    scan_directory,
)
from pipeline.controller.reporting import (
    format_audit_summary,
    format_verbose,
    load_scan_report,
    report_exit_code,
    report_view,
)


def _add_db_path(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db-path", type=Path, default=None, help="Corpus SQLite path")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="provtrail", description="Detect JavaScript vulnerability clones")
    commands = parser.add_subparsers(dest="command", required=True)

    scan = commands.add_parser("scan", help="Scan a JavaScript codebase")
    scan.add_argument("path", type=Path)
    _add_db_path(scan)
    scan.add_argument("--state-path", type=Path, default=None)
    scan.add_argument("--output", type=Path, default=None, help="Write structured scan JSON to this path")
    scan.add_argument("--model", default=None)
    scan.add_argument("--top-k", type=int, default=10)
    scan.add_argument("--retrieval-threshold", type=float, default=0.0)
    scan.add_argument("--minimum-vulnerable-score", type=float, default=0.75)
    scan.add_argument("--minimum-margin", type=float, default=0.08)
    scan.add_argument("--json", action="store_true", help="Print structured JSON instead of the summary")

    report = commands.add_parser("report", help="Inspect a saved scan report without rerunning detection")
    report.add_argument("path", type=Path, help="Scan JSON file or target directory")
    report.add_argument("--verbose", action="store_true", help="Show CVE, version, score, and provenance details")
    report.add_argument("--include-cleared", action="store_true", help="Include cleared findings in detailed output")
    report.add_argument("--json", action="store_true", help="Print the structured report view")

    corpus = commands.add_parser("corpus", help="Manage the vulnerability corpus")
    corpus_commands = corpus.add_subparsers(dest="corpus_command", required=True)
    build = corpus_commands.add_parser("build", help="Build the corpus from advisory sources")
    build.add_argument("--package", action="append", dest="packages", default=None)
    _add_db_path(build)
    stats = corpus_commands.add_parser("stats", help="Show corpus size and metadata coverage")
    _add_db_path(stats)
    return parser


def _scan(args: argparse.Namespace) -> int:
    entries = load_entries(args.db_path) if args.db_path else load_entries()
    verifier = RegionVerifierConfig(
        minimum_vulnerable_score=args.minimum_vulnerable_score,
        minimum_margin=args.minimum_margin,
    )
    detector_config = RegionDetectorConfig(
        **({"model_id": args.model} if args.model else {}),
        retrieval_top_k=args.top_k,
        retrieval_threshold=args.retrieval_threshold,
        max_verification_candidates=10,
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
    )
    payload = summary.to_dict()
    output_path = args.output or args.path.resolve() / ".provtrail" / "latest-scan.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(format_audit_summary(payload))
        print(f"  report:                {output_path}")
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
        print(json.dumps(report_view(payload, include_cleared=args.include_cleared), indent=2))
    elif args.verbose:
        print(format_verbose(payload, include_cleared=args.include_cleared))
    else:
        print(format_audit_summary(payload))
    return report_exit_code(payload)


def _corpus_build(args: argparse.Namespace) -> int:
    packages = tuple(args.packages) if args.packages else ("axios", "express")
    entries, reports = build_corpus(packages=packages)
    save_entries(entries, args.db_path) if args.db_path else save_entries(entries)
    for report in reports:
        print_attrition_report(report)
    print(f"Saved {len(entries)} corpus entries")
    return 0


def _corpus_stats(args: argparse.Namespace) -> int:
    entries = load_entries(args.db_path) if args.db_path else load_entries()
    packages = Counter(entry.package_name for entry in entries)
    confirmed = sum(entry.osv_confirmed for entry in entries)
    print(f"Corpus entries: {len(entries)}")
    print(f"OSV-confirmed:  {confirmed}")
    print(f"Corpus version: {corpus_fingerprint(entries)}")
    print("Packages:")
    for package, count in sorted(packages.items()):
        print(f"  {package}: {count}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "report":
        return _report(args)
    if args.corpus_command == "build":
        return _corpus_build(args)
    return _corpus_stats(args)


if __name__ == "__main__":
    raise SystemExit(main())
