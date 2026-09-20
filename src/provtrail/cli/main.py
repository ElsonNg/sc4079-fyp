"""Parse command-line arguments and dispatch ProvTrail commands."""

from __future__ import annotations

import argparse
import math
import os
import sys
from pathlib import Path

from provtrail.corpus.controller.snapshot import DEFAULT_SNAPSHOTS_DIR
from provtrail.corpus.controller.klaban import DEFAULT_KLABAN_PATH
from provtrail.pipeline.integrations.embedding import EMBEDDING_DEVICE_ENV
from provtrail.pipeline.detection.config import DEFAULT_MODEL_ID
from provtrail.pipeline.controller.region_retrieval import DEFAULT_REGION_EMBEDDINGS_DIR
from provtrail.pipeline.controller.retrieval import DEFAULT_EMBEDDINGS_DIR
from provtrail.pipeline.controller.review_explanation import (
    DEFAULT_OLLAMA_HOST,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_TIMEOUT,
)

from provtrail.cli import PROVTRAIL_VERSION
from provtrail.cli.commands.scan import run as _scan, _scan_progress
from provtrail.cli.commands.report import run as _report
from provtrail.cli.commands.corpus import (
    build as _corpus_build,
    probe as _corpus_probe,
    stats as _corpus_stats,
    index as _corpus_index,
    ingest_klaban as _corpus_ingest_klaban,
    _corpus_build_progress,
)


def _add_db_path(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db-path", type=Path, default=None, help="Corpus SQLite path")


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


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


def main(argv: list[str] | None = None) -> int:
    if os.name == "nt" and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
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
