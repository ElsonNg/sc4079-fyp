"""Execute scan commands and render their command-line output."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from corpus.controller.store import load_entries
from pipeline.detection.config import RegionDetectorConfig, RegionVerifierConfig
from pipeline.controller.review_explanation import (
    OllamaExplanationConfig,
    enrich_manual_review_findings,
    explanation_progress,
)
from pipeline.scanning.scanner import (
    ScanConfig,
    build_default_detector_factory,
    corpus_fingerprint,
    scan_directory,
)
from pipeline.controller.reporting import (
    DIVIDER,
    format_attention,
    format_audit_summary,
    report_exit_code,
)
from pipeline.controller.html_reporting import build_html_report_data, write_html_report
from cli import PROVTRAIL_VERSION


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


def run(args: argparse.Namespace) -> int:
    # Build the detector and cache settings from CLI options.
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

    # scanning.scan_directory handles discovery, cache reuse, detection and project assessment.
    summary = scan_directory(
        args.path,
        entries=entries,
        config=scan_config,
        detector_factory=build_default_detector_factory(entries, detector_config),
        progress_callback=_scan_progress,
    )

    # Optionally explain findings after the scan has produced its decisions.
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

    # Write the structured and HTML reports from the same scan summary.
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

    # Render terminal output and choose the process exit code from the findings.
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
