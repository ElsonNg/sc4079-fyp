"""Execute report commands and render their command-line output."""

from __future__ import annotations

import argparse
import json
import sys

from provtrail.cli.commands.exports import validate_paths, write_exports

from provtrail.pipeline.controller.reporting import (
    format_audit_summary,
    format_verbose,
    load_scan_report,
    report_exit_code,
    report_view,
)


def run(args: argparse.Namespace) -> int:
    report_path = args.path
    if report_path.is_dir():
        report_path = report_path / ".provtrail" / "latest-scan.json"
    sarif_path = getattr(args, "sarif_output", None)
    ai_path = getattr(args, "ai_output", None)
    try:
        validate_paths(sarif_path=sarif_path, ai_path=ai_path, reserved=(report_path,), json_stdout=args.json)
    except ValueError as exc:
        print(f"Invalid output options: {exc}", file=sys.stderr)
        return 2
    try:
        payload = load_scan_report(report_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"Unable to read scan report: {exc}")
        return 2

    try:
        ai_stdout = write_exports(payload, sarif_path=sarif_path, ai_path=ai_path)
    except OSError as exc:
        print(f"Unable to write export: {exc}", file=sys.stderr)
        return 2

    if ai_stdout is not None:
        print(ai_stdout, end="")
    elif args.json:
        print(json.dumps(report_view(payload, include_informational=args.include_informational), indent=2))
    elif args.verbose:
        print(format_verbose(payload, include_informational=args.include_informational))
    else:
        print(format_audit_summary(payload))
    return report_exit_code(payload)
