"""Execute report commands and render their command-line output."""

from __future__ import annotations

import argparse
import json

from pipeline.controller.reporting import (
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
