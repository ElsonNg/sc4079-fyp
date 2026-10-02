"""Persist human dismissals and refresh the existing offline scan artifacts."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from provtrail.cli.commands.exports import validate_paths, write_exports, write_text_atomic
from provtrail.pipeline.controller.html_reporting import (
    load_html_report_data, refresh_html_dismissals, write_html_report,
)
from provtrail.pipeline.controller.parsing import SUPPORTED_SOURCE_EXTENSIONS
from provtrail.pipeline.controller.reporting import load_scan_report
from provtrail.pipeline.models.result import RegionDetectionResult
from provtrail.pipeline.scanning.cache import DEFAULT_EXCLUDED_DIRS, _iter_tree_files
from provtrail.pipeline.scanning.discovery import _extract_file_functions
from provtrail.pipeline.scanning.dismissals import (
    ACTIVE_PRIORITIES, apply_dismissals, dismissal_lock, dismissal_path,
    finding_id, finding_signature, load_dismissals,
    make_dismissal, public_history, save_dismissals,
)
from provtrail.pipeline.scanning.project_context import build_project_evidence


def _source_path(root: Path, relative: str) -> Path:
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path == root:
        raise ValueError(f"Finding path is outside the project: {relative}")
    return path


def _live_context(root: Path, report: dict[str, Any], records: list[dict[str, Any]]) -> tuple[dict[str, str], dict[str, str]]:
    paths = {item["path"] for item in report.get("findings", [])}
    paths.update(record["finding"]["path"] for record in records)
    hashes = {}
    for relative in paths:
        path = _source_path(root, relative)
        if path.is_file():
            hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    js_files = [path.relative_to(root).as_posix() for path in _iter_tree_files(root, DEFAULT_EXCLUDED_DIRS)
                if path.suffix.lower() in SUPPORTED_SOURCE_EXTENSIONS]
    project = build_project_evidence(root, js_files)
    signatures = {}
    for item in report.get("findings", []):
        if (item.get("result") or {}).get("priority") not in ACTIVE_PRIORITIES:
            continue
        result = RegionDetectionResult.model_validate(item["result"])
        refreshed = project.assess(result, item["path"])
        signatures[item["function_id"]] = finding_signature({**item, "result": refreshed.model_dump(mode="json")})
    return hashes, signatures


def reconcile_saved_report(report: dict[str, Any], records: list[dict[str, Any]] | None = None) -> None:
    """Read current review decisions without running detection or changing evidence."""
    target = report.get("target_root")
    if not target or not Path(target).is_dir():
        return  # An exported historical report remains a standalone snapshot.
    root = Path(target).resolve()
    records = load_dismissals(root) if records is None else records
    if records:
        hashes, signatures = _live_context(root, report, records)
        apply_dismissals(report, records, file_hashes=hashes, context_signatures=signatures)
    else:
        apply_dismissals(report, [])


def _load_report(args) -> tuple[Path, Path, dict[str, Any]]:
    path = args.path.resolve()
    if path.is_file():
        if args.report is not None:
            raise ValueError("Use a project directory with --report, or pass the scan JSON directly")
        report_path = path
        report = load_scan_report(report_path)
        root = Path(report["target_root"]).resolve()
    else:
        root = path
        report_path = args.report or Path(".provtrail/latest-scan.json")
        if not report_path.is_absolute():
            report_path = root / report_path
        report = load_scan_report(report_path)
        if Path(report["target_root"]).resolve() != root:
            raise ValueError("The scan report belongs to another project; rescan this project")
    if not root.is_dir():
        raise ValueError(f"Project directory is unavailable: {root}")
    return root, report_path, report


def _select(values: list[dict[str, Any]], identity: str, key: str) -> dict[str, Any]:
    exact = [value for value in values if value.get(key) == identity]
    matches = exact or [value for value in values if len(identity) >= 8 and str(value.get(key) or "").startswith(identity)]
    if len(matches) != 1:
        raise ValueError("Finding ID is ambiguous; use the full ID" if matches else "Finding ID was not found; use the current report or provtrail dismissed")
    return matches[0]


def _artifacts(report_path: Path, report: dict[str, Any]) -> tuple[Path, Path | None, Path | None]:
    paths = report.get("artifacts") or {}
    html = Path(paths.get("html") or report_path.with_suffix(".html"))
    sarif = Path(paths["sarif"]) if paths.get("sarif") else None
    ai = Path(paths["ai"]) if paths.get("ai") else None
    root = Path(report["target_root"])
    validate_paths(sarif_path=sarif, ai_path=ai, reserved=(
        report_path, html, dismissal_path(root), dismissal_path(root).with_suffix(".lock"),
        Path(report.get("state_path") or root / ".provtrail/scan-state.json"),
    ), json_stdout=False)
    return html, sarif, ai


def _load_html(path: Path, report: dict[str, Any]) -> dict[str, Any] | None:
    if not path.exists():
        return None
    data = load_html_report_data(path)
    if data.get("root_hash") != report.get("root_hash"):
        raise ValueError("The HTML and JSON reports come from different scans; rescan to refresh both")
    return data


def run(args) -> int:
    saved = False
    try:
        root, report_path, report = _load_report(args)
        html_path, sarif_path, ai_path = _artifacts(report_path, report)
        html = _load_html(html_path, report)
        with dismissal_lock(root):
            records = load_dismissals(root)
            live_context = None
            if args.undo:
                selected = _select(records, args.finding, "id")
                records.remove(selected)
                identity = selected["id"]
            else:
                # Reject old reports and revalidate both code and dependency context.
                for item in report["findings"]:
                    item["finding_id"] = finding_id(item)
                if not any(item["finding_id"] for item in report["findings"]):
                    raise ValueError("This report has no file/function fingerprints; rescan with the current scanner")
                selected = _select(report["findings"], args.finding, "finding_id")
                if (selected.get("result") or {}).get("priority") not in ACTIVE_PRIORITIES:
                    raise ValueError("Only vulnerable matches and manual-review findings can be dismissed")
                hashes, signatures = _live_context(root, report, records)
                live_context = hashes, signatures
                if hashes.get(selected["path"]) != selected.get("file_hash"):
                    raise ValueError("The file changed since this scan; rescan before dismissing the finding")
                functions = _extract_file_functions(root, selected["path"])
                if not any(item["function_id"] == selected["function_id"] and item["function_hash"] == selected["function_hash"] for item in functions):
                    raise ValueError("The function changed since this scan; rescan before dismissing the finding")
                if signatures.get(selected["function_id"]) != finding_signature(selected):
                    raise ValueError("The dependency assessment changed since this scan; rescan before dismissing the finding")
                identity = selected["finding_id"]
                existing = next((record for record in records if record["id"] == identity), None)
                if existing is not None:
                    print(f"Already dismissed: {identity}")
                else:
                    snapshot = next((item for item in html["findings"] if item["id"] == selected["function_id"]), None) if html else None
                    records.append(make_dismissal(selected, args.reason or "", snapshot))
            if records:
                hashes, signatures = live_context or _live_context(root, report, records)
                apply_dismissals(report, records, file_hashes=hashes, context_signatures=signatures)
            else:
                apply_dismissals(report, [])
            if html is not None:
                refresh_html_dismissals(html, report)
            public = {**report, "dismissal_history": public_history(report["dismissal_history"])}
            save_dismissals(root, records)
            saved = True
            write_text_atomic(report_path, json.dumps(public, indent=2) + "\n")
            if html is not None:
                write_html_report(html_path, html)
            write_exports(public, sarif_path=sarif_path, ai_path=ai_path)
        print(f"{'Restored' if args.undo else 'Dismissed'}: {identity}")
        print(f"Updated scan report: {report_path}")
        if html is not None:
            print(f"Updated HTML artifact: {html_path} (reload the browser tab)")
        else:
            print("HTML artifact is unavailable; the next scan will regenerate it.")
        return 0
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        prefix = "Review decision saved, but artifact refresh failed" if saved else "Unable to update dismissal"
        print(f"{prefix}: {exc}", file=sys.stderr)
        return 2


def list_dismissed(args) -> int:
    try:
        root = args.path.resolve()
        requested = args.report or Path(".provtrail/latest-scan.json")
        report_path = requested if requested.is_absolute() else root / requested
        if root.is_dir() and not report_path.exists():
            records = load_dismissals(root)
            report = {"findings": []}
            hashes, _signatures = _live_context(root, report, records)
            apply_dismissals(report, records, file_hashes=hashes, scan_available=False)
        else:
            root, _report_path, report = _load_report(args)
            records = load_dismissals(root)
            reconcile_saved_report(report, records)
        history = public_history(report.get("dismissal_history", []))
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        print(f"Unable to list dismissals: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"schema": "provtrail_dismissed_v1", "dismissals": history}, indent=2))
    elif not history:
        print("No dismissed findings.")
    else:
        for row in history:
            print(f"{row['id']}  {row['status_label']}")
            print(f"  {row['path']}:{int(row.get('start_line') or 0) + 1}  {row.get('name') or '<anonymous>'}")
            print(f"  {row['dismissed_at']}  {row['reason'] or '(no reason recorded)'}")
            aliases = sorted({str(alias[key]) for alias in row["advisories"] for key in ("cve_id", "ghsa_id", "osv_id") if alias.get(key)})
            if aliases:
                print("  " + ", ".join(aliases))
        print(f"\n{sum(row['status'] == 'dismissed' for row in history)} still apply; {sum(row['status'] != 'dismissed' for row in history)} outdated.")
    return 0
