"""Human-readable and machine-readable reporting for saved scan results."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

SEVERITY_ORDER = ("critical", "high", "moderate", "medium", "low", "info", "unknown")
ACTIVE_STATUSES = {"flagged", "manual_review"}


def load_scan_report(path: Path | str) -> dict[str, Any]:
    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or "findings" not in payload:
        raise ValueError(f"Not a provtrail scan report: {path}")
    return payload


def _result(finding: dict[str, Any]) -> dict[str, Any]:
    return finding.get("result", {})


def _match_key(match: dict[str, Any]) -> tuple[Any, ...]:
    return (
        match.get("ghsa_id"),
        match.get("cve_id"),
        match.get("fix_commit_sha"),
        match.get("file_path"),
        match.get("function_name"),
    )


def _normalise_match(match: dict[str, Any], source: str) -> dict[str, Any]:
    output = dict(match)
    output["source"] = source
    output.setdefault("cwes", [])
    output.setdefault("affected_versions", [])
    output.setdefault("fixed_versions", [])
    output.setdefault("severity", "unknown")
    return output


def _matches_for_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for match in result.get("hash_matches", []):
        matches.append(_normalise_match(match, "hash"))
    for aggregate in result.get("aggregates", []):
        for match in aggregate.get("top_matches", []):
            matches.append(_normalise_match(match, "region"))

    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for match in matches:
        key = _match_key(match)
        existing = unique.get(key)
        similarity = float(match.get("similarity", -1.0))
        if existing is None or similarity > float(existing.get("similarity", -1.0)):
            unique[key] = match
    return list(unique.values())


def _best_evidence(result: dict[str, Any]) -> dict[str, Any] | None:
    evidence = result.get("evidence", [])
    if not evidence:
        return None
    return max(
        evidence,
        key=lambda item: (
            float(item.get("vulnerable_minus_patched", 0.0)),
            float(item.get("vulnerable_score", 0.0)),
        ),
    )


def _primary_match(result: dict[str, Any], matches: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not matches:
        return None
    evidence = _best_evidence(result)
    if evidence is not None:
        pair_id = evidence.get("pair_id")
        pair_matches = [match for match in matches if match.get("pair_id") == pair_id]
        if pair_matches:
            return max(pair_matches, key=lambda item: float(item.get("similarity", -1.0)))
    return max(matches, key=lambda item: float(item.get("similarity", -1.0)))


def finding_detail(finding: dict[str, Any]) -> dict[str, Any]:
    result = _result(finding)
    matches = _matches_for_result(result)
    primary = _primary_match(result, matches)
    return {
        "function_id": finding.get("function_id"),
        "path": finding.get("path"),
        "name": finding.get("name"),
        "node_type": finding.get("node_type"),
        "start_line": finding.get("start_line"),
        "end_line": finding.get("end_line"),
        "status": result.get("status", "unknown"),
        "provenance_confidence": result.get("provenance_confidence", "none"),
        "severity": (primary or {}).get("severity", "unknown"),
        "primary_match": primary,
        "advisories": matches,
        "evidence": _best_evidence(result),
        "hash_match_types": result.get("hash_match_types", []),
        "message": result.get("message"),
    }


def _advisory_key(match: dict[str, Any]) -> tuple[Any, ...]:
    return (match.get("ghsa_id"), match.get("cve_id"), match.get("fix_commit_sha"))


def audit_summary(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", [])
    statuses = Counter(_result(finding).get("status", "unknown") for finding in findings)
    active = [finding for finding in findings if _result(finding).get("status") in ACTIVE_STATUSES]
    severity_counts: Counter[str] = Counter()
    advisories: set[tuple[Any, ...]] = set()
    for finding in active:
        detail = finding_detail(finding)
        severity = str(detail.get("severity") or "unknown").lower()
        severity_counts[severity] += 1
        for match in detail["advisories"]:
            advisories.add(_advisory_key(match))

    ordered_severity = {
        severity: severity_counts[severity]
        for severity in SEVERITY_ORDER
        if severity_counts[severity]
    }
    return {
        "target_root": report.get("target_root"),
        "total_files": report.get("total_files", 0),
        "total_functions": report.get("total_functions", len(findings)),
        "scanned_functions": report.get("scanned_functions", 0),
        "reused_functions": report.get("reused_functions", 0),
        "findings": len(active),
        "flagged": statuses.get("flagged", 0),
        "manual_review": statuses.get("manual_review", 0),
        "cleared": statuses.get("cleared", 0),
        "unique_advisories": len(advisories),
        "severity": ordered_severity,
        "changed_files": len(report.get("changed_files", [])),
        "state_path": report.get("state_path"),
    }


def report_view(report: dict[str, Any], include_cleared: bool = False) -> dict[str, Any]:
    details = [
        finding_detail(finding)
        for finding in report.get("findings", [])
        if include_cleared or _result(finding).get("status") in ACTIVE_STATUSES
    ]
    return {
        "schema": "provtrail_report_v1",
        "scan_report": report.get("schema", "unknown"),
        "audit": audit_summary(report),
        "findings": details,
    }


def format_audit_summary(report: dict[str, Any]) -> str:
    summary = audit_summary(report)
    findings = summary["findings"]
    headline = "✔ No vulnerability clone findings" if findings == 0 else f"✖ {findings} vulnerability clone finding(s)"
    lines = [headline]
    lines.append(f"  flagged:               {summary['flagged']}")
    lines.append(f"  manual review:         {summary['manual_review']}")
    lines.append(f"  cleared:               {summary['cleared']}")
    lines.append(f"  unique advisories:     {summary['unique_advisories']}")
    lines.append("  severity:")
    if summary["severity"]:
        for severity, count in summary["severity"].items():
            lines.append(f"    {severity:18s} {count}")
    else:
        lines.append("    none")
    lines.append(f"  functions scanned:     {summary['total_functions']}")
    lines.append(f"  functions recomputed:  {summary['scanned_functions']}")
    lines.append(f"  functions reused:      {summary['reused_functions']}")
    lines.append(f"  changed files:         {summary['changed_files']}")
    return "\n".join(lines)


def _display(value: Any, fallback: str = "not recorded") -> str:
    if value is None or value == "" or value == []:
        return fallback
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


def format_verbose(report: dict[str, Any], include_cleared: bool = False) -> str:
    view = report_view(report, include_cleared=include_cleared)
    lines = [format_audit_summary(report)]
    details = view["findings"]
    if not details:
        lines.append("\nNo findings match the requested report scope.")
        return "\n".join(lines)

    for index, detail in enumerate(details, start=1):
        lines.append("")
        lines.append(f"Finding {index}: {str(detail['status']).upper()}")
        lines.append(
            f"  location:              {detail.get('path')}:{int(detail.get('start_line', 0)) + 1}-"
            f"{int(detail.get('end_line', 0)) + 1} ({detail.get('name') or '<anonymous>'})"
        )
        lines.append(f"  severity:              {detail.get('severity', 'unknown')}")
        lines.append(f"  provenance confidence:  {detail.get('provenance_confidence', 'none')}")
        if detail.get("evidence"):
            evidence = detail["evidence"]
            lines.append(f"  vulnerable score:       {float(evidence.get('vulnerable_score', 0.0)):.3f}")
            lines.append(f"  patched score:          {float(evidence.get('patched_score', 0.0)):.3f}")
            lines.append(f"  score margin:           {float(evidence.get('vulnerable_minus_patched', 0.0)):.3f}")
            lines.append(f"  retrieval similarity:   {float(evidence.get('retrieval_similarity', 0.0)):.3f}")
        advisories = detail.get("advisories", [])
        if not advisories:
            lines.append("  advisory metadata:      not recorded")
        else:
            for match in advisories:
                identifiers = [value for value in (match.get("cve_id"), match.get("ghsa_id"), match.get("osv_id")) if value]
                lines.append(f"  advisory:               {' / '.join(identifiers) or 'unknown advisory'}")
                lines.append(f"    package:              {_display(match.get('package_name'))} ({_display(match.get('ecosystem'))})")
                lines.append(f"    affected versions:    {_display(match.get('affected_versions'))}")
                lines.append(f"    fixed versions:       {_display(match.get('fixed_versions'))}")
                lines.append(f"    CWE:                  {_display([cwe.get('cwe_id', cwe) if isinstance(cwe, dict) else cwe for cwe in match.get('cwes', [])])}")
                lines.append(f"    repository:            {_display(match.get('repo'))}")
                lines.append(f"    fix commit:            {_display(match.get('fix_commit_sha'))}")
                if match.get("similarity") is not None:
                    lines.append(f"    retrieval rank/score:  {match.get('rank', '?')} / {float(match.get('similarity', 0.0)):.3f}")
    return "\n".join(lines)


def report_exit_code(report: dict[str, Any]) -> int:
    summary = audit_summary(report)
    return 1 if summary["flagged"] or summary["manual_review"] else 0
