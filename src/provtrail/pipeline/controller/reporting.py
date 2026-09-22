"""Human- and machine-readable views of the v5 scan result model."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from provtrail.pipeline.controller.report_evidence import (
    boundary_advisories, boundary_reason, decision_boundaries, primary_observation,
)
ACTIVE_PRIORITIES = {"automatic_vulnerability", "manual_review"}
ACTIVE_STATUSES = ACTIVE_PRIORITIES
DIVIDER = "─" * 72
SEVERITY_ORDER = ("critical", "high", "moderate", "medium", "low", "info", "unknown")


def load_scan_report(path: Path | str) -> dict[str, Any]:
    path = Path(path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema") != "provtrail_scan_v5":
        schema = payload.get("schema", "unknown") if isinstance(payload, dict) else "unknown"
        raise ValueError(
            f"Unsupported scan report schema {schema!r}; regenerate it with the current scanner"
        )
    if "findings" not in payload:
        raise ValueError(f"Not a provtrail scan report: {path}")
    return payload


def _result(finding: dict[str, Any]) -> dict[str, Any]:
    return finding.get("result", {})


def finding_detail(finding: dict[str, Any]) -> dict[str, Any]:
    result = _result(finding)
    boundaries = decision_boundaries(result)
    primary = boundaries[0] if boundaries else None
    advisories = boundary_advisories(boundaries)
    primary_advisories = primary.advisories if primary else []
    severity_order = {name: index for index, name in enumerate(SEVERITY_ORDER)}
    severity = min(
        (str(item.get("severity") or "unknown").lower() for item in primary_advisories),
        key=lambda value: severity_order.get(value, len(severity_order)),
        default="unknown",
    )
    return {
        "function_id": finding.get("function_id"), "path": finding.get("path"),
        "name": finding.get("name"), "node_type": finding.get("node_type"),
        "start_line": finding.get("start_line"), "end_line": finding.get("end_line"),
        "priority": result.get("priority", "none"), "severity": severity,
        "primary_lineage": primary.lineage if primary else None,
        "primary_boundary": primary.state if primary else None,
        "lineages": result.get("lineages", []),
        "vulnerability_states": result.get("vulnerability_states", []),
        "package_applicabilities": result.get("package_applicabilities", []),
        "advisories": advisories, "evidence": primary_observation(primary) if primary else None,
        "reason": boundary_reason(primary)[0],
        "hash_match_types": result.get("hash_match_types", []), "message": result.get("message"),
        "review_explanation": finding.get("review_explanation"),
    }


def audit_summary(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings", [])
    priorities = Counter(_result(item).get("priority", "none") for item in findings)
    active = [item for item in findings if _result(item).get("priority") in ACTIVE_PRIORITIES]
    severity_counts = Counter(finding_detail(item)["severity"] for item in active)
    advisories = {(alias.get("ghsa_id"), alias.get("cve_id"), alias.get("osv_id")) for item in active for alias in finding_detail(item)["advisories"]}
    return {
        "target_root": report.get("target_root"), "total_files": report.get("total_files", 0),
        "total_functions": report.get("total_functions", len(findings)),
        "scanned_functions": report.get("scanned_functions", 0), "reused_functions": report.get("reused_functions", 0),
        "findings": len(active), "automatic_vulnerability": priorities["automatic_vulnerability"],
        "manual_review": priorities["manual_review"], "informational_lineage": priorities["informational_lineage"],
        "none": priorities["none"], "unique_advisories": len(advisories),
        "severity": {name: severity_counts[name] for name in SEVERITY_ORDER if severity_counts[name]},
        "changed_files": len(report.get("changed_files", [])), "state_path": report.get("state_path"),
    }


def final_metrics(report: dict[str, Any]) -> dict[str, Any]:
    summary = audit_summary(report)
    verdicts, attention = Counter(), Counter()
    unavailable = 0
    for finding in report.get("findings", []):
        priority = _result(finding).get("priority")
        if priority not in ACTIVE_PRIORITIES:
            continue
        explanation = finding.get("review_explanation") or {}
        if priority == "manual_review" and explanation.get("status") == "generated":
            verdicts[str(explanation.get("llm_verdict") or "needs_review")] += 1
            if explanation.get("llm_verdict") == "dismissed":
                continue
        elif priority == "manual_review" and explanation.get("status") == "unavailable":
            unavailable += 1
        severity = finding_detail(finding)["severity"]
        attention["high" if severity in {"critical", "high"} else "low" if severity in {"low", "info"} else "medium"] += 1
    reviewed = sum(verdicts.values())
    return {
        "deterministic_automatic": summary["automatic_vulnerability"], "llm_escalated": verdicts["flagged"],
        "llm_dismissed": verdicts["dismissed"], "llm_needs_review": verdicts["needs_review"],
        "llm_unavailable": unavailable, "llm_unreviewed": max(0, summary["manual_review"] - reviewed - unavailable),
        "llm_reviewed": reviewed, "manual_review": summary["manual_review"],
        "attention": {name: attention[name] for name in ("high", "medium", "low")},
        "final_findings": sum(attention.values()), "total_functions": summary["total_functions"],
    }


def report_view(report: dict[str, Any], include_informational: bool = False) -> dict[str, Any]:
    details = [finding_detail(item) for item in report.get("findings", []) if include_informational or _result(item).get("priority") in ACTIVE_PRIORITIES]
    return {"schema": "provtrail_report_v2", "scan_report": report.get("schema", "unknown"), "audit": audit_summary(report), "findings": details}


def format_audit_summary(report: dict[str, Any]) -> str:
    summary = audit_summary(report)
    headline = "✔ No actionable findings" if not summary["findings"] else f"✖ {summary['findings']} finding(s) require attention"
    return "\n".join([
        DIVIDER, "PROVTRAIL SCAN RESULT", DIVIDER, headline, "", "SCAN OVERVIEW",
        f"  functions analyzed:      {summary['total_functions']}", f"  functions recomputed:    {summary['scanned_functions']}",
        f"  functions reused:        {summary['reused_functions']}", f"  changed files:           {summary['changed_files']}",
        "", DIVIDER, "RESULTS", f"  automatic vulnerability: {summary['automatic_vulnerability']}",
        f"  manual review:           {summary['manual_review']}", f"  informational lineage:   {summary['informational_lineage']}",
        f"  no lineage:              {summary['none']}", f"  advisories:              {summary['unique_advisories']}", DIVIDER,
    ])


def format_attention(report: dict[str, Any]) -> str:
    values = final_metrics(report)["attention"]
    return "\n".join(["ATTENTION", *(f"  {name.title():22s}{values[name]}" for name in ("high", "medium", "low")), DIVIDER])


def format_verbose(report: dict[str, Any], include_informational: bool = False) -> str:
    details = report_view(report, include_informational=include_informational)["findings"]
    lines = [format_audit_summary(report)]
    for index, detail in enumerate(details, 1):
        lines.extend(["", f"Finding {index}: {detail['priority'].upper()}", f"  location: {detail.get('path')}:{int(detail.get('start_line') or 0) + 1}"])
        for lineage in detail["lineages"]:
            lines.append(f"  lineage: {lineage['lineage_id']} ({lineage['confidence']}, {float(lineage['score']):.3f})")
        for state in detail["vulnerability_states"]:
            lines.append(f"  fix boundary: {state['fix_commit_sha']} — {state['status']} (contrast {float(state.get('contrast_score') or 0):.3f})")
        for application in detail["package_applicabilities"]:
            lines.append(f"  package: {application['package']} — {application['status']}")
    return "\n".join(lines)


def report_exit_code(report: dict[str, Any]) -> int:
    summary = audit_summary(report)
    return 1 if summary["automatic_vulnerability"] or summary["manual_review"] else 0
