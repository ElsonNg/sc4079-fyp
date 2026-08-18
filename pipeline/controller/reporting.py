"""Human-readable and machine-readable reporting for saved scan results."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

SEVERITY_ORDER = ("critical", "high", "moderate", "medium", "low", "info", "unknown")
ACTIVE_STATUSES = {"flagged", "manual_review"}
DIVIDER = "─" * 72


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


def _primary_advisory_verdict(result: dict[str, Any]) -> dict[str, Any] | None:
    verdicts = result.get("advisory_verdicts", [])
    if not verdicts:
        return None
    overall_status = result.get("status")
    return next(
        (verdict for verdict in verdicts if verdict.get("status") == overall_status),
        verdicts[0],
    )


def _best_evidence(result: dict[str, Any]) -> dict[str, Any] | None:
    evidence = result.get("evidence", [])
    if not evidence:
        return None
    verdict = _primary_advisory_verdict(result)
    if verdict:
        pair_ids = set(verdict.get("evidence_pair_ids", []))
        scoped = [item for item in evidence if item.get("pair_id") in pair_ids]
        if scoped:
            evidence = scoped
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
    verdict = _primary_advisory_verdict(result)
    if verdict:
        scoped = [
            match for match in matches
            if match.get("ghsa_id") == verdict.get("ghsa_id")
            and match.get("fix_commit_sha") == verdict.get("fix_commit_sha")
            and match.get("file_path") == verdict.get("file_path")
            and match.get("function_name") == verdict.get("function_name")
        ]
        if scoped:
            matches = scoped
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
        "advisory_verdicts": result.get("advisory_verdicts", []),
        "evidence": _best_evidence(result),
        "hash_match_types": result.get("hash_match_types", []),
        "message": result.get("message"),
        "review_explanation": finding.get("review_explanation"),
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


def final_metrics(report: dict[str, Any]) -> dict[str, Any]:
    summary = audit_summary(report)
    verdicts: Counter[str] = Counter()
    unavailable = 0
    attention_levels: Counter[str] = Counter()
    for finding in report.get("findings", []):
        status = _result(finding).get("status")
        if status not in ACTIVE_STATUSES:
            continue
        explanation = finding.get("review_explanation") or {}
        if status == "manual_review" and explanation.get("status") == "generated":
            verdicts[str(explanation.get("llm_verdict") or "needs_review")] += 1
        elif status == "manual_review" and explanation.get("status") == "unavailable":
            unavailable += 1

        if (
            status == "manual_review"
            and explanation.get("status") == "generated"
            and explanation.get("llm_verdict") == "dismissed"
        ):
            continue
        severity = str(finding_detail(finding).get("severity") or "unknown").lower()
        if severity in {"critical", "high"}:
            attention_levels["high"] += 1
        elif severity in {"low", "info"}:
            attention_levels["low"] += 1
        else:
            # Moderate/medium and unknown severities remain visible in the
            # middle bucket rather than being understated as low attention.
            attention_levels["medium"] += 1
    reviewed = sum(verdicts.values())
    manual_review = summary["manual_review"]
    return {
        "deterministic_flagged": summary["flagged"],
        "llm_escalated": verdicts["flagged"],
        "llm_dismissed": verdicts["dismissed"],
        "llm_needs_review": verdicts["needs_review"],
        "llm_unavailable": unavailable,
        "llm_unreviewed": max(0, manual_review - reviewed - unavailable),
        "llm_reviewed": reviewed,
        "manual_review": manual_review,
        "attention": {
            "high": attention_levels["high"],
            "medium": attention_levels["medium"],
            "low": attention_levels["low"],
        },
        "final_findings": sum(attention_levels.values()),
        "total_functions": summary["total_functions"],
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
    metrics = final_metrics(report)
    findings = summary["findings"]
    headline = (
        "✔ No vulnerability clone findings"
        if findings == 0
        else (
            f"✖ {findings} vulnerability clone finding(s) · "
            f"{metrics['final_findings']} requiring attention (!)"
        )
    )
    lines = [DIVIDER, "PROVTRAIL SCAN RESULT", DIVIDER, headline]
    lines.extend(["", "SCAN OVERVIEW"])
    lines.append(f"  functions analyzed:    {summary['total_functions']}")
    lines.append(f"  functions recomputed:  {summary['scanned_functions']}")
    lines.append(f"  functions reused:      {summary['reused_functions']}")
    lines.append(f"  changed files:         {summary['changed_files']}")
    lines.extend(["", DIVIDER, "RESULTS"])
    lines.append(f"  flagged:               {summary['flagged']}")
    lines.append(f"  manual review:         {summary['manual_review']}")
    lines.append(f"  cleared:               {summary['cleared']}")
    lines.append(f"  advisories:            {summary['unique_advisories']}")
    lines.extend(["", DIVIDER, "SEVERITY"])
    if summary["severity"]:
        for severity, count in summary["severity"].items():
            lines.append(f"  {severity:22s}{count}")
    else:
        lines.append("  none")
    lines.extend(["", DIVIDER, "FINAL METRICS"])
    lines.append(f"  Deterministic flagged: {metrics['deterministic_flagged']}")
    lines.append(f"  LLM escalated:         {metrics['llm_escalated']}")
    lines.append(f"  LLM dismissed:         {metrics['llm_dismissed']}")
    lines.append(f"  LLM needs review:      {metrics['llm_needs_review']}")
    lines.append(DIVIDER)
    return "\n".join(lines)


def format_attention(report: dict[str, Any]) -> str:
    metrics = final_metrics(report)
    attention = metrics["attention"]
    return "\n".join(
        [
            "ATTENTION",
            f"  High:                  {attention['high']}",
            f"  Medium:                {attention['medium']}",
            f"  Low:                   {attention['low']}",
            f"  Total:                 {metrics['final_findings']}",
            DIVIDER,
        ]
    )


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
        explanation = detail.get("review_explanation")
        if explanation:
            lines.append(f"  local explanation:      {explanation.get('status', 'unavailable')}")
            lines.append(f"    model:                {_display(explanation.get('model'))}")
            if explanation.get("status") == "generated":
                lines.append(f"    LLM verdict:          {_display(explanation.get('llm_verdict'))}")
                lines.append(f"    relevance tier:       {_display(explanation.get('relevance_tier'))} / 3")
                lines.append(f"    rationale:            {_display(explanation.get('verdict_rationale'))}")
                lines.append(f"    security mechanism:   {_display(explanation.get('security_mechanism'))}")
                lines.append(f"    review steps:         {_display(explanation.get('review_steps'))}")
            else:
                lines.append(f"    reason:               {_display(explanation.get('error_code'))}")
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
