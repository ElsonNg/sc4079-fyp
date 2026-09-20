"""Project actionable scan findings into SARIF and compact agent handoff text."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from provtrail.pipeline.controller.reporting import ACTIVE_PRIORITIES

SARIF_SCHEMA = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
RULES = {
    "automatic_vulnerability": ("provtrail/vulnerable-code", "error", "Vulnerable code clone"),
    "manual_review": ("provtrail/manual-review", "note", "Review possible vulnerable code clone"),
}


@dataclass(frozen=True)
class ExportFinding:
    path: str
    name: str
    start_line: int
    end_line: int
    priority: str
    advisory_ids: tuple[str, ...]
    packages: tuple[str, ...]
    confidence: str | None
    reason: str
    llm_verdict: str | None
    fingerprint: str


def _first_reason(result: dict[str, Any]) -> str:
    matches = [
        match for match in result.get("hash_matches") or []
        if match.get("side") == "vulnerable"
    ]
    if matches:
        kinds = sorted({str(match["match_type"]) for match in matches if match.get("match_type")})
        if kinds:
            return f"vulnerable-side {'/'.join(kinds)} hash match"
        return "vulnerable-side hash match"
    for state in result.get("vulnerability_states") or []:
        if state.get("status") == "vulnerable":
            return "vulnerable fix-boundary evidence"
    for state in result.get("vulnerability_states") or []:
        if state.get("abstention_reason"):
            return str(state["abstention_reason"]).lower().replace("_", " ")
    message = result.get("message")
    return str(message) if message else "candidate needs manual verification"


def project_findings(report: dict[str, Any]) -> list[ExportFinding]:
    """Use saved scan facts only, including review findings dismissed by Ollama."""
    projected = []
    for finding in report.get("findings", []):
        result = finding.get("result") or {}
        priority = result.get("priority")
        if priority not in ACTIVE_PRIORITIES:
            continue

        aliases = []
        for lineage in result.get("lineages") or []:
            aliases.extend(lineage.get("associated_advisories") or [])
        for state in result.get("vulnerability_states") or []:
            aliases.extend(state.get("advisories") or [])
        for match in result.get("hash_matches") or []:
            aliases.append(match)
            aliases.extend(match.get("advisories") or [])
        for aggregate in result.get("aggregates") or []:
            for match in aggregate.get("top_matches") or []:
                aliases.append(match)
                aliases.extend(match.get("advisories") or [])
        advisory_ids = tuple(sorted({
            str(alias[key])
            for alias in aliases
            for key in ("cve_id", "ghsa_id", "osv_id")
            if alias.get(key)
        }))

        packages = set()
        for application in result.get("package_applicabilities") or []:
            package = application.get("package")
            if package:
                packages.add(f"{package}:{application.get('status') or 'unknown'}")
        for alias in aliases:
            package = alias.get("package_name")
            if package and not any(item.startswith(f"{package}:") for item in packages):
                packages.add(f"{package}:unknown")

        confidences = {str(lineage.get("confidence")) for lineage in result.get("lineages") or []}
        confidence = next(
            (value for value in ("high", "medium", "low", "ambiguous") if value in confidences),
            None,
        )
        path = str(finding.get("path") or "").replace("\\", "/").lstrip("/")
        start = max(1, int(finding.get("start_line") or 0) + 1)
        end = max(start, int(finding.get("end_line") or 0) + 1)
        name = str(finding.get("name") or "<anonymous>")
        source_identity = finding.get("function_id") or f"{name}:{start}:{end}"
        identity = "|".join((
            priority, path, str(source_identity), str(finding.get("function_hash") or ""),
        ))
        fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        explanation = finding.get("review_explanation") or {}
        verdict = explanation.get("llm_verdict") if explanation.get("status") == "generated" else None
        projected.append(ExportFinding(
            path=path,
            name=name,
            start_line=start,
            end_line=end,
            priority=priority,
            advisory_ids=advisory_ids,
            packages=tuple(sorted(packages)),
            confidence=confidence,
            reason=_first_reason(result),
            llm_verdict=str(verdict) if verdict else None,
            fingerprint=fingerprint,
        ))
    return sorted(
        projected,
        key=lambda item: (item.path, item.start_line, item.end_line, item.priority, item.name),
    )


def build_sarif(report: dict[str, Any], *, tool_version: str) -> dict[str, Any]:
    findings = project_findings(report)
    root = Path(str(report.get("target_root") or ".")).resolve().as_uri().rstrip("/") + "/"
    results = []
    for finding in findings:
        rule_id, level, _ = RULES[finding.priority]
        details = f"{finding.name}: {finding.reason}"
        if finding.llm_verdict:
            details += f". Ollama verdict: {finding.llm_verdict}"
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": details},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": quote(finding.path, safe="/"), "uriBaseId": "%SRCROOT%"},
                "region": {"startLine": finding.start_line, "endLine": finding.end_line},
            }}],
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
            "properties": {"provtrail": {
                "priority": finding.priority,
                "advisoryIds": list(finding.advisory_ids),
                "packages": list(finding.packages),
                "confidence": finding.confidence,
                "reason": finding.reason,
                "llmVerdict": finding.llm_verdict,
            }},
        })
    rules = [{
        "id": rule_id,
        "name": rule_id.rsplit("/", 1)[-1],
        "shortDescription": {"text": description},
        "defaultConfiguration": {"level": level},
    } for rule_id, level, description in RULES.values()]
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ProvTrail", "version": tool_version, "rules": rules}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": root}},
            "results": results,
        }],
    }


def _single_line(value: str) -> str:
    return " ".join(str(value).split())


def format_ai(report: dict[str, Any]) -> str:
    """Group paths and omit code snippets to keep agent handoffs compact."""
    findings = project_findings(report)
    counts = Counter(item.priority for item in findings)
    lines = ["ProvTrail AI v1", f"root: {_single_line(str(report.get('target_root') or '.'))}"]
    directory = None
    for finding in findings:
        path = Path(finding.path)
        parent = path.parent.as_posix()
        if parent != directory:
            lines.append(f"{parent}/" if parent != "." else "./")
            directory = parent
        status = "VULN" if finding.priority == "automatic_vulnerability" else "REVIEW"
        parts = [f"  {path.name}:{finding.start_line}-{finding.end_line}", status]
        if finding.advisory_ids:
            parts.append("ids=" + ",".join(finding.advisory_ids))
        if finding.packages:
            parts.append("pkg=" + ",".join(finding.packages))
        if finding.confidence:
            parts.append("confidence=" + finding.confidence)
        parts.append("reason=" + _single_line(finding.reason))
        if finding.llm_verdict:
            parts.append("ollama=" + _single_line(finding.llm_verdict))
        lines.append(" ".join(parts))
    lines.append(
        f"total={len(findings)} vuln={counts['automatic_vulnerability']} "
        f"review={counts['manual_review']}"
    )
    return "\n".join(lines) + "\n"
