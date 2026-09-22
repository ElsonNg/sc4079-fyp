"""Generate a portable, interactive HTML artifact for a provtrail scan."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from provtrail.corpus.models.corpus import CorpusEntry
from provtrail.pipeline.controller.region_extraction import enumerate_candidate_regions
from provtrail.pipeline.controller.reporting import ACTIVE_STATUSES, audit_summary, finding_detail
from provtrail.pipeline.controller.report_evidence import (
    ReportBoundary, boundary_reason, primary_observation, report_boundaries, supports_decision,
)
from provtrail.pipeline.scanning.scanner import ScanConfig, ScanSummary

MAX_EXCERPT_LINES = 120
SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "moderate": 2,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}
DEPENDENCY_SECTIONS = {
    "dependencies": "runtime",
    "devDependencies": "development",
    "peerDependencies": "peer",
    "optionalDependencies": "optional",
}


def _safe_url(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    parsed = urlparse(value)
    return value if parsed.scheme in {"http", "https"} and parsed.netloc else ""


def _entry_key(value: dict[str, Any] | CorpusEntry) -> tuple[Any, ...]:
    if isinstance(value, CorpusEntry):
        return value.advisory.ghsa_id, value.origin.fix_commit_sha, value.origin.file_path, value.origin.function_name
    return (
        value.get("ghsa_id"),
        value.get("fix_commit_sha"),
        value.get("file_path"),
        value.get("function_name"),
    )


def _identifier(match: dict[str, Any]) -> str:
    return str(match.get("cve_id") or match.get("ghsa_id") or match.get("osv_id") or "Unknown advisory")


def _version_values(values: Any) -> list[str]:
    """Normalize HTML entities present in some imported advisory version ranges."""
    if not isinstance(values, list):
        return []
    return [html.unescape(str(value)).replace("\xa0", " ") for value in values]


def _advisory_summary(value: Any) -> str:
    """Keep a complete leading Summary section, or the first Markdown block."""
    source = str(value or "").strip()
    if not source:
        return ""
    summary = re.match(
        r"\A(#{1,6}[ \t]+summary[^\n]*\r?\n[\s\S]*?)(?=\r?\n#{1,6}[ \t]+|\Z)",
        source,
        flags=re.IGNORECASE,
    )
    if summary:
        return summary.group(1).strip()
    blocks = [block.strip() for block in re.split(r"\r?\n\s*\r?\n", source) if block.strip()]
    if not blocks:
        return ""
    excerpt = blocks[0]
    if re.fullmatch(r"#{1,6}[ \t]+[^\n]+", excerpt) and len(blocks) > 1:
        excerpt = f"{excerpt}\n\n{blocks[1]}"
    return excerpt


def _project_dependencies(target_root: str) -> dict[str, Any]:
    """Read direct dependency declarations from the scanned project's root manifest."""
    manifest_path = Path(target_root) / "package.json"
    manifest_status = "missing"
    declared: dict[str, list[dict[str, str]]] = {}
    project_name: str | None = None
    project_version: str | None = None
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("package.json must contain an object")
            manifest_status = "loaded"
            project_name = str(manifest.get("name") or "").strip() or None
            project_version = str(manifest.get("version") or "").strip() or None
            for section, scope in DEPENDENCY_SECTIONS.items():
                values = manifest.get(section)
                if not isinstance(values, dict):
                    continue
                for name, version in values.items():
                    declared.setdefault(str(name), []).append(
                        {"scope": scope, "version": str(version)}
                    )
            bundled = manifest.get("bundledDependencies", manifest.get("bundleDependencies", []))
            if isinstance(bundled, list):
                for name in bundled:
                    declared.setdefault(str(name), []).append(
                        {"scope": "bundled", "version": "declared"}
                    )
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
            manifest_status = "invalid"
    return {
        "manifest": "package.json" if manifest_status != "missing" else None,
        "manifest_status": manifest_status,
        "declared": declared,
        "project_name": project_name,
        "project_version": project_version,
    }


def _target_package_context(
    target_root: str,
    relative_path: str,
    project: dict[str, Any],
) -> dict[str, Any]:
    """Resolve ownership of the scanned file independently from corpus provenance."""

    parts = Path(relative_path).parts
    if "node_modules" in parts:
        index = len(parts) - 1 - list(reversed(parts)).index("node_modules")
        package_parts = list(parts[index + 1 : index + 3])
        if package_parts:
            count = 2 if package_parts[0].startswith("@") and len(package_parts) > 1 else 1
            name = "/".join(package_parts[:count])
            manifest = Path(target_root) / Path(*parts[: index + 1 + count]) / "package.json"
            version = None
            try:
                payload = json.loads(manifest.read_text(encoding="utf-8"))
                if isinstance(payload, dict):
                    version = str(payload.get("version") or "").strip() or None
            except (OSError, UnicodeError, json.JSONDecodeError):
                pass
            return {
                "name": name,
                "version": version,
                "source": str(manifest.relative_to(target_root)),
                "status": "resolved",
            }
    if project.get("project_name"):
        return {
            "name": project["project_name"],
            "version": project.get("project_version"),
            "source": project.get("manifest"),
            "status": "resolved",
        }
    return {"name": None, "version": None, "source": None, "status": "unresolved"}


def _reference_lines(entry: CorpusEntry, patched: bool) -> set[int]:
    values: set[int] = set()
    for diagnostic in entry.diagnostic_lines:
        line = diagnostic.patched_line if patched else diagnostic.vulnerable_line
        if line is not None:
            values.add(int(line))
    return values


def _candidate_lines(finding: dict[str, Any], source: str, evidence: dict[str, Any]) -> set[int]:
    """Resolve the verified candidate region back to function-relative lines."""

    span = evidence.get("candidate_span") or {}
    if span.get("start_line") is not None and span.get("end_line") is not None:
        start = max(0, int(span["start_line"]))
        end = min(len(source.splitlines()), int(span["end_line"]) + 1)
        return set(range(start, end))

    region_id = evidence.get("candidate_region_id")
    if region_id:
        try:
            regions = enumerate_candidate_regions(
                source,
                candidate_id=str(finding.get("function_id") or ""),
                filename=finding.get("path"),
            )
            region = next(item.region for item in regions if item.region.region_id == region_id)
            return set(range(region.span.start_line, region.span.end_line + 1))
        except (StopIteration, ValueError):
            pass
    # Missing correspondence has no defensible local highlight.
    return set()


def _patch_changes(entry: CorpusEntry | None) -> dict[str, list[str]]:
    if entry is None:
        return {"removed": [], "added": []}
    return {
        "removed": [item.text for item in entry.diagnostic_lines if item.kind == "removed"],
        "added": [item.text for item in entry.diagnostic_lines if item.kind == "added"],
    }


def _excerpt(
    source: str,
    *,
    first_line: int = 1,
    focus_lines: set[int] | None = None,
    marker: str = "",
) -> dict[str, Any]:
    lines = source.splitlines()
    focus_lines = focus_lines or set()
    if len(lines) <= MAX_EXCERPT_LINES:
        start, end = 0, len(lines)
    else:
        anchor = min(focus_lines) if focus_lines else 0
        start = max(0, anchor - 24)
        end = min(len(lines), start + MAX_EXCERPT_LINES)
        start = max(0, end - MAX_EXCERPT_LINES)
    return {
        "lines": [
            {
                "number": first_line + index,
                "text": line,
                "marker": marker if index in focus_lines else "",
            }
            for index, line in enumerate(lines[start:end], start=start)
        ],
        "truncated": start > 0 or end < len(lines),
        "total_lines": len(lines),
        "first_line": first_line,
        "highlight_lines": sorted(first_line + index for index in focus_lines),
        "highlight_kind": marker,
        "full_source": source if start > 0 or end < len(lines) else None,
    }


def _enrich_match(match: dict[str, Any], entry: CorpusEntry | None) -> dict[str, Any]:
    output = dict(match)
    if entry is not None:
        output["advisory_title"] = output.get("advisory_title") or entry.advisory.advisory_title
        output["advisory_description"] = output.get("advisory_description") or entry.advisory.advisory_description
        output["advisory_url"] = output.get("advisory_url") or entry.advisory.advisory_url
        output["advisory_references"] = output.get("advisory_references") or entry.advisory.advisory_references
        output["affected_versions"] = output.get("affected_versions") or entry.advisory.affected_versions
        output["fixed_versions"] = output.get("fixed_versions") or entry.advisory.fixed_versions
        output["source_language"] = entry.origin.source_language
    output["affected_versions"] = _version_values(output.get("affected_versions"))
    output["fixed_versions"] = _version_values(output.get("fixed_versions"))
    output["advisory_summary"] = _advisory_summary(output.get("advisory_description"))
    output["patch_changes"] = _patch_changes(entry)
    output["advisory_url"] = _safe_url(output.get("advisory_url"))
    ghsa_id = str(output.get("ghsa_id") or "")
    if not output["advisory_url"] and re.fullmatch(r"GHSA-[A-Za-z0-9-]+", ghsa_id):
        output["advisory_url"] = f"https://github.com/advisories/{ghsa_id}"
    output["advisory_references"] = [
        url for url in (_safe_url(value) for value in output.get("advisory_references", [])) if url
    ]
    repo = str(output.get("repo") or "")
    sha = str(output.get("fix_commit_sha") or "")
    output["fix_url"] = _safe_url(f"https://github.com/{repo}/commit/{sha}") if repo and sha else ""
    output["identifier"] = _identifier(output)
    output["title"] = output.get("advisory_title") or output["identifier"]
    output["cwes"] = [
        cwe.get("cwe_id", "") if isinstance(cwe, dict) else str(cwe)
        for cwe in output.get("cwes", [])
    ]
    return output


# HTML and the LLM consume the same selected boundary and source correspondence.
def _enrich_boundary(
    boundary: ReportBoundary,
    finding: dict[str, Any],
    entries_by_key: dict[tuple[Any, ...], CorpusEntry],
) -> dict[str, Any]:
    lineage, state = boundary.lineage, boundary.state
    aliases = []
    entries = []
    for alias in boundary.advisories:
        match = {
            **alias,
            "lineage_id": lineage.get("lineage_id"),
            "fix_boundary_id": state.get("fix_boundary_id"),
            "repo": lineage.get("repo"),
            "fix_commit_sha": state.get("fix_commit_sha"),
            "file_path": lineage.get("file_path"),
            "function_name": lineage.get("reference_function"),
        }
        entry = entries_by_key.get(_entry_key(match))
        aliases.append(_enrich_match(match, entry))
        entries.append(entry)

    selected = next((index for index, entry in enumerate(entries) if entry is not None), 0)
    representative = aliases[selected] if aliases else {}
    entry = entries[selected] if entries else None
    observation = primary_observation(boundary)
    source = str(finding.get("source") or "")
    focus = _candidate_lines(finding, source, observation)
    if boundary.hash_matches:
        focus = set(range(len(source.splitlines())))
    reference = {
        "candidate": _excerpt(
            source, first_line=int(finding.get("start_line") or 0) + 1,
            focus_lines=focus, marker="detected",
        ) if source else None,
        "vulnerable": _excerpt(
            entry.vulnerable_function, focus_lines=_reference_lines(entry, patched=False), marker="removed",
        ) if entry else None,
        "patched": _excerpt(
            entry.patched_function, focus_lines=_reference_lines(entry, patched=True), marker="added",
        ) if entry else None,
    }
    reason, action = boundary_reason(boundary)
    return {
        "lineage": {key: lineage.get(key) for key in (
            "lineage_id", "confidence", "score", "repo", "file_path", "reference_function",
        )},
        "state": {key: value for key, value in state.items() if key not in {"advisories", "evidence_pair_ids"}},
        "advisories": aliases,
        "representative": representative,
        "reference": reference,
        "observation": observation,
        "hash_matches": [{key: match.get(key) for key in (
            "side", "match_type", "representation", "fix_boundary_id",
        )} for match in boundary.hash_matches],
        "supports_decision": supports_decision(boundary, finding.get("result", {}).get("priority", "none")),
        "reason": reason,
        "recommended_action": action,
    }


def _display_outcome(priority: str, boundary: ReportBoundary | None) -> str:
    if priority == "automatic_vulnerability":
        exact = boundary and any(
            item.get("match_type") == "exact" and item.get("side") == "vulnerable"
            and item.get("representation", "native") == "native"
            for item in boundary.hash_matches
        )
        return "flagged_exact" if exact else "flagged_inferred"
    return {"manual_review": "manual_review", "informational_lineage": "patched"}.get(priority, "none")


# One primary boundary drives the headline, comparison, diagnostics and review input.
def _build_finding(
    finding: dict[str, Any],
    entries_by_key: dict[tuple[Any, ...], CorpusEntry],
    target_root: str,
    project: dict[str, Any],
) -> dict[str, Any]:
    result = finding.get("result", {})
    detail = finding_detail(finding)
    selected = report_boundaries(result)
    boundaries = [_enrich_boundary(item, finding, entries_by_key) for item in selected]
    primary_boundary = boundaries[0] if boundaries else {}
    primary = primary_boundary.get("representative") or {
        "identifier": "No advisory recorded", "title": "No advisory metadata recorded",
        "severity": "unknown", "patch_changes": {"removed": [], "added": []},
    }
    reason, action = boundary_reason(selected[0] if selected else None)
    return {
        "id": str(finding.get("function_id") or ""),
        "path": str(finding.get("path") or "unknown"),
        "name": finding.get("name") or "<anonymous>",
        "source_language": finding.get("source_language") or "javascript",
        "start_line": int(finding.get("start_line") or 0) + 1,
        "end_line": int(finding.get("end_line") or 0) + 1,
        "priority": detail["priority"],
        "outcome": _display_outcome(detail["priority"], selected[0] if selected else None),
        "reason": reason,
        "recommended_action": action,
        "severity": detail["severity"],
        "confidence": (detail.get("primary_lineage") or {}).get("confidence", "none"),
        "primary": primary,
        "boundaries": boundaries,
        "target_package": _target_package_context(target_root, str(finding.get("path") or ""), project),
        "package_applicabilities": result.get("package_applicabilities") or [],
        "evidence": primary_boundary.get("observation") or {},
        "reference": primary_boundary.get("reference") or {},
        "parser_supported": result.get("parser_supported", True),
        "review_explanation": _report_review_explanation(finding.get("review_explanation"), primary.get("fix_boundary_id")),
    }


def _report_review_explanation(value: Any, fix_boundary_id: str | None) -> dict[str, Any] | None:
    """Keep only concise LLM fields needed by the self-contained report."""
    if not isinstance(value, dict):
        return None
    fields = (
        "status",
        "model",
        "generated_at",
        "fix_boundary_id",
        "relevance_tier",
        "llm_verdict",
        "verdict_rationale",
        "security_mechanism",
        "error_code",
    )
    output = {field: value[field] for field in fields if field in value}
    output["reference_matches"] = bool(fix_boundary_id and value.get("fix_boundary_id") == fix_boundary_id)
    return output


def build_html_report_data(
    summary: ScanSummary,
    *,
    entries: list[CorpusEntry],
    config: ScanConfig,
    generated_at: datetime | None = None,
    tool_version: str = "development",
) -> dict[str, Any]:
    """Normalize live scan data into the private payload embedded in the HTML file."""

    generated_at = generated_at or datetime.now().astimezone()
    entries_by_key = {_entry_key(entry): entry for entry in entries}
    project = _project_dependencies(summary.target_root)
    findings = [
        _build_finding(finding, entries_by_key, summary.target_root, project)
        for finding in summary.findings
    ]
    findings.sort(
        key=lambda item: (
            0 if item["priority"] == "automatic_vulnerability" else 1 if item["priority"] == "manual_review" else 2,
            SEVERITY_RANK.get(item["severity"], 5),
            item["path"],
            item["start_line"],
        )
    )
    active = [item for item in findings if item["priority"] in ACTIVE_STATUSES]
    outcome_counts = {
        name: sum(item["outcome"] == name for item in active)
        for name in ("flagged_exact", "flagged_inferred", "manual_review")
    }
    outcome_counts["patched"] = sum(item["outcome"] == "patched" for item in findings)
    public_payload = summary.to_dict()
    audit = audit_summary(public_payload)
    # The HTML artifact is intended to be shareable. Keep repository-relative
    # locations, but never embed workstation-specific absolute paths.
    audit.pop("target_root", None)
    audit.pop("state_path", None)
    return {
        "schema": "provtrail_html_report_v4",
        "project": Path(summary.target_root).name or "project",
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "tool_version": tool_version,
        "corpus_version": config.corpus_version,
        "coverage": {
            "corpus_entries": len(entries),
            "reference_packages": len({entry.advisory.package_name for entry in entries}),
            "unsupported_functions": sum(not item["parser_supported"] for item in findings),
            "languages": sorted({item["source_language"] for item in findings}),
        },
        "root_hash": summary.root_hash,
        "previous_root_hash": summary.previous_root_hash,
        "changed_files": summary.changed_files,
        "deleted_files": summary.deleted_files,
        "scanned_files": summary.scanned_files,
        "audit": audit,
        "outcome_counts": outcome_counts,
        "findings": findings,
        "explanation_run": summary.explanation_run,
        "config": {
            "model": config.detector.model_id,
            "retrieval_top_k": config.detector.retrieval_top_k,
            "retrieval_threshold": config.detector.retrieval_threshold,
            "minimum_structure_score": config.detector.verifier.minimum_structure_score,
            "minimum_token_score": config.detector.verifier.minimum_token_score,
            "minimum_edit_side_score": config.detector.verifier.minimum_edit_side_score,
            "minimum_edit_margin": config.detector.verifier.minimum_edit_margin,
        },
    }


def render_html_report(data: dict[str, Any]) -> str:
    """Render normalized report data as one dependency-free HTML document."""

    encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    encoded = encoded.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    title = html.escape(f"provtrail - {data.get('project', 'scan report')}", quote=True)
    resources = files("provtrail.pipeline.controller")
    template = resources.joinpath("report_template.html").read_text(encoding="utf-8")
    styles = resources.joinpath("report_styles.css").read_text(encoding="utf-8")
    script = resources.joinpath("report_view.js").read_text(encoding="utf-8")
    return (template.replace("__REPORT_STYLES__", styles).replace("__REPORT_SCRIPT__", script)
            .replace("__REPORT_TITLE__", title).replace("__REPORT_DATA__", encoded))


def write_html_report(path: Path | str, data: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(render_html_report(data), encoding="utf-8")
    temporary.replace(path)
