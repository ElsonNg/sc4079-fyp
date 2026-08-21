"""Generate a portable, interactive HTML artifact for a provtrail scan."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from corpus.models.corpus import CorpusEntry
from pipeline.controller.region_extraction import enumerate_candidate_regions
from pipeline.controller.reporting import ACTIVE_STATUSES, audit_summary, final_metrics, finding_detail
from pipeline.controller.scanning import ScanConfig, ScanSummary

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
        return value.ghsa_id, value.fix_commit_sha, value.file_path, value.function_name
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


def _dependency_report(findings: list[dict[str, Any]], target_root: str) -> dict[str, Any]:
    """Compare verified reference-package signals with target declarations."""
    project = _project_dependencies(target_root)
    libraries: dict[str, dict[str, Any]] = {}
    for finding in findings:
        seen_in_finding: set[str] = set()
        for lineage in finding.get("lineages", []):
            for reference in lineage.get("reference_packages", []):
                name = str(reference.get("name") or "").strip()
                if not name:
                    continue
                ecosystem = str(reference.get("ecosystem") or "unknown").strip() or "unknown"
                key = f"{ecosystem.lower()}:{name}"
                library = libraries.setdefault(
                    key,
                    {
                        "name": name,
                        "ecosystem": ecosystem,
                        "declarations": project["declared"].get(name, []),
                        "locations": set(),
                        "advisories": set(),
                        "lineages": set(),
                        "finding_ids": set(),
                    },
                )
                library["locations"].add(f"{finding['path']}:{finding['start_line']}")
                library["lineages"].add(lineage["lineage_id"])
                for advisory in lineage.get("advisories", []):
                    identifier = str(advisory.get("identifier") or _identifier(advisory)).strip()
                    if identifier and identifier != "Unknown advisory":
                        library["advisories"].add(identifier)
                if key not in seen_in_finding:
                    library["finding_ids"].add(finding["id"])
                    seen_in_finding.add(key)

    output = []
    for library in libraries.values():
        declarations = library["declarations"]
        output.append(
            {
                "name": library["name"],
                "ecosystem": library["ecosystem"],
                "package_url": (
                    f"https://www.npmjs.com/package/{quote(library['name'], safe='@/')}"
                    if library["ecosystem"].lower() == "npm"
                    else ""
                ),
                "status": "declared_reference" if declarations else "unresolved_reference",
                "declarations": declarations,
                "evidence_count": len(library["finding_ids"]),
                "locations": sorted(library["locations"]),
                "advisories": sorted(library["advisories"]),
                "lineage_count": len(library["lineages"]),
            }
        )
    output.sort(key=lambda item: (item["status"] == "declared_reference", item["name"].lower()))
    return {
        "manifest": project["manifest"],
        "manifest_status": project["manifest_status"],
        "detected_count": len(output),
        "unresolved_count": sum(item["status"] == "unresolved_reference" for item in output),
        # Compatibility for existing report consumers; this now means an
        # undeclared reference signal, never a proven installed dependency.
        "ghost_count": sum(item["status"] == "unresolved_reference" for item in output),
        "libraries": output,
    }


def _reference_lines(entry: CorpusEntry, patched: bool) -> set[int]:
    values: set[int] = set()
    for diagnostic in entry.diagnostic_lines:
        line = diagnostic.patched_line if patched else diagnostic.vulnerable_line
        if line is not None:
            values.add(int(line))
    return values


def _candidate_lines(finding: dict[str, Any], source: str, evidence: dict[str, Any]) -> set[int]:
    """Resolve the verified candidate region back to function-relative lines."""

    region_id = evidence.get("candidate_region_id")
    if region_id:
        try:
            regions = enumerate_candidate_regions(
                source,
                candidate_id=str(finding.get("function_id") or ""),
            )
            region = next(item.region for item in regions if item.region.region_id == region_id)
            return set(range(region.span.start_line, region.span.end_line + 1))
        except (StopIteration, ValueError):
            pass
    # Hash matches apply to the complete function. Unsupported/ambiguous findings
    # without a localized region likewise need the whole excerpt called out.
    return set(range(len(source.splitlines())))


def _patch_changes(entry: CorpusEntry | None) -> dict[str, list[str]]:
    if entry is None:
        return {"removed": [], "added": []}
    return {
        "removed": [item.text for item in entry.diagnostic_lines if item.kind == "removed"][:8],
        "added": [item.text for item in entry.diagnostic_lines if item.kind == "added"][:8],
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
    }


def _enrich_match(match: dict[str, Any], entry: CorpusEntry | None) -> dict[str, Any]:
    output = dict(match)
    if entry is not None:
        output["advisory_title"] = output.get("advisory_title") or entry.advisory_title
        output["advisory_description"] = output.get("advisory_description") or entry.advisory_description
        output["advisory_url"] = output.get("advisory_url") or entry.advisory_url
        output["advisory_references"] = output.get("advisory_references") or entry.advisory_references
        output["affected_versions"] = output.get("affected_versions") or entry.affected_versions
        output["fixed_versions"] = output.get("fixed_versions") or entry.fixed_versions
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


def _enrich_lineage(
    lineage: dict[str, Any],
    entries_by_key: dict[tuple[Any, ...], CorpusEntry],
    target_package: dict[str, Any],
    states: list[dict[str, Any]],
    applications: list[dict[str, Any]],
) -> dict[str, Any]:
    output = {
        key: lineage.get(key)
        for key in (
            "lineage_id", "confidence", "score", "repo", "file_path",
            "reference_function", "evidence_pair_ids",
        )
    }
    lineage_states = [item for item in states if item.get("lineage_id") == lineage.get("lineage_id")]
    state_options = lineage_states or [{}]
    advisory_options = lineage.get("associated_advisories") or [{}]
    representative_raw: dict[str, Any] = {}
    representative_entry = None
    for state in state_options:
        for advisory in advisory_options:
            candidate = {
                **advisory,
                "lineage_id": lineage.get("lineage_id"),
                "repo": lineage.get("repo"),
                "fix_commit_sha": state.get("fix_commit_sha"),
                "file_path": lineage.get("file_path"),
                "function_name": lineage.get("reference_function"),
            }
            entry = entries_by_key.get(_entry_key(candidate))
            if entry is not None:
                representative_raw, representative_entry = candidate, entry
                break
        if representative_entry is not None:
            break
    if not representative_raw:
        representative_raw = {
            **advisory_options[0],
            "lineage_id": lineage.get("lineage_id"),
            "repo": lineage.get("repo"),
            "fix_commit_sha": state_options[0].get("fix_commit_sha"),
            "file_path": lineage.get("file_path"),
            "function_name": lineage.get("reference_function"),
        }
    representative = _enrich_match(representative_raw, representative_entry) if representative_raw else {}
    output["representative"] = representative
    output["reference"] = {
        "vulnerable": _excerpt(
            representative_entry.vulnerable_function,
            focus_lines=_reference_lines(representative_entry, patched=False),
            marker="vulnerable",
        ) if representative_entry is not None else None,
        "patched": _excerpt(
            representative_entry.patched_function,
            focus_lines=_reference_lines(representative_entry, patched=True),
            marker="patched",
        ) if representative_entry is not None else None,
    }

    advisories = []
    for value in lineage.get("associated_advisories", []):
        combined = {
            **representative_raw,
            **value,
            "lineage_id": lineage.get("lineage_id"),
            "repo": lineage.get("repo") or representative_raw.get("repo"),
            "fix_commit_sha": representative_raw.get("fix_commit_sha"),
            "file_path": lineage.get("file_path") or representative_raw.get("file_path"),
            "function_name": lineage.get("function_name") or representative_raw.get("function_name"),
        }
        entry = entries_by_key.get(_entry_key(combined))
        advisories.append(_enrich_match(combined, entry))
    output["advisories"] = advisories
    output["reference_packages"] = sorted({
        (value.get("package_name"), value.get("ecosystem") or "npm")
        for value in lineage.get("associated_advisories", []) if value.get("package_name")
    })
    output["reference_packages"] = [
        {"name": name, "ecosystem": ecosystem} for name, ecosystem in output["reference_packages"]
    ]
    lineage_apps = [item for item in applications if item.get("lineage_id") == lineage.get("lineage_id")]
    app_statuses = {item.get("status") for item in lineage_apps}
    output["package_applicability"] = (
        "confirmed" if "confirmed" in app_statuses else
        "conflicting" if "conflicting" in app_statuses else "unknown"
    )
    output["status"] = (
        "vulnerable" if any(item.get("status") == "vulnerable" for item in lineage_states) else
        "uncertain" if any(item.get("status") == "uncertain" for item in lineage_states) else "patched"
    )
    output["provenance_confidence"] = lineage.get("confidence", "none")
    output["target_package"] = target_package
    return output


def _display_outcome(priority: str, result: dict[str, Any]) -> str:
    if priority == "automatic_vulnerability":
        exact_vulnerable = any(
            item.get("match_type") == "exact" and item.get("side") == "vulnerable"
            for item in result.get("hash_matches", [])
        )
        return "flagged_exact" if exact_vulnerable else "flagged_inferred"
    if priority == "manual_review":
        return "manual_review"
    if priority == "informational_lineage":
        return "patched"
    return "none"


def _decision_copy(outcome: str, result: dict[str, Any]) -> tuple[str, str]:
    evidence = result.get("evidence", []) or []
    supporting = {
        item.get("candidate_region_id") for item in evidence
        if item.get("candidate_region_id") and float(item.get("vulnerable_minus_patched") or 0) > 0
    }
    if outcome == "flagged_exact":
        return (
            "The function exactly matches the vulnerable side of a known fix boundary.",
            "Apply the upstream security fix or replace this copied implementation with the patched version.",
        )
    if outcome == "flagged_inferred":
        count = len(supporting)
        support = f"{count} independent region{'s' if count != 1 else ''}" if count else "independent structural evidence"
        verb = "favours" if count in {0, 1} else "favour"
        return (
            f"{support.capitalize()} strongly {verb} the vulnerable implementation over the patched implementation.",
            "Compare this code with the upstream fix and apply the missing security control.",
        )
    if outcome == "manual_review":
        return (
            "The code lineage is credible, but the vulnerable and patched evidence cannot be resolved confidently.",
            "Review the highlighted code against the upstream patch before accepting or dismissing this finding.",
        )
    if outcome == "patched":
        return (
            "The code is related to a known lineage and the patched-side evidence is stronger.",
            "No action is required for this fix boundary unless project context contradicts the detected state.",
        )
    return (
        "No credible vulnerable-code lineage was retained.",
        "No action is required from this scan result.",
    )


def _build_finding(
    finding: dict[str, Any],
    entries_by_key: dict[tuple[Any, ...], CorpusEntry],
    target_root: str,
    project: dict[str, Any],
) -> dict[str, Any]:
    detail = finding_detail(finding)
    target_package = _target_package_context(
        target_root,
        str(finding.get("path") or ""),
        project,
    )
    lineages = [
        _enrich_lineage(
            lineage, entries_by_key, target_package,
            detail.get("vulnerability_states", []), detail.get("package_applicabilities", []),
        )
        for lineage in detail.get("lineages", [])
    ]
    primary_lineage_id = str((detail.get("primary_lineage") or {}).get("lineage_id") or "")
    primary_lineage = next(
        (lineage for lineage in lineages if lineage.get("lineage_id") == primary_lineage_id),
        lineages[0] if lineages else {},
    )
    primary_raw = (primary_lineage.get("representative") if primary_lineage else {}) or {}
    primary_entry = entries_by_key.get(_entry_key(primary_raw)) if primary_raw else None
    primary = _enrich_match(primary_raw, primary_entry) if primary_raw else {
        "identifier": "No advisory recorded",
        "title": "No advisory metadata recorded",
        "severity": "unknown",
        "cwes": [],
        "advisory_url": "",
        "fix_url": "",
        "affected_versions": [],
        "fixed_versions": [],
    }
    evidence = detail.get("evidence") or {}
    priority = str(detail.get("priority") or "none")
    candidate_source = str(finding.get("source") or "") if priority in ACTIVE_STATUSES else ""
    result = finding.get("result", {})
    if candidate_source:
        for lineage in lineages:
            pair_ids = set(lineage.get("evidence_pair_ids") or [])
            scoped_evidence = [
                item for item in (result.get("evidence", []) or [])
                if item.get("pair_id") in pair_ids
            ]
            focus_lines: set[int] = set()
            for item in scoped_evidence:
                focus_lines.update(_candidate_lines(finding, candidate_source, item))
            if not focus_lines and any(
                item.get("lineage_id") == lineage.get("lineage_id")
                for item in (result.get("hash_matches", []) or [])
            ):
                focus_lines = set(range(len(candidate_source.splitlines())))
            lineage.setdefault("reference", {})["candidate"] = _excerpt(
                candidate_source,
                first_line=int(finding.get("start_line") or 0) + 1,
                focus_lines=focus_lines,
                marker="detected",
            )
    outcome = _display_outcome(priority, result)
    reason, recommended_action = _decision_copy(outcome, result)
    start_line = int(finding.get("start_line") or 0) + 1
    reference = {
        "candidate": _excerpt(
            candidate_source,
            first_line=start_line,
            focus_lines=_candidate_lines(finding, candidate_source, evidence),
            marker="detected",
        ) if candidate_source else None,
        "vulnerable": None,
        "patched": None,
    }
    if primary_entry is not None and priority in ACTIVE_STATUSES:
        reference["vulnerable"] = _excerpt(
            primary_entry.vulnerable_function,
            focus_lines=_reference_lines(primary_entry, patched=False),
            marker="vulnerable",
        )
        reference["patched"] = _excerpt(
            primary_entry.patched_function,
            focus_lines=_reference_lines(primary_entry, patched=True),
            marker="patched",
        )
    return {
        "id": str(finding.get("function_id") or ""),
        "path": str(finding.get("path") or "unknown"),
        "name": finding.get("name") or "<anonymous>",
        "node_type": finding.get("node_type") or "function",
        "start_line": start_line,
        "end_line": int(finding.get("end_line") or 0) + 1,
        "priority": priority,
        "status": priority,
        "outcome": outcome,
        "reason": reason,
        "recommended_action": recommended_action,
        "severity": str(detail.get("severity") or "unknown").lower(),
        "confidence": str((detail.get("primary_lineage") or {}).get("confidence") or "none"),
        "message": detail.get("message") or "",
        "primary": primary,
        "lineages": lineages,
        "target_package": target_package,
        "attribution_status": (
            "single_lineage" if len(lineages) == 1
            else "multiple_lineages" if len(lineages) > 1
            else "unresolved"
        ),
        "evidence": evidence,
        "diagnostics": {
            "candidate_region_count": result.get("candidate_region_count", 0),
            "retrieval_match_count": result.get("retrieval_match_count", 0),
            "evidence_count": len(result.get("evidence", []) or []),
            "supporting_region_count": len({
                item.get("candidate_region_id") for item in result.get("evidence", [])
                if item.get("candidate_region_id")
                and float(item.get("vulnerable_minus_patched") or 0) > 0
            }),
            "contradicting_region_count": len({
                item.get("candidate_region_id") for item in result.get("evidence", [])
                if item.get("candidate_region_id")
                and float(item.get("vulnerable_minus_patched") or 0) < 0
            }),
            "aggregates": [
                {
                    "pair_id": item.get("pair_id"),
                    "lineage_id": item.get("lineage_id"),
                    "best_similarity": item.get("best_similarity"),
                    "support_count": item.get("support_count"),
                }
                for item in (result.get("aggregates", []) or [])[:10]
            ],
            "hash_matches": [
                {
                    "match_type": item.get("match_type"),
                    "side": item.get("side"),
                    "lineage_id": item.get("lineage_id"),
                    "fix_boundary_id": item.get("fix_boundary_id"),
                }
                for item in result.get("hash_matches", [])
            ],
            "vulnerability_states": [
                {
                    key: item.get(key)
                    for key in (
                        "lineage_id", "fix_boundary_id", "fix_commit_sha", "status",
                        "vulnerable_score", "patched_score", "contrast_score",
                        "fix_signature_coverage", "vulnerable_signature_coverage",
                        "fix_evidence", "contradictions",
                    )
                }
                for item in result.get("vulnerability_states", [])
            ],
            "package_applicabilities": [
                {
                    "lineage_id": item.get("lineage_id"),
                    "package": item.get("package"),
                    "ecosystem": item.get("ecosystem"),
                    "status": item.get("status"),
                }
                for item in result.get("package_applicabilities", [])
            ],
        },
        "hash_match_types": detail.get("hash_match_types", []),
        "reference": reference,
        "parser_supported": result.get("parser_supported", True),
        "review_explanation": _report_review_explanation(finding.get("review_explanation")),
    }


def _report_review_explanation(value: Any) -> dict[str, Any] | None:
    """Keep only concise LLM fields needed by the self-contained report."""
    if not isinstance(value, dict):
        return None
    fields = (
        "status",
        "model",
        "generated_at",
        "relevance_tier",
        "llm_verdict",
        "verdict_rationale",
        "security_mechanism",
        "error_code",
    )
    return {field: value[field] for field in fields if field in value}


def _llm_dismissed(finding: dict[str, Any]) -> bool:
    explanation = finding.get("review_explanation") or {}
    return (
        finding.get("priority") == "manual_review"
        and explanation.get("status") == "generated"
        and explanation.get("llm_verdict") == "dismissed"
    )


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
    public_payload = summary.to_dict()
    audit = audit_summary(public_payload)
    metrics = final_metrics(public_payload)
    # The HTML artifact is intended to be shareable. Keep repository-relative
    # locations, but never embed workstation-specific absolute paths.
    audit.pop("target_root", None)
    audit.pop("state_path", None)
    return {
        "schema": "provtrail_html_report_v3",
        "project": Path(summary.target_root).name or "project",
        "generated_at": generated_at.isoformat(timespec="seconds"),
        "tool_version": tool_version,
        "corpus_version": config.corpus_version,
        "root_hash": summary.root_hash,
        "previous_root_hash": summary.previous_root_hash,
        "changed_files": summary.changed_files,
        "deleted_files": summary.deleted_files,
        "scanned_files": summary.scanned_files,
        "audit": audit,
        "results": {"final_metrics": metrics},
        "outcome_counts": outcome_counts,
        "findings": findings,
        "explanation_run": summary.explanation_run,
        "config": {
            "model": config.detector.model_id,
            "retrieval_top_k": config.detector.retrieval_top_k,
            "retrieval_threshold": config.detector.retrieval_threshold,
            "minimum_vulnerable_score": config.detector.verifier.minimum_vulnerable_score,
            "minimum_margin": config.detector.verifier.minimum_margin,
        },
    }


def render_html_report(data: dict[str, Any]) -> str:
    """Render normalized report data as one dependency-free HTML document."""

    encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    encoded = encoded.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")
    title = html.escape(f"provtrail - {data.get('project', 'scan report')}", quote=True)
    template = Path(__file__).with_name("report_template.html").read_text(encoding="utf-8")
    return template.replace("__REPORT_TITLE__", title).replace("__REPORT_DATA__", encoded)


def write_html_report(path: Path | str, data: dict[str, Any]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(render_html_report(data), encoding="utf-8")
    temporary.replace(path)


_TEMPLATE = r'''<!doctype html>
<html lang="en" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>__REPORT_TITLE__</title>
<style>
:root{--paper:#f4f6f9;--surface:#fff;--surface-2:#edf1f6;--ink:#142033;--muted:#687386;--line:#d8dee8;--navy:#253b5b;--red:#b93832;--red-bg:#fbeceb;--amber:#94620d;--amber-bg:#fff4d8;--location-bg:#fff8cf;--teal:#13736a;--teal-bg:#e5f5f2;--focus:#315bd8;--focus-bg:#e9efff;--shadow:0 10px 30px rgba(20,32,51,.08)}
[data-theme="dark"]{--paper:#10151d;--surface:#171e28;--surface-2:#202a36;--ink:#edf2f8;--muted:#a8b3c2;--line:#344151;--navy:#b9c9df;--red:#ff918a;--red-bg:#402423;--amber:#f2c66d;--amber-bg:#3c321c;--location-bg:#37311c;--teal:#73d7ca;--teal-bg:#183a37;--focus:#8ba7ff;--focus-bg:#243453;--shadow:0 12px 34px rgba(0,0,0,.28)}
*{box-sizing:border-box}html{background:var(--paper);color:var(--ink);font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}body{margin:0;min-width:320px}button,input,select{font:inherit;color:inherit}button{cursor:pointer}.shell{max-width:1560px;margin:auto;padding:24px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:24px;margin-bottom:22px}.brand{display:flex;align-items:center}.wordmark{margin:0;color:var(--teal);font-size:24px;line-height:1.1;font-weight:700;letter-spacing:-.04em}.actions{display:flex;gap:8px}.icon-btn,.btn,.back-btn{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:var(--surface);border-radius:5px;padding:9px 12px;font-weight:750}.icon-btn:hover,.btn:hover,.back-btn:hover{background:var(--surface-2)}:focus-visible{outline:3px solid var(--focus);outline-offset:2px}.outcome{background:var(--surface);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow);padding:22px;margin-bottom:16px}.outcome-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}.outcome h2{font-size:29px;letter-spacing:-.04em;margin:0 0 8px;font-weight:650}.muted{color:var(--muted)}.scan-meta{display:flex;align-items:center;gap:9px;flex-wrap:wrap;font-size:13px}.scan-state{font-weight:800}.notice{max-width:520px;font-size:13px;line-height:1.5;margin:0}.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-top:22px}.tab{border:0;background:transparent;padding:11px 16px;font-weight:800;color:var(--muted);border-radius:5px 5px 0 0}.tab[aria-selected="true"]{background:var(--surface);color:var(--ink);box-shadow:inset 0 -3px var(--navy)}.panel{display:none}.panel.active{display:block}.workspace{display:grid;grid-template-columns:minmax(270px,32%) 1fr;min-height:600px;background:var(--surface);border:1px solid var(--line);border-radius:0 0 8px 8px}.explorer{padding:16px;border-right:1px solid var(--line);overflow:auto;max-height:calc(100vh - 270px)}.pane{padding:24px;min-width:0;overflow:hidden}.section-title{font-size:14px;color:var(--ink);font-weight:850;margin:0 0 12px}.icon{width:17px;height:17px;flex:0 0 auto;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.tree details{padding-inline-start:12px}.tree summary{display:flex;align-items:center;gap:6px;list-style:none;padding:5px 4px;font-size:13px;font-weight:750;cursor:pointer}.tree summary::-webkit-details-marker{display:none}.tree summary::before{content:"▸";display:inline-block;width:12px;color:var(--muted)}.tree details[open]>summary::before{content:"▾"}.folder-open{display:none}.tree details[open]>summary .folder-open{display:block}.tree details[open]>summary .folder-closed{display:none}.tree-file{width:100%;display:flex;align-items:center;gap:7px;border:0;background:transparent;border-radius:4px;padding:6px 7px 6px 19px;text-align:left;font-size:13px}.tree-file:hover,.tree-file.selected{background:var(--surface-2)}.tree-file.unaffected{color:var(--muted)}.file-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tree-counts{margin-inline-start:auto;display:inline-flex;align-items:center;gap:7px}.count-marker{display:inline-flex;align-items:center;gap:3px;font-size:11px;font-weight:850;white-space:nowrap}.count-marker .icon{width:13px;height:13px}.count-marker.flagged{color:var(--red)}.count-marker.llm_escalate{color:var(--amber)}.count-marker.manual_review{color:var(--focus)}.count-marker.llm_dismissed{color:var(--muted)}.badge{display:inline-flex;align-items:center;gap:5px;border-radius:3px;padding:3px 6px;font-size:11px;font-weight:850;white-space:nowrap}.badge.flagged,.badge.critical,.badge.high{color:var(--red);background:var(--red-bg)}.badge.manual_review,.badge.moderate,.badge.medium{color:var(--amber);background:var(--amber-bg)}.badge.cleared,.badge.low{color:var(--teal);background:var(--teal-bg)}.badge.unknown,.badge.none{background:var(--surface-2);color:var(--muted)}.file-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px}.file-title{display:flex;align-items:flex-start;gap:10px}.file-heading h2{font-size:23px;margin:3px 0 5px;overflow-wrap:anywhere;font-weight:650}.overview-files{display:grid;gap:8px;margin-top:18px}.overview-file{display:flex;align-items:center;gap:9px;width:100%;border:1px solid var(--line);background:var(--surface);border-radius:5px;padding:11px;text-align:left;font-weight:750}.overview-file:hover{background:var(--surface-2)}.finding-card{border:1px solid var(--line);border-radius:7px;margin:0 0 18px;overflow:hidden}.finding-head{padding:16px 18px;background:var(--surface-2);display:flex;justify-content:space-between;gap:14px}.finding-head h3{font-size:17px;margin:4px 0}.finding-body{padding:18px}.badge-row,.link-row{display:flex;gap:7px;flex-wrap:wrap;align-items:center}.advisory-heading{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:0 0 14px}.advisory-heading h3{margin:0;font-size:18px}.advisory-heading-id{font-weight:900}.advisory-id-link{color:inherit;font-weight:800;text-decoration:underline;text-underline-offset:3px}.code-compare{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:12px;align-items:start}.reference-stack{display:grid;gap:12px}.code-panel{border:1px solid var(--line);border-radius:5px;overflow:hidden;min-width:0}.code-label{display:flex;justify-content:space-between;padding:8px 10px;background:var(--surface-2);font-size:11px;font-weight:850;text-transform:uppercase;letter-spacing:.06em}.code{margin:0;max-height:380px;overflow:auto;background:#111820;color:#e8edf5;padding:9px 0;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.code-line{display:grid;grid-template-columns:46px max-content;min-width:100%;width:max-content;padding:0 10px}.code-line.detected{background:#263a62}.code-line.vulnerable{background:#502b2b}.code-line.patched{background:#17423c}.line-no{color:#9aa7b8;text-align:right;padding-right:12px;user-select:none}.line-text{white-space:pre}.truncate{font-size:11px;color:var(--muted);padding:7px 10px;background:var(--surface-2)}.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:18px}.detail-box{border:1px solid var(--line);border-radius:5px;padding:14px}.detail-box h4{margin:0 0 11px;font-size:14px}.facts{display:grid;grid-template-columns:max-content 1fr;gap:7px 13px;font-size:13px}.facts dt{color:var(--muted)}.facts dd{margin:0;overflow-wrap:anywhere}.score{display:grid;grid-template-columns:100px 1fr 42px;gap:8px;align-items:center;margin:8px 0;font-size:12px}.bar{height:8px;background:var(--surface-2);border-radius:999px;overflow:hidden}.bar-fill{height:100%;background:var(--navy)}.bar-fill.patch{background:var(--teal)}a{color:var(--focus);text-underline-offset:3px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:14px;background:var(--surface);border:1px solid var(--line);border-top:0}.control{border:1px solid var(--line);background:var(--surface);border-radius:5px;padding:9px 10px}.toolbar select.control{padding-right:34px}.search{min-width:270px;flex:1}.table-wrap{overflow:auto;border:1px solid var(--line);border-top:0;background:var(--surface)}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:11px 13px;border-bottom:1px solid var(--line)}th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}tr[data-file]{cursor:pointer}tr[data-file]:hover{background:var(--surface-2)}.recommendations{display:grid;gap:14px;padding-top:16px}.recommendation{background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:20px;min-width:0}.recommendation h3{margin:7px 0 8px}.recommendation-grid{display:grid;grid-template-columns:fit-content(300px) minmax(0,1fr);gap:18px;margin-top:16px}.recommendation-grid>div{min-width:0}.version-box{background:var(--surface-2);border-radius:5px;padding:13px;overflow-wrap:anywhere}.version-box+.version-box{margin-top:8px}.version-box strong{display:block;margin-top:3px}.affected-locations{margin-top:16px;background:var(--location-bg);border-radius:5px;padding:13px}.affected-locations h4{margin:0 0 8px}.patch-lines{display:grid;gap:7px}.patch-line{display:grid;grid-template-columns:86px minmax(0,1fr);gap:10px;align-items:start;padding:9px 11px;border-radius:4px}.patch-line strong{font-size:12px}.patch-line code{overflow:auto;background:transparent;color:inherit;padding:1px 0;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.patch-line.removed{background:var(--red-bg);color:var(--red)}.patch-line.added{background:var(--teal-bg);color:var(--teal)}.locations{display:grid;gap:4px}.location{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;padding:3px 0;overflow-wrap:anywhere}.empty{display:grid;place-items:center;min-height:320px;text-align:center;padding:30px}.empty strong{font-size:22px}.details{margin-top:16px;background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:12px 14px}.details summary{cursor:pointer;font-weight:800}.scan-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:14px;font-size:12px}.scan-grid div{overflow-wrap:anywhere}.scan-grid span{display:block;color:var(--muted);margin-bottom:3px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:1000px){.workspace{grid-template-columns:1fr}.explorer{border-right:0;border-bottom:1px solid var(--line);max-height:280px}.code-compare,.detail-grid,.recommendation-grid{grid-template-columns:1fr}}
@media(max-width:650px){.shell{padding:12px}.topbar,.outcome-head,.file-heading{flex-direction:column}.outcome h2{font-size:24px}.pane{padding:15px}.tabs{overflow:auto}.search{min-width:100%}.scan-grid{grid-template-columns:1fr}.actions{width:100%}.actions button{flex:1}}
@media(prefers-reduced-motion:no-preference){.panel.active{animation:appear .16s ease-out}@keyframes appear{from{opacity:.5;transform:translateY(3px)}to{opacity:1;transform:none}}}
.explorer{height:calc(100vh - 270px);min-height:600px;overflow-y:scroll;scrollbar-gutter:stable;scrollbar-color:var(--muted) var(--surface-2);scrollbar-width:auto}.explorer::-webkit-scrollbar{width:12px}.explorer::-webkit-scrollbar-track{background:var(--surface-2)}.explorer::-webkit-scrollbar-thumb{background:var(--muted);border:3px solid var(--surface-2);border-radius:8px}.metric.flagged strong,.metric.critical strong,.metric.high strong{color:var(--red)}.metric.manual_review strong,.metric.moderate strong,.metric.medium strong{color:var(--amber)}.metric.low strong{color:var(--teal)}.code-compare{height:720px}.code-panel{display:flex;flex-direction:column}.detected-panel{height:720px}.reference-stack{height:720px;grid-template-rows:repeat(2,minmax(0,1fr))}.reference-stack .code-panel{min-height:0}.code-panel .code{flex:1;max-height:none}.bar-fill.vulnerable{background:var(--red)}.bar-fill.patched{background:var(--teal)}.bar-fill.retrieval{background:var(--focus)}
.top-details{margin:-10px 0 15px;background:transparent;border:0;border-radius:0;padding:0}.top-details summary{display:inline-block;color:var(--muted);font-size:13px;font-weight:750;text-decoration:underline;text-underline-offset:4px}.top-details .scan-grid{background:var(--surface);border:1px solid var(--line);border-radius:5px;padding:14px}.report-date{font-size:15px;font-weight:750;margin:0}
.outcome .top-details{margin:8px 0 0}
.outcome .top-details summary{color:var(--focus);background:transparent;border-radius:0;padding:0}.report-label{margin-left:8px;color:#111820;font-size:24px;line-height:1.1;font-weight:700;letter-spacing:-.04em}[data-theme="dark"] .report-label{color:var(--ink)}.recommendation>.badge-row{padding-bottom:14px}.recommendation-summary{line-height:1.6}.recommendation-summary.collapsed{max-height:10em;overflow:hidden}.summary-toggle{display:inline-flex;margin-top:16px;border:0;background:transparent;color:var(--focus);padding:0;font-weight:inherit;text-decoration:underline;text-underline-offset:3px}.markdown-body{font-size:14px;overflow-wrap:anywhere}.markdown-body>:first-child{margin-top:0}.markdown-body>:last-child{margin-bottom:0}.markdown-body p{margin:0 0 10px}.markdown-body h4,.markdown-body h5,.markdown-body h6{margin:16px 0 7px;line-height:1.3}.markdown-body h4{font-size:15px}.markdown-body h5,.markdown-body h6{font-size:14px}.markdown-body ul,.markdown-body ol{margin:0 0 11px;padding-inline-start:22px}.markdown-body li+li{margin-top:4px}.markdown-body code{font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;background:var(--surface-2);border-radius:3px;padding:2px 4px}.markdown-body pre{margin:0 0 12px;padding:12px;overflow:auto;background:#111820;color:#e8edf5;border-radius:5px}.markdown-body pre code{padding:0;background:transparent;color:inherit;white-space:pre}.markdown-body blockquote{margin:0 0 12px;padding:10px 12px;background:var(--surface-2);color:var(--muted);border-radius:5px}.markdown-table-wrap{overflow:auto;margin:0 0 12px}.markdown-table{min-width:480px;border:1px solid var(--line)}.markdown-table th,.markdown-table td{padding:8px 10px}.markdown-table th{background:var(--surface-2)}
.report-label{margin-left:0}.badge.automatic_vulnerability{color:var(--red);background:var(--red-bg)}.badge.informational_lineage{color:var(--teal);background:var(--teal-bg)}.badge.manual_review{color:var(--focus);background:var(--focus-bg)}.badge.llm_dismissed{color:var(--muted);background:var(--surface-2)}.badge.llm_escalate{color:var(--amber);background:var(--amber-bg)}.metric.manual_review strong{color:var(--focus)}.tree-file.flagged>.icon,.tree-file.flagged>.file-name{color:var(--red)}.tree-file.llm_dismissed,.tree summary.llm_dismissed{color:var(--muted)}.tree-file.llm_escalate,.tree summary.llm_escalate{color:var(--amber)}.finding-card>summary{list-style:none;cursor:pointer}.finding-card>summary::-webkit-details-marker{display:none}.finding-chevron{display:inline-flex;color:var(--muted);transition:transform .16s ease}.finding-card[open] .finding-chevron{transform:rotate(180deg)}
.overview-file{font-weight:400}.overview-file.llm_escalate .file-name{color:var(--amber)}
.advisory-intro{margin-bottom:16px}.advisory-intro .advisory-heading{margin:0}.advisory-summary{max-width:920px;margin:7px 0 0;color:var(--muted);font-size:13px;line-height:1.55}
.advisory-id-link{text-decoration:none}.advisory-id-link:hover{text-decoration:underline;text-underline-offset:3px}
.review-explanation{background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:15px;margin:0 0 14px}.review-explanation h4{margin:0;font-size:14px}.review-explanation p{line-height:1.5}.review-explanation-head{display:flex;align-items:center;justify-content:space-between;gap:12px}.llm-verdict{display:flex;align-items:center;gap:14px;margin:0 0 8px;padding:10px 12px;border:1px solid var(--line);border-radius:6px;background:var(--surface)}.llm-verdict strong{display:inline-flex;align-items:center;gap:6px;font-size:15px}.llm-verdict.flagged strong{color:var(--red)}.llm-verdict.needs_review strong{color:var(--focus)}.llm-verdict.dismissed strong{color:var(--teal)}.verdict-rationale{margin:10px 0}.review-explanation.dismissed .verdict-rationale{margin-bottom:0;color:var(--muted);font-size:12px}.review-explanation-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px}.review-explanation h5{margin:0 0 6px;font-size:12px}.review-explanation ul,.review-explanation ol{margin:0;padding-inline-start:20px;font-size:13px;line-height:1.5}.review-explanation-meta{color:var(--muted);font-size:11px}.review-explanation.unavailable p{margin:8px 0 0;color:var(--muted);font-size:13px}
.results-board{background:var(--surface);border:1px solid var(--line);border-radius:0 0 8px 8px;padding:28px}.results-heading{display:flex;align-items:flex-end;justify-content:space-between;gap:24px;margin-bottom:22px}.results-heading h2{margin:3px 0 5px;font-size:27px;letter-spacing:-.035em}.eyebrow{margin:0;color:var(--muted);font-size:11px;font-weight:900;letter-spacing:.1em;text-transform:uppercase}.attention-ledger{display:grid;grid-template-columns:1.25fr repeat(3,1fr);border:1px solid var(--line);background:var(--line);gap:1px}.attention-cell{background:var(--surface);padding:18px;min-height:108px;display:flex;flex-direction:column;justify-content:space-between}.attention-cell strong{font-size:31px;letter-spacing:-.045em;line-height:1}.attention-cell span{font-size:12px;font-weight:850;color:var(--muted)}.attention-total{background:var(--focus-bg);color:var(--ink)}.attention-total span{color:var(--muted)}.attention-high strong{color:var(--red)}.attention-medium strong{color:var(--amber)}.attention-low strong{color:var(--teal)}.result-ledgers{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-top:16px}.result-ledger{border:1px solid var(--line);border-radius:6px;padding:17px}.result-ledger h3{margin:0 0 5px;font-size:15px}.result-ledger-note{margin:0 0 14px;font-size:12px;color:var(--muted);line-height:1.45;min-height:35px}.result-list{margin:0}.result-row{display:flex;align-items:baseline;justify-content:space-between;gap:18px;padding:9px 0;border-top:1px solid var(--line)}.result-row dt{color:var(--muted);font-size:12px}.result-row dd{margin:0;font-size:17px;font-weight:850}.result-row.flagged dd{color:var(--red)}.result-row.review dd{color:var(--focus)}.result-row.escalated dd{color:var(--amber)}.result-row.dismissed dd{color:var(--muted)}
.dependencies-board{background:var(--surface);border:1px solid var(--line);border-radius:0 0 8px 8px;padding:28px;min-height:420px}.dependencies-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;margin-bottom:20px}.dependencies-heading h2{margin:0 0 6px;font-size:27px;letter-spacing:-.035em}.dependencies-heading p{margin:0;max-width:760px;line-height:1.55}.dependency-totals{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin-bottom:16px}.dependency-total{background:var(--surface);padding:15px}.dependency-total span{display:block;color:var(--muted);font-size:11px;font-weight:800;margin-bottom:5px}.dependency-total strong{font-size:22px;letter-spacing:-.03em}.dependency-total.ghost strong{color:var(--amber)}.dependency-table-wrap{overflow:auto;border:1px solid var(--line);border-radius:6px}.dependency-table{min-width:700px}.dependency-table th{background:var(--surface-2)}.dependency-name{font-weight:850}.dependency-meta{display:block;color:var(--muted);font-size:11px;margin-top:3px}.dependency-locations{display:grid;gap:4px}.dependency-location{font:11px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.dependency-footnote{margin:13px 0 0;color:var(--muted);font-size:12px;line-height:1.55}
.evidence-breakdown-trigger{display:inline-flex;margin-top:13px;border:0;background:transparent;color:var(--focus);padding:0;font-size:13px;font-weight:650;text-decoration:underline;text-underline-offset:3px}.evidence-dialog{width:min(960px,calc(100vw - 32px));max-height:min(88vh,900px);padding:0;border:1px solid var(--line);border-radius:8px;background:var(--surface);color:var(--ink);box-shadow:0 24px 80px rgba(10,20,34,.32)}.evidence-dialog::backdrop{background:rgba(10,20,34,.58)}.evidence-dialog-shell{display:flex;flex-direction:column;min-width:0;max-height:min(88vh,900px)}.evidence-dialog-head{flex:0 0 auto;display:flex;align-items:flex-start;justify-content:space-between;gap:20px;padding:20px 22px;border-bottom:1px solid var(--line);background:var(--surface)}.evidence-dialog-head h2{margin:3px 0 3px;font-size:22px;letter-spacing:-.025em}.dialog-close{border:1px solid var(--line);background:var(--surface);border-radius:5px;padding:8px 11px;font-weight:750}.dialog-close:hover{background:var(--surface-2)}.evidence-dialog-body{flex:1;min-height:0;padding:22px;overflow:auto}.breakdown-score-strip{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;border:1px solid var(--line);background:var(--line);margin-bottom:18px}.breakdown-score{background:var(--surface);padding:14px}.breakdown-score span{display:block;color:var(--muted);font-size:11px;font-weight:800;margin-bottom:5px}.breakdown-score strong{font-size:22px;letter-spacing:-.03em}.breakdown-score.vulnerable strong{color:var(--red)}.breakdown-score.patched strong{color:var(--teal)}.breakdown-score.margin strong{color:var(--amber)}.calculation-section{margin-top:20px}.calculation-section h3{margin:0 0 5px;font-size:15px}.calculation-section>p{margin:0 0 12px;line-height:1.5;font-size:13px}.calculation-table-wrap{overflow:auto;border:1px solid var(--line);border-radius:6px}.calculation-table{min-width:720px}.calculation-table th{background:var(--surface-2)}.calculation-table td:nth-child(n+2){font-variant-numeric:tabular-nums}.calculation-table th:nth-child(4),.calculation-table th:nth-child(6),.calculation-table td:nth-child(4),.calculation-table td:nth-child(6){background:var(--focus-bg);color:var(--ink);font-weight:850}.weight-note{display:block;color:var(--muted);font-size:11px;margin-top:2px}.breakdown-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:18px}.formula-card{border:1px solid var(--line);border-radius:6px;padding:15px}.formula-card h3{margin:0 0 7px;font-size:14px}.formula-card p{margin:0 0 8px;font-size:12px;line-height:1.5}.formula-card code{display:block;padding:9px;background:var(--surface-2);border-radius:4px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;overflow-wrap:anywhere}.decision-gate{margin-top:18px;padding:15px;border:1px solid var(--line);border-radius:6px;background:var(--focus-bg)}.decision-gate h3{margin:0 0 8px;font-size:14px}.decision-gate ul{margin:0;padding-inline-start:20px;font-size:12px;line-height:1.65}.breakdown-empty{padding:20px;background:var(--surface-2);border-radius:6px;line-height:1.55}
@media(max-width:1000px){.explorer{height:280px;min-height:0}.code-compare,.reference-stack,.detected-panel{height:auto}.code-panel .code{max-height:380px}.review-explanation-grid{grid-template-columns:1fr}}
@media(max-width:1000px){.result-ledgers{grid-template-columns:1fr 1fr}.attention-ledger{grid-template-columns:1fr 1fr}}
@media(max-width:650px){.results-board{padding:18px}.results-heading{align-items:flex-start}.result-ledgers{grid-template-columns:1fr}.attention-ledger{grid-template-columns:1fr 1fr}.attention-cell{min-height:92px;padding:14px}}
@media(max-width:650px){.dependencies-board{padding:18px}.dependencies-heading{display:block}.dependency-totals{grid-template-columns:1fr}.dependency-total{padding:13px}}
@media(max-width:700px){.evidence-dialog-head,.evidence-dialog-body{padding:16px}.breakdown-score-strip{grid-template-columns:1fr 1fr}.breakdown-grid{grid-template-columns:1fr}.equation{grid-template-columns:1fr;gap:4px}}
 .dependency-name{text-decoration:none}.dependency-name:hover{text-decoration:underline;text-underline-offset:3px}
.provenance-map{margin:0 0 18px;border:1px solid var(--line);border-radius:6px;overflow:hidden;background:var(--surface)}.provenance-root{display:flex;align-items:center;gap:11px;padding:13px 15px;background:var(--surface-2)}.provenance-root-node,.lineage-node{width:13px;height:13px;border:3px solid var(--surface);border-radius:50%;box-shadow:0 0 0 2px var(--navy);flex:0 0 auto}.provenance-root strong{display:block;font-size:13px}.provenance-root span{display:block;color:var(--muted);font:11px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.lineage-list{padding:0 15px 11px 37px}.lineage-branch{position:relative;border-left:2px solid var(--line);padding:10px 0 0 46px}.lineage-branch:last-child{padding-bottom:3px}.lineage-branch::before{content:"";position:absolute;left:0;top:25px;width:22px;border-top:2px solid var(--line)}.lineage-branch>summary{list-style:none;display:flex;align-items:flex-start;gap:10px;cursor:pointer}.lineage-branch>summary::-webkit-details-marker{display:none}.lineage-node{position:absolute;left:20px;top:19px;background:var(--surface);box-shadow:0 0 0 2px var(--focus)}.lineage-branch.vulnerable .lineage-node{box-shadow:0 0 0 2px var(--red)}.lineage-branch.uncertain .lineage-node{box-shadow:0 0 0 2px var(--amber)}.lineage-head{min-width:0;flex:1}.lineage-head strong{display:block;font-size:13px;overflow-wrap:anywhere}.lineage-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:3px;color:var(--muted);font:11px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.lineage-toggle{color:var(--muted);transition:transform .16s ease}.lineage-branch[open] .lineage-toggle{transform:rotate(180deg)}.lineage-body{margin:9px 0 0;padding:10px 12px;border-left:2px solid var(--surface-2);background:var(--surface-2);font-size:12px}.lineage-facts{display:grid;grid-template-columns:max-content 1fr;gap:5px 11px;margin:0}.lineage-facts dt{color:var(--muted)}.lineage-facts dd{margin:0;overflow-wrap:anywhere}.alias-list{display:grid;gap:5px;margin-top:9px}.alias-row{display:grid;grid-template-columns:minmax(130px,.65fr) minmax(0,1fr) max-content;align-items:start;gap:10px;padding-top:6px;border-top:1px solid var(--line)}.alias-row span{overflow-wrap:anywhere}.most-likely-badge{display:inline-flex;align-items:center;border:1px solid var(--focus);border-radius:999px;padding:2px 7px;color:var(--focus);background:var(--focus-bg);font-size:10px;font-weight:900;letter-spacing:.02em;white-space:nowrap}.applicability{font-weight:800}.applicability.confirmed{color:var(--teal)}.applicability.conflicting{color:var(--red)}.applicability.unknown,.applicability.unresolved{color:var(--amber)}.ranked-reference-note{margin:5px 0 0;color:var(--muted);font-size:12px}.association-count{font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:var(--muted)}
@media(max-width:650px){.lineage-list{padding-left:28px}.alias-row{grid-template-columns:1fr}.lineage-facts{grid-template-columns:1fr}.lineage-facts dt{margin-top:4px}}
.advisory-intro{margin-bottom:26px}.advisory-summary{margin-top:13px}.most-likely-label{color:var(--teal)}.provenance-map .lineage-list{padding-top:10px}.alias-row{display:block;padding:9px 10px;text-align:left}.alias-row.most-likely{background:var(--focus-bg)}.alias-copy{display:grid;gap:4px;justify-items:start;min-width:0}.alias-id{font-weight:850}.alias-title{color:var(--muted);line-height:1.45}.advisory-text-link{display:inline-flex;margin-top:13px;border:0;background:transparent;color:var(--focus);padding:0;font-size:13px;font-weight:650;text-decoration:underline;text-underline-offset:3px}
.most-likely-label.dismissed{color:var(--muted)}.detail-box.reference-detail{display:flex;flex-direction:column}.reference-actions{justify-content:space-between;margin:auto 0 0;padding-top:22px;gap:20px}.reference-actions .advisory-text-link{margin-top:0}.reference-actions .fix{margin-left:auto}
</style>
</head>
<body>
<main class="shell">
  <header class="topbar"><div class="brand"><h1 class="wordmark">provtrail</h1><span class="report-label">'s report</span></div><div class="actions"><button class="icon-btn" id="theme-toggle" aria-label="Switch color theme">Dark theme</button></div></header>
  <section class="outcome" aria-labelledby="outcome-title"><h2 id="outcome-title"></h2><p class="muted report-date" id="generated"></p><details class="top-details"><summary>Details</summary><div class="scan-grid" id="scan-details"></div></details></section>
  <nav class="tabs" aria-label="Report views"><button class="tab" data-tab="files" aria-selected="true">Files</button><button class="tab" data-tab="findings" aria-selected="false">Findings</button><button class="tab" data-tab="recommendations" aria-selected="false">Recommendations</button><button class="tab" data-tab="dependencies" aria-selected="false">Dependencies</button><button class="tab" data-tab="results" aria-selected="false">Results</button></nav>
  <section id="files" class="panel active"><div class="workspace"><aside class="explorer"><p class="section-title">Project Directory</p><div class="tree" id="tree"></div></aside><article class="pane" id="file-pane"></article></div></section>
  <section id="findings" class="panel"><div class="toolbar"><label class="sr-only" for="search">Search findings</label><input id="search" class="control search" type="search" placeholder="Search path, function, lineage, advisory, or package"><select id="status-filter" class="control" aria-label="Filter by priority"><option value="active">Needs attention</option><option value="automatic_vulnerability">Automatic vulnerability</option><option value="manual_review">Manual review</option><option value="informational_lineage">Informational lineage</option><option value="all">All analyzed</option></select><select id="severity-filter" class="control" aria-label="Filter by severity"><option value="all">All severities</option><option>critical</option><option>high</option><option>moderate</option><option>medium</option><option>low</option><option>unknown</option></select><span class="muted" id="result-count"></span></div><div class="table-wrap"><table><thead><tr><th>Priority</th><th>Severity</th><th>LLM Decision</th><th>Location</th><th>Function</th><th>Verified associations</th><th>Confidence</th></tr></thead><tbody id="finding-rows"></tbody></table></div></section>
  <section id="recommendations" class="panel"><div id="recommendation-list" class="recommendations"></div></section>
  <section id="dependencies" class="panel"><div class="dependencies-board"><header class="dependencies-heading"><div><h2>Reference Package Signals</h2><p class="muted">Packages attached to verified provenance lineages, compared with direct declarations. These are source references, not installed-package claims.</p></div></header><div id="dependency-content"></div></div></section>
  <section id="results" class="panel"><div class="results-board"><header class="results-heading"><h2>Scan Summary</h2></header><div id="results-content"></div></div></section>
</main>
<dialog id="evidence-dialog" class="evidence-dialog" aria-labelledby="evidence-dialog-title"><div class="evidence-dialog-shell"><header class="evidence-dialog-head"><div><p class="eyebrow">Detection evidence</p><h2 id="evidence-dialog-title">Score breakdown</h2><p class="muted" id="evidence-dialog-location"></p></div><form method="dialog"><button class="dialog-close" type="submit">Close</button></form></header><div class="evidence-dialog-body" id="evidence-dialog-body"></div></div></dialog>
<script id="provtrail-data" type="application/json">__REPORT_DATA__</script>
<script>
const report=JSON.parse(document.getElementById('provtrail-data').textContent);
const activeStatuses=new Set(['automatic_vulnerability','manual_review']);
const $=(q,root=document)=>root.querySelector(q);
const $$=(q,root=document)=>[...root.querySelectorAll(q)];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
function inlineMarkdown(value){
  const raw=String(value??'');let output='',cursor=0;
  const tokens=/`([^`\n]+)`|\[([^\]\n]+)\]\((https?:\/\/[^)\s]+)\)/g;let match;
  const emphasis=text=>esc(text).replace(/\*\*([^*\n]+)\*\*/g,'<strong>$1</strong>');
  while((match=tokens.exec(raw))){
    output+=emphasis(raw.slice(cursor,match.index));
    if(match[1]!==undefined)output+=`<code>${esc(match[1])}</code>`;
    else output+=`<a href="${esc(match[3])}" target="_blank" rel="noopener noreferrer">${emphasis(match[2])}</a>`;
    cursor=match.index+match[0].length;
  }
  return output+emphasis(raw.slice(cursor));
}
function markdown(value){
  const lines=String(value??'').replace(/\r\n?/g,'\n').split('\n');const blocks=[];let index=0;
  const cells=line=>line.trim().replace(/^\||\|$/g,'').split('|').map(cell=>cell.trim());
  const tableDivider=line=>/^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$/.test(line);
  while(index<lines.length){
    const line=lines[index];
    if(!line.trim()){index++;continue}
    if(/^\s*```/.test(line)){
      const language=line.trim().slice(3).trim();const code=[];index++;
      while(index<lines.length&&!/^\s*```/.test(lines[index]))code.push(lines[index++]);
      if(index<lines.length)index++;
      blocks.push(`<pre${language?` data-language="${esc(language)}"`:''}><code>${esc(code.join('\n'))}</code></pre>`);continue;
    }
    if(index+1<lines.length&&line.includes('|')&&tableDivider(lines[index+1])){
      const headings=cells(line);const rows=[];index+=2;
      while(index<lines.length&&lines[index].includes('|')&&lines[index].trim())rows.push(cells(lines[index++]));
      blocks.push(`<div class="markdown-table-wrap"><table class="markdown-table"><thead><tr>${headings.map(cell=>`<th>${inlineMarkdown(cell)}</th>`).join('')}</tr></thead><tbody>${rows.map(row=>`<tr>${headings.map((_,cellIndex)=>`<td>${inlineMarkdown(row[cellIndex]||'')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);continue;
    }
    const heading=line.match(/^\s*(#{1,6})\s+(.+)$/);
    if(heading){const level=Math.min(6,Math.max(4,heading[1].length+3));blocks.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);index++;continue}
    if(/^\s*>\s?/.test(line)){
      const quote=[];while(index<lines.length&&/^\s*>\s?/.test(lines[index]))quote.push(lines[index++].replace(/^\s*>\s?/,''));
      blocks.push(`<blockquote>${quote.map(inlineMarkdown).join('<br>')}</blockquote>`);continue;
    }
    const listMatch=line.match(/^\s*(?:[-*+]\s+|(\d+)[.)]\s+)/);
    if(listMatch){const ordered=Boolean(listMatch[1]),items=[];const itemPattern=ordered?/^\s*\d+[.)]\s+/:/^\s*[-*+]\s+/;
      while(index<lines.length&&itemPattern.test(lines[index]))items.push(lines[index++].replace(itemPattern,''));
      const tag=ordered?'ol':'ul';blocks.push(`<${tag}>${items.map(item=>`<li>${inlineMarkdown(item)}</li>`).join('')}</${tag}>`);continue;
    }
    const paragraph=[line.trim()];index++;
    while(index<lines.length&&lines[index].trim()&&!/^\s*(?:```|#{1,6}\s|>|[-*+]\s+|\d+[.)]\s+)/.test(lines[index])&&!(index+1<lines.length&&lines[index].includes('|')&&tableDivider(lines[index+1]))){paragraph.push(lines[index].trim());index++}
    blocks.push(`<p>${inlineMarkdown(paragraph.join(' '))}</p>`);
  }
  return blocks.join('');
}
const label=v=>String(v??'unknown').replaceAll('_',' ');
const flagIcon='<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 21V4m0 1h9l1.5 2L19 5v9h-9l-1.5-2L5 14"/></svg>';
const reviewIcon='<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9.8 9a2.3 2.3 0 1 1 3.6 1.9c-.9.6-1.4 1.1-1.4 2.1m0 3.5h.01"/></svg>';
const dismissIcon='<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m5 12 4 4L19 6"/></svg>';
const badge=(v,kind=v)=>{const icon=kind==='automatic_vulnerability'||kind==='llm_escalate'?flagIcon:kind==='manual_review'?reviewIcon:kind==='llm_dismissed'?dismissIcon:'';const text=kind==='automatic_vulnerability'?'Automatic vulnerability':kind==='manual_review'?'Review':kind==='llm_dismissed'?'LLM Dismissed':kind==='llm_escalate'?'LLM Escalate':label(v);return `<span class="badge ${esc(kind)}">${icon}${esc(text)}</span>`};
const icons={
  folderClosed:'<svg class="icon folder-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6.5h6l2 2h10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M3 9h18"/></svg>',
  folderOpen:'<svg class="icon folder-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7h6l2 2h9a2 2 0 0 1 1.9 2.6l-2 6A2 2 0 0 1 18 19H5a2 2 0 0 1-1.9-2.6L5 11h16"/></svg>',
  file:'<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5"/><path d="m9 13-2 2 2 2m4-4 2 2-2 2"/></svg>',
  back:'<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m15 18-6-6 6-6"/></svg>',
  chevron:'<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>'
};
const active=report.findings.filter(f=>activeStatuses.has(f.status));
const byFile=new Map();
for(const f of active){if(!byFile.has(f.path))byFile.set(f.path,[]);byFile.get(f.path).push(f)}
let selectedFile='';

function initSummary(){
  $('#outcome-title').textContent=report.project;
  updateGeneratedTime();
}
function renderResults(){
  const a=report.audit,m=report.results.final_metrics,attention=m.attention;
  const rows=items=>`<dl class="result-list">${items.map(([name,value,tone=''])=>`<div class="result-row ${esc(tone)}"><dt>${esc(name)}</dt><dd>${esc(value)}</dd></div>`).join('')}</dl>`;
  $('#results-content').innerHTML=`<section class="attention-ledger" aria-label="Findings requiring attention by priority"><div class="attention-cell attention-total"><span>Total requiring attention</span><strong>${esc(m.final_findings)}</strong></div><div class="attention-cell attention-high"><span>High</span><strong>${esc(attention.high)}</strong></div><div class="attention-cell attention-medium"><span>Medium</span><strong>${esc(attention.medium)}</strong></div><div class="attention-cell attention-low"><span>Low</span><strong>${esc(attention.low)}</strong></div></section><div class="result-ledgers"><section class="result-ledger"><h3>Scan Coverage</h3><p class="result-ledger-note">Work completed in this run, including incremental reuse.</p>${rows([['Functions analyzed',a.total_functions],['Functions recomputed',a.scanned_functions],['Functions reused',a.reused_functions],['Changed files',a.changed_files]])}</section><section class="result-ledger"><h3>Derived Priorities</h3><p class="result-ledger-note">Lineage, fix-boundary state, and package applicability combined.</p>${rows([['Automatic vulnerability',a.automatic_vulnerability,'flagged'],['Manual review',a.manual_review,'review'],['Informational lineage',a.informational_lineage],['No lineage',a.none],['Advisories',a.unique_advisories]])}</section><section class="result-ledger"><h3>Final Review Decisions</h3><p class="result-ledger-note">Deterministic findings and optional contextual reviews.</p>${rows([['Deterministic automatic',m.deterministic_automatic,'flagged'],['LLM escalated',m.llm_escalated,'escalated'],['LLM dismissed',m.llm_dismissed,'dismissed'],['LLM needs review',m.llm_needs_review,'review']])}</section></div>`;
}
function renderDependencies(){
  const d=report.dependencies||{manifest:null,manifest_status:'missing',detected_count:0,ghost_count:0,libraries:[]};
  const unresolved=d.libraries.filter(item=>item.status==='unresolved_reference');
  const manifest=d.manifest_status==='loaded'?d.manifest:d.manifest_status==='invalid'?'Invalid package.json':'No package.json found';
  const totals=`<div class="dependency-totals"><div class="dependency-total ghost"><span>Unresolved reference packages</span><strong>${esc(d.unresolved_count??d.ghost_count??0)}</strong></div><div class="dependency-total"><span>Verified package signals</span><strong>${esc(d.detected_count)}</strong></div><div class="dependency-total"><span>Declaration source</span><strong>${esc(manifest)}</strong></div></div>`;
  if(!unresolved.length){$('#dependency-content').innerHTML=`${totals}<div class="empty"><div><strong>No unresolved reference packages</strong><p class="muted">Every verified reference package is directly declared, or no package attribution was available.</p></div></div><p class="dependency-footnote">A reference package identifies corpus provenance. It does not prove ownership of the scanned file.</p>`;return}
  const rows=unresolved.map(item=>{
    const locations=item.locations.slice(0,3).map(value=>`<span class="dependency-location">${esc(value)}</span>`).join('');
    const remainder=item.locations.length>3?`<span class="dependency-meta">+${esc(item.locations.length-3)} more</span>`:'';
    const advisories=item.advisories.length?item.advisories.join(', '):'';
    const packageName=item.package_url?`<a class="dependency-name" href="${esc(item.package_url)}" target="_blank" rel="noopener noreferrer">${esc(item.name)}</a>`:`<span class="dependency-name">${esc(item.name)}</span>`;
    return `<tr><td>${packageName}<span class="dependency-meta">${esc(item.ecosystem)}</span></td><td>${esc(item.evidence_count)} finding${item.evidence_count===1?'':'s'}</td><td><div class="dependency-locations">${locations}${remainder}</div></td><td>${esc(advisories)}</td></tr>`
  }).join('');
  $('#dependency-content').innerHTML=`${totals}<div class="dependency-table-wrap"><table class="dependency-table"><thead><tr><th>Reference package</th><th>Verified findings</th><th>Scanned locations</th><th>Advisory aliases</th></tr></thead><tbody>${rows}</tbody></table></div><p class="dependency-footnote">* Resolve the target file's owning package and version before treating a reference package as affected.</p>`;
}
function updateGeneratedTime(){
  const element=$('#generated'),generated=new Date(report.generated_at),elapsed=Date.now()-generated.getTime();
  const exact=generated.toLocaleString();
  let value=exact;
  if(elapsed>=0&&elapsed<60_000)value='just now';
  else if(elapsed>=0&&elapsed<3_600_000){const minutes=Math.floor(elapsed/60_000);value=`${minutes} min${minutes===1?'':'s'} ago`}
  else if(elapsed>=0&&elapsed<86_400_000){const hours=Math.floor(elapsed/3_600_000);value=`${hours} hour${hours===1?'':'s'} ago`}
  element.textContent=`Generated ${value}`;
  element.title=`Generated ${exact}`;
}
function llmVerdict(finding){const explanation=finding.review_explanation;return explanation?.status==='generated'?explanation.llm_verdict||'':''}
function referencePresentation(finding){
  const verdict=llmVerdict(finding);
  if(finding.status==='automatic_vulnerability')return{title:'Attributed advisory:',lineage:'Credible code lineage',vulnerable:'Vulnerable-side reference',tone:'',highlight:true};
  if(verdict==='flagged')return{title:'Most Probable Candidate:',lineage:'Most Probable Candidate Lineage',vulnerable:'Most probable vulnerable reference',tone:'',highlight:true};
  if(verdict==='dismissed')return{title:'Closest Code Reference:',lineage:'Closest Code Reference',vulnerable:'Closest vulnerable code reference',tone:'dismissed',highlight:false};
  return{title:'Highest-Ranked Candidate:',lineage:'Highest-Ranked Candidate Lineage',vulnerable:'Highest-ranked vulnerable reference',tone:'',highlight:true}
}
function llmDecision(finding){
  if(finding.status!=='manual_review')return'<span class="muted">—</span>';
  const verdict=llmVerdict(finding);
  if(verdict==='dismissed')return `<span class="badge llm_dismissed">${dismissIcon}Dismissed</span>`;
  if(verdict==='flagged')return `<span class="badge llm_escalate">${flagIcon}Escalate</span>`;
  if(verdict==='needs_review')return `<span class="badge manual_review">${reviewIcon}Needs review</span>`;
  return'<span class="muted">—</span>'
}
function findingKind(finding){
  if(finding.status==='automatic_vulnerability')return'flagged';
  const verdict=llmVerdict(finding);
  if(verdict==='flagged')return'llm_escalate';
  if(verdict==='dismissed')return'llm_dismissed';
  return'manual_review'
}
function countMarkers(findings){
  const order=['flagged','llm_escalate','manual_review','llm_dismissed'],counts={};
  findings.forEach(f=>{const kind=findingKind(f);counts[kind]=(counts[kind]||0)+1});
  const meta={flagged:['Flagged',flagIcon],llm_escalate:['LLM escalated',flagIcon],manual_review:['Needs review',reviewIcon],llm_dismissed:['LLM dismissed',dismissIcon]};
  const markers=order.filter(kind=>counts[kind]).map(kind=>{const [title,icon]=meta[kind];return `<span class="count-marker ${kind}" title="${esc(`${counts[kind]} ${title}`)}"><span>${counts[kind]}</span>${icon}</span>`}).join('');
  return markers?`<span class="tree-counts">${markers}</span>`:''
}
function attentionStatus(findings){
  if(findings.some(f=>f.status==='automatic_vulnerability'))return'flagged';
  const reviews=findings.filter(f=>f.status==='manual_review');
  if(reviews.some(f=>llmVerdict(f)==='flagged'))return'llm_escalate';
  if(reviews.some(f=>llmVerdict(f)!=='dismissed'))return'manual_review';
  return reviews.length?'llm_dismissed':'cleared'
}
function fileStatus(path){return attentionStatus(byFile.get(path)||[])}
function branchStats(prefix){const findings=active.filter(f=>f.path.startsWith(prefix));return{findings,count:findings.length,status:attentionStatus(findings)}}
function buildTree(){
  const root={dirs:{},files:[]};
  for(const path of report.scanned_files){const parts=path.split('/');let node=root;for(const part of parts.slice(0,-1))node=node.dirs[part]??={dirs:{},files:[]};node.files.push(parts.at(-1))}
  const hasAffected=(node,prefix)=>node.files.some(name=>byFile.has(prefix+name))||Object.entries(node.dirs).some(([name,child])=>hasAffected(child,prefix+name+'/'));
  const render=(node,prefix='')=>{
    const dirs=Object.entries(node.dirs).sort(([a],[b])=>a.localeCompare(b)).map(([name,child])=>{const childPrefix=prefix+name+'/',stats=branchStats(childPrefix),affected=hasAffected(child,childPrefix);return `<details ${affected?'open':''}><summary class="${esc(stats.status)}">${icons.folderClosed}${icons.folderOpen}<span class="file-name">${esc(name)}</span>${countMarkers(stats.findings)}</summary>${render(child,childPrefix)}</details>`}).join('');
    const files=node.files.sort().map(name=>{const path=prefix+name,findings=byFile.get(path)||[],count=findings.length,status=fileStatus(path);return `<button class="tree-file ${count?'':'unaffected'} ${esc(status)} ${path===selectedFile?'selected':''}" data-path="${esc(path)}">${icons.file}<span class="file-name">${esc(name)}</span>${countMarkers(findings)}</button>`}).join('');
    return dirs+files;
  };
  $('#tree').innerHTML=render(root);
  $$('.tree-file').forEach(button=>button.addEventListener('click',()=>selectFile(button.dataset.path)));
}
function codePanel(title,snippet,panelClass=''){
  if(!snippet)return `<div class="code-panel ${esc(panelClass)}"><div class="code-label"><span>${esc(title)}</span></div><div class="empty"><span class="muted">Reference source unavailable; verify the advisory or fix commit directly.</span></div></div>`;
  const lines=snippet.lines.map(line=>`<div class="code-line ${esc(line.marker)}"><span class="line-no">${line.number}</span><span class="line-text">${esc(line.text)||' '}</span></div>`).join('');
  return `<div class="code-panel ${esc(panelClass)}"><div class="code-label"><span>${esc(title)}</span></div><pre class="code">${lines}</pre>${snippet.truncated?`<div class="truncate">Excerpt limited to ${snippet.lines.length} of ${snippet.total_lines} lines.</div>`:''}</div>`;
}
function scoreRow(name,value,tone){const number=Number(value);if(!Number.isFinite(number))return'';const percent=Math.max(0,Math.min(100,number*100));return `<div class="score"><span>${esc(name)}</span><span class="bar"><span class="bar-fill ${esc(tone)}" style="width:${percent}%"></span></span><strong>${number.toFixed(3)}</strong></div>`}
function scoreValue(value){if(value===null||value===undefined||value==='')return'Unavailable';const number=Number(value);return Number.isFinite(number)?number.toFixed(3):'Unavailable'}
function evidenceBreakdown(f){
  const e=f.evidence||{},hasRegionScore=Number.isFinite(Number(e.vulnerable_score));
  if(!hasRegionScore){
    const matchType=f.hash_match_types.length?f.hash_match_types.join(', '):'No localized match';
    const explanation=f.hash_match_types.length?'The detector resolved this finding through its hash fast path, so region retrieval and weighted verification were not run.':'No localized region evidence was recorded for this finding.';
    return `<div class="breakdown-empty"><strong>${esc(label(matchType))}</strong><p>${esc(explanation)}</p><p class="muted">There are no structural, token, semantic, margin, or AST-coverage calculations for this path.</p></div>`;
  }
  const localEnabled=e.local_alignment_vulnerable!==null&&e.local_alignment_vulnerable!==undefined&&e.local_alignment_patched!==null&&e.local_alignment_patched!==undefined;
  const signals=localEnabled?[
    ['Structural',.40,e.structural_vulnerable,e.structural_patched,'50% AST shape ratio + 50% AST path ratio'],
    ['Token',.30,e.token_vulnerable,e.token_patched,'Sequence similarity after identifiers and literals are normalized by role'],
    ['Semantic',.20,e.semantic_vulnerable,e.semantic_patched,'50% call-set Jaccard + 50% member-access Jaccard'],
    ['Local alignment',.10,e.local_alignment_vulnerable,e.local_alignment_patched,'Normalized local source-line alignment']
  ]:[
    ['Structural',1,e.structural_vulnerable,e.structural_patched,'50% AST shape ratio + 50% AST path ratio'],
    ['Token',1,e.token_vulnerable,e.token_patched,'Sequence similarity after identifiers and literals are normalized by role'],
    ['Semantic',1,e.semantic_vulnerable,e.semantic_patched,'50% call-set Jaccard + 50% member-access Jaccard']
  ];
  const recorded=value=>value!==null&&value!==undefined&&value!==''&&Number.isFinite(Number(value));
  const vulnerableWeightTotal=signals.reduce((total,[,weight,value])=>total+(recorded(value)?weight:0),0);
  const patchedWeightTotal=signals.reduce((total,[,weight,,value])=>total+(recorded(value)?weight:0),0);
  const effectiveWeight=(value,weight,total)=>recorded(value)&&total?weight/total:null;
  const weighted=(value,weight)=>value!==null&&value!==undefined&&value!==''&&Number.isFinite(Number(value))?Number(value)*weight:null;
  const weightLabel=weight=>weight===null?'Unavailable':`${(weight*100).toFixed(2)}%`;
  const tableRows=signals.map(([name,weight,vulnerable,patched,note])=>{const vulnerableWeight=effectiveWeight(vulnerable,weight,vulnerableWeightTotal),patchedWeight=effectiveWeight(patched,weight,patchedWeightTotal);return `<tr><td><strong>${esc(name)}</strong><span class="weight-note">${esc(note)}</span></td><td>${weightLabel(vulnerableWeight)}</td><td>${scoreValue(vulnerable)}</td><td>${scoreValue(weighted(vulnerable,vulnerableWeight))}</td><td>${weightLabel(patchedWeight)}</td><td>${scoreValue(patched)}</td><td>${scoreValue(weighted(patched,patchedWeight))}</td></tr>`}).join('');
  const minimumVulnerable=Number(report.config.minimum_vulnerable_score),minimumMargin=Number(report.config.minimum_margin);
  const verdict=f.status==='automatic_vulnerability'?'Automatic vulnerability':f.status==='informational_lineage'?'Informational lineage':f.status==='none'?'No lineage':'Manual review';
  return `<div class="breakdown-score-strip"><div class="breakdown-score"><span>Retrieval similarity</span><strong>${scoreValue(e.retrieval_similarity)}</strong></div><div class="breakdown-score vulnerable"><span>Vulnerable score</span><strong>${scoreValue(e.vulnerable_score)}</strong></div><div class="breakdown-score patched"><span>Patched score</span><strong>${scoreValue(e.patched_score)}</strong></div><div class="breakdown-score margin"><span>Score margin</span><strong>${scoreValue(e.vulnerable_minus_patched)}</strong></div></div><section class="calculation-section"><h3>Fix-boundary evidence</h3><p>Vulnerable and patched references are scored symmetrically. Overlapping AST windows are deduplicated before their contrast and fix signatures are aggregated.</p><div class="calculation-table-wrap"><table class="calculation-table"><thead><tr><th>Signal</th><th>Vulnerable weight</th><th>Vulnerable similarity</th><th>Weighted</th><th>Patched weight</th><th>Patched similarity</th><th>Weighted</th></tr></thead><tbody>${tableRows}</tbody></table></div></section><div class="breakdown-grid"><section class="formula-card"><h3>Retrieval supports lineage</h3><p>Retrieval similarity ranks code-family candidates; it does not itself establish vulnerability state.</p><code>lineage retrieval = ${scoreValue(e.retrieval_similarity)}</code></section><section class="formula-card"><h3>AST coverage</h3><p>Coverage weights independent changed-region observations during robust aggregation.</p><code>AST coverage = ${scoreValue(e.ast_coverage)}</code></section></div><section class="decision-gate"><h3>Derived priority · ${esc(verdict)}</h3><ul><li>Automatic vulnerability additionally requires credible lineage and confirmed package applicability.</li><li>Fix-present contradictions prevent automatic promotion.</li><li>Unresolved state or applicability remains manual review.</li></ul></section>`;
}
function openEvidenceBreakdown(findingId){
  const finding=report.findings.find(item=>item.id===findingId);if(!finding)return;
  $('#evidence-dialog-title').textContent=`${finding.name} score breakdown`;
  $('#evidence-dialog-location').textContent=`${finding.path}:${finding.start_line}–${finding.end_line}`;
  $('#evidence-dialog-body').innerHTML=evidenceBreakdown(finding);
  $('#evidence-dialog').showModal();
}
function bindEvidenceBreakdowns(root=document){$$('.evidence-breakdown-trigger',root).forEach(button=>button.addEventListener('click',()=>openEvidenceBreakdown(button.dataset.findingId)))}
function externalLink(url,text){return url?`<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text)} ↗</a>`:''}
function advisoryActionLink(url,text,side){return url?`<a class="advisory-text-link ${esc(side||'')}" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text)}</a>`:''}
function advisoryIdentifierLink(url,identifier){return url?`<a class="advisory-id-link" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(identifier)}</a>`:`<span class="advisory-heading-id">${esc(identifier)}</span>`}
function advisorySummary(value){
  const source=String(value||'').trim();
  return source?`<div class="advisory-summary markdown-body">${markdown(source)}</div>`:''
}
function reviewExplanationPanel(explanation){
  if(!explanation)return'';
  const model=esc(String(explanation.model||'local model').replace(/^qwen3(?=:|$)/i,'Qwen3'));
  if(explanation.status!=='generated')return `<section class="review-explanation unavailable" aria-label="LLM explanation"><div class="review-explanation-head"><h4>LLM Explanation</h4><span class="review-explanation-meta">By ${model}</span></div><p>Explanation unavailable for this scan (${esc(label(explanation.error_code||'unknown error'))}).</p></section>`;
  const verdict=explanation.llm_verdict||'needs_review',verdictText=verdict==='flagged'?'Escalate':verdict==='dismissed'?'Dismissed':'Needs review';
  const verdictIcon=verdict==='flagged'?flagIcon:verdict==='dismissed'?dismissIcon:reviewIcon;
  const verdictRow=`<div class="llm-verdict ${esc(verdict)}" aria-label="LLM verdict"><strong>${verdictIcon}Verdict: ${verdictText}</strong></div>`;
  const head=`<div class="review-explanation-head"><h4>LLM Explanation</h4><span class="review-explanation-meta">By ${model}</span></div>`;
  if(verdict==='dismissed')return `${verdictRow}<section class="review-explanation dismissed" aria-label="LLM explanation">${head}<p>Code similarity was detected, but contextual vulnerability relevance was not supported.</p><p class="verdict-rationale">${esc(explanation.verdict_rationale)}</p></section>`;
  return `${verdictRow}<section class="review-explanation" aria-label="LLM explanation">${head}<p class="verdict-rationale">${esc(explanation.verdict_rationale)}</p><p><strong>Advisory mechanism:</strong> ${esc(explanation.security_mechanism)}</p></section>`;
}
function factRow(name,value){if(value===null||value===undefined||value==='')return'';return `<dt>${esc(name)}</dt><dd>${esc(value)}</dd>`}
function factHtml(name,value){if(!value)return'';return `<dt>${esc(name)}</dt><dd>${value}</dd>`}
function numericFact(name,value,digits=3){if(value===null||value===undefined||value===''||!Number.isFinite(Number(value)))return'';return factRow(name,Number(value).toFixed(digits))}
function packageNames(lineage){return(lineage.reference_packages||[]).map(item=>item.ecosystem?`${item.name} (${item.ecosystem})`:item.name).join(', ')}
function targetPackageLabel(target){if(!target?.name)return'';return target.version?`${target.name} @ ${target.version}`:target.name}
function lineageTitle(lineage,index){
  const rep=lineage.representative||{},functionName=lineage.function_name||rep.function_name||'',filePath=lineage.file_path||rep.file_path||'';
  if(functionName&&filePath)return `${functionName} · ${filePath}`;
  return functionName||filePath||rep.repo||packageNames(lineage)||`Lineage ${index+1}`
}
function advisoryKeys(value){return[value?.cve_id,value?.ghsa_id,value?.osv_id,value?.identifier].filter(Boolean).map(item=>String(item).toLocaleLowerCase())}
function isMostLikelyAdvisory(alias,lineage,primary){
  if(!primary)return false;
  if(primary.lineage_id&&lineage.lineage_id&&primary.lineage_id!==lineage.lineage_id)return false;
  const aliasKeys=advisoryKeys(alias),primaryKeys=advisoryKeys(primary);
  if(aliasKeys.length&&primaryKeys.length)return aliasKeys.some(key=>primaryKeys.includes(key));
  return Boolean(alias.advisory_url&&primary.advisory_url&&alias.advisory_url===primary.advisory_url)
}
function compareEvidenceRank(left,right){
  const a=left.evidence_rank||[],b=right.evidence_rank||[],length=Math.max(a.length,b.length);
  for(let index=0;index<length;index++){const difference=Number(b[index]||0)-Number(a[index]||0);if(difference)return difference}
  return String(left.lineage_id||'').localeCompare(String(right.lineage_id||''))
}
function provenanceTree(f,presentation){
  const lineages=[...(f.lineages||[])].sort(compareEvidenceRank),advisoryCount=lineages.reduce((total,lineage)=>total+(lineage.advisories||[]).length,0);
  const branches=lineages.map((lineage,index)=>{
    const aliases=[...(lineage.advisories||[])].sort((left,right)=>Number(isMostLikelyAdvisory(right,lineage,f.primary))-Number(isMostLikelyAdvisory(left,lineage,f.primary))),rep=lineage.representative||{},confidence=label(lineage.provenance_confidence||'none');
    const aliasRows=aliases.map(alias=>{const identifier=alias.cve_id||alias.ghsa_id||alias.osv_id||'Unknown advisory',title=String(alias.title||alias.advisory_title||'').trim();const linked=advisoryIdentifierLink(alias.advisory_url,identifier),mostLikely=isMostLikelyAdvisory(alias,lineage,f.primary),titleRow=title&&title.toLocaleLowerCase()!==identifier.toLocaleLowerCase()?`<span class="alias-title">${esc(title)}</span>`:'';return `<div class="alias-row${presentation.highlight&&mostLikely?' most-likely':''}"><div class="alias-copy"><span class="alias-id">${linked}</span>${titleRow}</div></div>`}).join('');
    const commit=String(lineage.fix_commit_sha||''),shortCommit=commit.length>12?commit.slice(0,12)+'…':commit;
    const applicability=lineage.package_applicability||'unresolved';
    const referencePackage=packageNames(lineage),targetPackage=targetPackageLabel(f.target_package),reference=[rep.repo,lineage.file_path||rep.file_path].filter(Boolean).join(' · ');
    const packageFacts=targetPackage?`${factRow('Target package',targetPackage)}${factHtml('Applicability',`<span class="applicability ${esc(applicability)}">${esc(label(applicability))}</span>`)}`:factHtml('Package applicability','<span class="applicability unresolved">Unverified — target package could not be resolved</span>');
    const provenanceFacts=reference?factRow('Reference',reference):factHtml('Reference provenance','<span class="applicability unresolved">Missing source repository and file</span>');
    const fixFact=commit?factRow('Fix commit hash',commit):factHtml('Fix provenance','<span class="applicability unresolved">Missing fix commit hash</span>');
    const meta=[shortCommit,`${aliases.length} advisory alias${aliases.length===1?'':'es'}`,confidence!=='None'?`${confidence} confidence`:null].filter(Boolean).map(value=>`<span>${esc(value)}</span>`).join('');
    return `<details class="lineage-branch ${esc(lineage.status)}"${index===0?' open':''}><summary><span class="lineage-node" aria-hidden="true"></span><span class="lineage-head"><strong>${esc(lineageTitle(lineage,index))}</strong><span class="lineage-meta">${meta}</span></span><span class="lineage-toggle">${icons.chevron}</span></summary><div class="lineage-body"><dl class="lineage-facts">${factRow('Reference package',referencePackage)}${packageFacts}${provenanceFacts}${fixFact}</dl>${aliasRows?`<div class="alias-list">${aliasRows}</div>`:''}</div></details>`;
  }).join('');
  return `<section class="provenance-map" aria-label="Finding provenance tree"><div class="lineage-list">${branches||'<p class="muted">No verified advisory lineage was retained.</p>'}</div></section>`
}
function findingCard(f,openByDefault=false){
  const p=f.primary,e=f.evidence||{};
  const needsReview=f.status==='manual_review';
  const verdict=llmVerdict(f),presentation=referencePresentation(f),llmStatus=verdict==='dismissed'?'llm_dismissed':verdict==='flagged'?'llm_escalate':'';
  const headerBadges=needsReview?(llmStatus?badge(llmStatus,llmStatus):badge(f.status)):`${badge(f.status)} ${badge(f.severity,f.severity)}`;
  const impact=label(f.severity),potentialImpact=needsReview&&verdict!=='dismissed'?`<dt>Potential impact</dt><dd><strong>${esc(impact.charAt(0).toUpperCase()+impact.slice(1))} if confirmed</strong></dd>`:'';
  const ids=[p.cve_id,p.ghsa_id,p.osv_id].filter(Boolean).join(' · ')||p.identifier;
  const identifier=String(p.cve_id||p.ghsa_id||p.osv_id||p.identifier||'Advisory').trim(),title=String(p.title||'').trim();
  const headingText=title&&title.toLocaleLowerCase()!==identifier.toLocaleLowerCase()?`${identifier}: ${title}`:identifier;
  const heading=p.advisory_url?`<a class="advisory-id-link" href="${esc(p.advisory_url)}" target="_blank" rel="noreferrer">${esc(headingText)}</a>`:esc(headingText);
  const affected=(p.affected_versions||[]).join(', '),versions=(p.fixed_versions||[]).join(', ');
  const summary=advisorySummary(p.advisory_summary);
  const lineageCount=(f.lineages||[]).length,advisoryCount=(f.lineages||[]).reduce((total,lineage)=>total+(lineage.advisories||[]).length,0);
  const rankedLineage=[...(f.lineages||[])].sort(compareEvidenceRank)[0]||{},rankedRepresentative=rankedLineage.representative||{};
  const fixRepo=p.repo||rankedRepresentative.repo||'',fixCommit=p.fix_commit_sha||rankedLineage.fix_commit_sha||rankedRepresentative.fix_commit_sha||'';
  const fixUrl=p.fix_url||rankedRepresentative.fix_url||(fixRepo&&fixCommit?`https://github.com/${fixRepo}/commit/${fixCommit}`:'');
  const reviewPanel=needsReview?reviewExplanationPanel(f.review_explanation):'',dismissedReview=verdict==='dismissed'?reviewPanel:'',activeReview=verdict==='dismissed'?'':reviewPanel;
  const referenceActions=`${advisoryActionLink(p.advisory_url,'Open advisory','advisory')}${advisoryActionLink(fixUrl,'Open fix commit','fix')}`;
  const referencePackage=p.package_name?`${p.package_name}${p.ecosystem?` (${p.ecosystem})`:''}`:'',cwes=(p.cwes||[]).join(', ');
  const primaryFacts=`${potentialImpact}${factRow('Representative IDs',ids)}${advisoryCount>1?factRow('Advisory aliases',advisoryCount):''}${factRow('Affected versions',affected)}${factRow('Known fixed versions',versions)}${factRow('Reference package',referencePackage)}${factRow('CWE',cwes)}`;
  const confidenceFact=f.confidence&&f.confidence!=='none'?factHtml('Confidence',`<strong>${esc(label(f.confidence))}</strong>`):factHtml('Evidence completeness','<span class="applicability unresolved">Confidence unavailable</span>');
  const evidenceFacts=`${confidenceFact}${numericFact('Score margin',e.vulnerable_minus_patched)}${numericFact('AST coverage',e.ast_coverage)}${factRow('Match type',f.hash_match_types.join(', ')||'Region similarity')}`;
  return `<details class="finding-card"${openByDefault?' open':''}><summary class="finding-head"><div><h3>${esc(f.name)}</h3><span class="muted">${esc(f.path)}:${f.start_line}–${f.end_line}</span></div><div class="badge-row"><span class="association-count">${esc(lineageCount)} lineage${lineageCount===1?'':'s'} · ${esc(advisoryCount)} ${advisoryCount===1?'advisory':'advisories'}</span>${headerBadges}<span class="finding-chevron">${icons.chevron}</span></div></summary><div class="finding-body">${dismissedReview}${provenanceTree(f,presentation)}<div class="advisory-intro"><div class="advisory-heading"><h3><span class="advisory-heading-id"><span class="most-likely-label ${esc(presentation.tone)}">${esc(presentation.title)}</span> ${heading}</span></h3></div>${summary}</div>${activeReview}<div class="code-compare">${codePanel('Project code',f.reference.candidate,'detected-panel')}<div class="reference-stack">${codePanel(presentation.vulnerable,f.reference.vulnerable)}${codePanel('Known patched reference',f.reference.patched)}</div></div><div class="detail-grid"><section class="detail-box reference-detail"><h4>${esc(presentation.lineage)}</h4><dl class="facts">${primaryFacts}</dl>${referenceActions?`<p class="link-row reference-actions">${referenceActions}</p>`:''}</section><section class="detail-box"><h4>Detection Evidence</h4>${scoreRow('Vulnerable',e.vulnerable_score,'vulnerable')}${scoreRow('Patched',e.patched_score,'patched')}${scoreRow('Retrieval',e.retrieval_similarity,'retrieval')}<dl class="facts">${evidenceFacts}</dl><button class="evidence-breakdown-trigger" type="button" aria-haspopup="dialog" data-finding-id="${esc(f.id)}">View breakdown</button></section></div></div></details>`;
}
function selectFile(path){selectedFile=path;$$('.tree-file').forEach(button=>button.classList.toggle('selected',button.dataset.path===path));renderFile()}
function renderFile(){
  if(!selectedFile){
    const statusRank={flagged:0,llm_escalate:1,manual_review:2,llm_dismissed:3,informational_lineage:4,none:5};
    const affectedFiles=[...byFile.keys()].sort((a,b)=>statusRank[fileStatus(a)]-statusRank[fileStatus(b)]||a.localeCompare(b));
    $('#file-pane').innerHTML=`<header class="file-heading"><div><h2>${esc(report.project)}</h2><span class="muted">${affectedFiles.length?`${affectedFiles.length} affected file${affectedFiles.length===1?'':'s'}`:'No affected files'}</span></div></header>${affectedFiles.length?`<div class="overview-files">${affectedFiles.map(path=>{const status=fileStatus(path),findings=byFile.get(path)||[];return `<button class="overview-file ${esc(status)}" data-path="${esc(path)}"><span class="file-name">${esc(path)}</span>${countMarkers(findings)}</button>`}).join('')}</div>`:`<div class="empty"><strong>No active findings</strong></div>`}`;
    $$('.overview-file').forEach(button=>button.addEventListener('click',()=>selectFile(button.dataset.path)));
    return;
  }
  const fs=byFile.get(selectedFile)||[];
  $('#file-pane').innerHTML=`<header class="file-heading"><div class="file-title"><button class="back-btn" id="back-project" aria-label="Back to project overview">${icons.back}<span>Back</span></button><div><h2>${esc(selectedFile)}</h2><span class="muted">${fs.length?`${fs.length} finding${fs.length===1?'':'s'} needs review`:'No active findings in this file'}</span></div></div></header>${fs.length?fs.map(f=>findingCard(f,fs.length===1)).join(''):`<div class="empty"><div><strong>No active findings</strong><p class="muted">Provtrail analyzed this file without flagging a vulnerability clone.</p></div></div>`}`;
  bindEvidenceBreakdowns($('#file-pane'));
  $('#back-project').addEventListener('click',()=>selectFile(''));
}
function switchTab(id){$$('.tab').forEach(t=>t.setAttribute('aria-selected',String(t.dataset.tab===id)));$$('.panel').forEach(p=>p.classList.toggle('active',p.id===id))}
function renderRows(){
  const query=$('#search').value.trim().toLowerCase(),status=$('#status-filter').value,severity=$('#severity-filter').value;
  const rows=report.findings.filter(f=>{const statusOk=status==='all'||status==='active'&&activeStatuses.has(f.status)||f.status===status;const sevOk=severity==='all'||f.severity===severity;const associations=(f.lineages||[]).flatMap(lineage=>[lineage.lineage_id,lineage.repo,...(lineage.reference_packages||[]).map(item=>item.name),...(lineage.advisories||[]).flatMap(item=>[item.identifier,item.title])]);const hay=[f.path,f.name,...associations].join(' ').toLowerCase();return statusOk&&sevOk&&(!query||hay.includes(query))});
  $('#result-count').textContent=`${rows.length} result${rows.length===1?'':'s'}`;
  $('#finding-rows').innerHTML=rows.length?rows.map(f=>{const lineages=f.lineages||[],advisories=lineages.reduce((total,lineage)=>total+(lineage.advisories||[]).length,0);return `<tr data-file="${esc(f.path)}" tabindex="0"><td>${badge(f.status)}</td><td>${badge(f.severity,f.severity)}</td><td>${llmDecision(f)}</td><td>${esc(f.path)}:${f.start_line}</td><td>${esc(f.name)}</td><td>${esc(lineages.length)} lineage${lineages.length===1?'':'s'} · ${esc(advisories)} ${advisories===1?'advisory':'advisories'}</td><td>${esc(label(f.confidence))}</td></tr>`}).join(''):`<tr><td colspan="7"><div class="empty"><span class="muted">No findings match these filters.</span></div></td></tr>`;
  $$('tr[data-file]').forEach(row=>{const open=()=>{selectFile(row.dataset.file);switchTab('files')};row.addEventListener('click',open);row.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();open()}})})
}
function renderRecommendations(){
  const root=$('#recommendation-list');
  if(!report.recommendations.length){root.innerHTML=`<div class="empty"><div><strong>No remediation actions</strong><p class="muted">The scan completed without active findings.</p></div></div>`;return}
  root.innerHTML=report.recommendations.map((r,index)=>{
    const affected=r.affected_versions.length?r.affected_versions.join(', '):'';
    const fixed=r.fixed_versions.length?r.fixed_versions.join(', '):'';
    const removed=r.patch_changes.removed||[],added=r.patch_changes.added||[];
    const changeText=added.length&&removed.length?`Replace the matched behavior in ${r.locations.length} location${r.locations.length===1?'':'s'} with the validation or control flow demonstrated by the known patch.`:added.length?`Add the missing safeguard demonstrated by the known patch to each matched location.`:removed.length?`Remove or constrain the behavior deleted by the known patch in each matched location.`:`Use the known patched implementation as the behavioral baseline for the matched region in ${r.reference_file||'the reference source'}.`;
    const changes=[...removed.map(line=>['Removed',line]),...added.map(line=>['Added',line])];
    const rawTitle=String(r.title||'').trim(),identifier=String(r.identifier||'').trim(),title=rawTitle||identifier||'Advisory';
    const sameTitle=identifier&&identifier.toLocaleLowerCase()===title.toLocaleLowerCase();
    const linkedIdentifier=identifier?advisoryIdentifierLink(r.advisory_url,identifier):'';
    const titleMarkup=identifier?(sameTitle?linkedIdentifier:`${linkedIdentifier}: ${esc(title)}`):esc(title);
    const description=String(r.description||'').trim(),expandable=description.length>240,summaryId=`recommendation-summary-${index}`;
    const summaryControl=expandable?`<button class="summary-toggle" type="button" aria-expanded="false" aria-controls="${summaryId}">Show more</button>`:'';
    const descriptionMarkup=description?`<div class="recommendation-summary markdown-body ${expandable?'collapsed':''}" id="${summaryId}">${markdown(description)}</div>${summaryControl}`:'';
    const packageLabel=(r.reference_packages||[]).map(item=>item.ecosystem?`${item.name} (${item.ecosystem})`:item.name).join(', ');
    const targetLabel=targetPackageLabel(r.target_package),applicability=label(r.package_applicability||'unresolved');
    const packageBoxes=`${packageLabel?`<div class="version-box"><span class="muted">Reference package</span><strong>${esc(packageLabel)}</strong></div>`:''}${targetLabel?`<div class="version-box"><span class="muted">Target package</span><strong>${esc(targetLabel)}</strong><span class="applicability ${esc(r.package_applicability)}">${esc(applicability)}</span></div>`:`<div class="version-box"><span class="muted">Package applicability</span><strong class="applicability unresolved">Unverified — target package could not be resolved</strong></div>`}${affected?`<div class="version-box"><span class="muted">Historical affected versions</span><strong>${esc(affected)}</strong></div>`:''}${fixed?`<div class="version-box"><span class="muted">Known fixed versions</span><strong>${esc(fixed)}</strong></div>`:''}`;
    const versionGuidance='For copied or adapted code, follow the code change shown here instead of changing a dependency version.';
    const lineageNote=r.advisory_count===1?'1 advisory alias':`${r.advisory_count} advisory aliases`;
    return `<article class="recommendation"><h3>${titleMarkup}</h3><div class="badge-row">${badge(r.severity,r.severity)}<span class="association-count">${esc(lineageNote)}</span></div>${descriptionMarkup}<div class="recommendation-grid"><div>${packageBoxes}<p class="muted">${esc(versionGuidance)}</p><section class="affected-locations"><h4>Affected locations</h4><div class="locations">${r.locations.map(l=>`<span class="location">${esc(l)}</span>`).join('')}</div></section></div><div><h4>Recommended code change</h4><p>${esc(changeText)}</p>${changes.length?`<div class="patch-lines">${changes.map(([kind,line])=>{const tone=kind.toLowerCase(),marker=kind==='Removed'?'−':'+';return `<div class="patch-line ${tone}"><strong><span aria-hidden="true">${marker}</span> ${kind}</strong><code>${esc(line)}</code></div>`}).join('')}</div>`:`<p class="muted">Patch guidance unavailable; inspect the linked fix commit before modifying code.</p>`}</div></div><p class="link-row">${externalLink(r.advisory_url,'Read representative advisory')} ${externalLink(r.fix_url,'Inspect fix commit')}</p></article>`
  }).join('');
  $$('.summary-toggle',root).forEach(button=>button.addEventListener('click',()=>{const summary=document.getElementById(button.getAttribute('aria-controls')),expanded=button.getAttribute('aria-expanded')==='true';button.setAttribute('aria-expanded',String(!expanded));button.textContent=expanded?'Show more':'Show less';summary.classList.toggle('collapsed',expanded)}))
}
function initDetails(){
  const values=[['Project',report.project],['Report schema',report.schema],['Tool version',report.tool_version],['Corpus version',report.corpus_version],['Root hash',report.root_hash],['Embedding model',report.config.model],['Retrieval threshold',report.config.retrieval_threshold],['Minimum vulnerable score',report.config.minimum_vulnerable_score],['Minimum margin',report.config.minimum_margin],['Changed files',report.changed_files.length],['Deleted files',report.deleted_files.length],['Files analyzed',report.scanned_files.length],['Functions recomputed',report.audit.scanned_functions]];
  const run=report.explanation_run||{};
  if(run.enabled)values.push(['Review explanation model',run.model],['Explanations generated',run.generated],['Explanations reused',run.reused],['Explanations unavailable',run.unavailable]);
  $('#scan-details').innerHTML=values.filter(([,value])=>value!==null&&value!==undefined&&value!=='').map(([k,v])=>`<div><span>${esc(k)}</span><strong>${esc(v)}</strong></div>`).join('')
}
$$('.tab').forEach(tab=>tab.addEventListener('click',()=>switchTab(tab.dataset.tab)));
['search','status-filter','severity-filter'].forEach(id=>$('#'+id).addEventListener(id==='search'?'input':'change',renderRows));
$('#theme-toggle').addEventListener('click',()=>{const dark=document.documentElement.dataset.theme!=='dark';document.documentElement.dataset.theme=dark?'dark':'light';$('#theme-toggle').textContent=dark?'Light theme':'Dark theme'});
$('#evidence-dialog').addEventListener('click',event=>{if(event.target===$('#evidence-dialog'))$('#evidence-dialog').close()});
initSummary();renderDependencies();renderResults();buildTree();renderFile();renderRows();renderRecommendations();initDetails();
</script>
</body>
</html>'''
