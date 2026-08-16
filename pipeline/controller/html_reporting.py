"""Generate a portable, interactive HTML artifact for a provtrail scan."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from corpus.models.corpus import CorpusEntry
from pipeline.controller.region_extraction import enumerate_candidate_regions
from pipeline.controller.reporting import ACTIVE_STATUSES, audit_summary, finding_detail
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


def _build_finding(
    finding: dict[str, Any],
    entries_by_key: dict[tuple[Any, ...], CorpusEntry],
) -> dict[str, Any]:
    detail = finding_detail(finding)
    matches: list[dict[str, Any]] = []
    for match in detail.get("advisories", []):
        entry = entries_by_key.get(_entry_key(match))
        matches.append(_enrich_match(match, entry))
    primary_raw = detail.get("primary_match") or {}
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
    status = str(detail.get("status") or "unknown")
    candidate_source = str(finding.get("source") or "") if status in ACTIVE_STATUSES else ""
    result = finding.get("result", {})
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
    if primary_entry is not None and status in ACTIVE_STATUSES:
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
        "status": status,
        "severity": str(detail.get("severity") or "unknown").lower(),
        "confidence": str(detail.get("provenance_confidence") or "none"),
        "message": detail.get("message") or "",
        "primary": primary,
        "advisories": matches,
        "evidence": evidence,
        "hash_match_types": detail.get("hash_match_types", []),
        "reference": reference,
        "parser_supported": result.get("parser_supported", True),
    }


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
    findings = [_build_finding(finding, entries_by_key) for finding in summary.findings]
    findings.sort(
        key=lambda item: (
            0 if item["status"] == "flagged" else 1 if item["status"] == "manual_review" else 2,
            SEVERITY_RANK.get(item["severity"], 5),
            item["path"],
            item["start_line"],
        )
    )
    active = [item for item in findings if item["status"] in ACTIVE_STATUSES]
    recommendations: dict[str, dict[str, Any]] = {}
    for finding in active:
        primary = finding["primary"]
        key = str(primary.get("ghsa_id") or primary.get("cve_id") or primary.get("identifier"))
        group = recommendations.setdefault(
            key,
            {
                "key": key,
                "identifier": primary.get("identifier"),
                "title": primary.get("title"),
                "description": primary.get("advisory_description") or "No advisory description was recorded.",
                "severity": str(primary.get("severity") or finding["severity"]).lower(),
                "advisory_url": primary.get("advisory_url") or "",
                "fix_url": primary.get("fix_url") or "",
                "affected_versions": primary.get("affected_versions") or [],
                "fixed_versions": primary.get("fixed_versions") or [],
                "package_name": primary.get("package_name") or "",
                "reference_file": primary.get("file_path") or "",
                "reference_function": primary.get("function_name") or "",
                "patch_changes": primary.get("patch_changes") or {"removed": [], "added": []},
                "locations": [],
            },
        )
        location = f"{finding['path']}:{finding['start_line']}"
        if location not in group["locations"]:
            group["locations"].append(location)
    recommendation_list = sorted(
        recommendations.values(),
        key=lambda item: (SEVERITY_RANK.get(item["severity"], 5), item["identifier"]),
    )
    public_payload = summary.to_dict()
    audit = audit_summary(public_payload)
    # The HTML artifact is intended to be shareable. Keep repository-relative
    # locations, but never embed workstation-specific absolute paths.
    audit.pop("target_root", None)
    audit.pop("state_path", None)
    return {
        "schema": "provtrail_html_report_v1",
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
        "findings": findings,
        "recommendations": recommendation_list,
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
    title = html.escape(f"provtrail · {data.get('project', 'scan report')}", quote=True)
    return _TEMPLATE.replace("__REPORT_TITLE__", title).replace("__REPORT_DATA__", encoded)


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
*{box-sizing:border-box}html{background:var(--paper);color:var(--ink);font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}body{margin:0;min-width:320px}button,input,select{font:inherit;color:inherit}button{cursor:pointer}.shell{max-width:1560px;margin:auto;padding:24px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:24px;margin-bottom:22px}.brand{display:flex;align-items:center}.wordmark{margin:0;color:var(--teal);font-size:24px;line-height:1.1;font-weight:850;letter-spacing:-.04em}.actions{display:flex;gap:8px}.icon-btn,.btn,.back-btn{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);background:var(--surface);border-radius:5px;padding:9px 12px;font-weight:750}.icon-btn:hover,.btn:hover,.back-btn:hover{background:var(--surface-2)}:focus-visible{outline:3px solid var(--focus);outline-offset:2px}.outcome{background:var(--surface);border:1px solid var(--line);border-radius:8px;box-shadow:var(--shadow);padding:22px;margin-bottom:16px}.outcome-head{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}.outcome h2{font-size:29px;letter-spacing:-.04em;margin:0 0 8px;font-weight:850}.muted{color:var(--muted)}.scan-meta{display:flex;align-items:center;gap:9px;flex-wrap:wrap;font-size:13px}.scan-state{font-weight:800}.notice{max-width:520px;font-size:13px;line-height:1.5;margin:0}.metrics{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:1px;background:var(--line);border:1px solid var(--line);margin-top:20px}.metric{background:var(--surface);padding:13px}.metric strong{display:block;font-size:22px;letter-spacing:-.03em}.metric span{font-size:12px;color:var(--muted);font-weight:700}.tabs{display:flex;gap:4px;border-bottom:1px solid var(--line);margin-top:22px}.tab{border:0;background:transparent;padding:11px 16px;font-weight:800;color:var(--muted);border-radius:5px 5px 0 0}.tab[aria-selected="true"]{background:var(--surface);color:var(--ink);box-shadow:inset 0 -3px var(--navy)}.panel{display:none}.panel.active{display:block}.workspace{display:grid;grid-template-columns:minmax(270px,32%) 1fr;min-height:600px;background:var(--surface);border:1px solid var(--line);border-radius:0 0 8px 8px}.explorer{padding:16px;border-right:1px solid var(--line);overflow:auto;max-height:calc(100vh - 270px)}.pane{padding:24px;min-width:0;overflow:hidden}.section-title{font-size:14px;color:var(--ink);font-weight:850;margin:0 0 12px}.icon{width:17px;height:17px;flex:0 0 auto;stroke:currentColor;fill:none;stroke-width:1.8;stroke-linecap:round;stroke-linejoin:round}.tree details{padding-inline-start:12px}.tree summary{display:flex;align-items:center;gap:6px;list-style:none;padding:5px 4px;font-size:13px;font-weight:750;cursor:pointer}.tree summary::-webkit-details-marker{display:none}.tree summary::before{content:"▸";display:inline-block;width:12px;color:var(--muted)}.tree details[open]>summary::before{content:"▾"}.folder-open{display:none}.tree details[open]>summary .folder-open{display:block}.tree details[open]>summary .folder-closed{display:none}.tree-file{width:100%;display:flex;align-items:center;gap:7px;border:0;background:transparent;border-radius:4px;padding:6px 7px 6px 19px;text-align:left;font-size:13px}.tree-file:hover,.tree-file.selected{background:var(--surface-2)}.tree-file.unaffected{color:var(--muted)}.file-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.tree-count{margin-inline-start:auto}.badge{display:inline-flex;align-items:center;gap:5px;border-radius:3px;padding:3px 6px;font-size:11px;font-weight:850;white-space:nowrap}.badge.flagged,.badge.critical,.badge.high{color:var(--red);background:var(--red-bg)}.badge.manual_review,.badge.moderate,.badge.medium{color:var(--amber);background:var(--amber-bg)}.badge.cleared,.badge.low{color:var(--teal);background:var(--teal-bg)}.badge.unknown,.badge.none{background:var(--surface-2);color:var(--muted)}.file-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:22px}.file-title{display:flex;align-items:flex-start;gap:10px}.file-heading h2{font-size:23px;margin:3px 0 5px;overflow-wrap:anywhere}.overview-files{display:grid;gap:8px;margin-top:18px}.overview-file{display:flex;align-items:center;gap:9px;width:100%;border:1px solid var(--line);background:var(--surface);border-radius:5px;padding:11px;text-align:left;font-weight:750}.overview-file:hover{background:var(--surface-2)}.finding-card{border:1px solid var(--line);border-radius:7px;margin:0 0 18px;overflow:hidden}.finding-head{padding:16px 18px;background:var(--surface-2);display:flex;justify-content:space-between;gap:14px}.finding-head h3{font-size:17px;margin:4px 0}.finding-body{padding:18px}.badge-row,.link-row{display:flex;gap:7px;flex-wrap:wrap;align-items:center}.advisory-heading{display:flex;align-items:center;justify-content:space-between;gap:16px;margin:0 0 14px}.advisory-heading h3{margin:0;font-size:18px}.advisory-heading-id{font-weight:900}.advisory-action{display:grid;place-items:center;flex:0 0 auto;width:34px;height:34px;border:1px solid var(--line);border-radius:5px;background:var(--surface);color:var(--focus)}.advisory-action:hover{background:var(--surface-2)}.advisory-id-link{color:inherit;font-weight:800;text-decoration:underline;text-underline-offset:3px}.code-compare{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(0,.95fr);gap:12px;align-items:start}.reference-stack{display:grid;gap:12px}.code-panel{border:1px solid var(--line);border-radius:5px;overflow:hidden;min-width:0}.code-label{display:flex;justify-content:space-between;padding:8px 10px;background:var(--surface-2);font-size:11px;font-weight:850;text-transform:uppercase;letter-spacing:.06em}.code{margin:0;max-height:380px;overflow:auto;background:#111820;color:#e8edf5;padding:9px 0;font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}.code-line{display:grid;grid-template-columns:46px max-content;min-width:100%;width:max-content;padding:0 10px}.code-line.detected{background:#263a62}.code-line.vulnerable{background:#502b2b}.code-line.patched{background:#17423c}.line-no{color:#9aa7b8;text-align:right;padding-right:12px;user-select:none}.line-text{white-space:pre}.truncate{font-size:11px;color:var(--muted);padding:7px 10px;background:var(--surface-2)}.detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:18px}.detail-box{border:1px solid var(--line);border-radius:5px;padding:14px}.detail-box h4{margin:0 0 11px;font-size:14px}.facts{display:grid;grid-template-columns:max-content 1fr;gap:7px 13px;font-size:13px}.facts dt{color:var(--muted)}.facts dd{margin:0;overflow-wrap:anywhere}.score{display:grid;grid-template-columns:100px 1fr 42px;gap:8px;align-items:center;margin:8px 0;font-size:12px}.bar{height:8px;background:var(--surface-2);border-radius:999px;overflow:hidden}.bar-fill{height:100%;background:var(--navy)}.bar-fill.patch{background:var(--teal)}a{color:var(--focus);text-underline-offset:3px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;padding:14px;background:var(--surface);border:1px solid var(--line);border-top:0}.control{border:1px solid var(--line);background:var(--surface);border-radius:5px;padding:9px 10px}.search{min-width:270px;flex:1}.table-wrap{overflow:auto;border:1px solid var(--line);border-top:0;background:var(--surface)}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:11px 13px;border-bottom:1px solid var(--line)}th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}tr[data-file]{cursor:pointer}tr[data-file]:hover{background:var(--surface-2)}.recommendations{display:grid;gap:14px;padding-top:16px}.recommendation{background:var(--surface);border:1px solid var(--line);border-radius:7px;padding:20px}.recommendation h3{margin:7px 0 8px}.recommendation-grid{display:grid;grid-template-columns:minmax(210px,.7fr) 1.3fr;gap:18px;margin-top:16px}.version-box{background:var(--surface-2);border-radius:5px;padding:13px}.version-box+.version-box{margin-top:8px}.version-box strong{display:block;margin-top:3px}.affected-locations{margin-top:16px;background:var(--location-bg);border-radius:5px;padding:13px}.affected-locations h4{margin:0 0 8px}.patch-lines{display:grid;gap:7px}.patch-line{display:grid;grid-template-columns:86px minmax(0,1fr);gap:10px;align-items:start;padding:9px 11px;border-radius:4px}.patch-line strong{font-size:12px}.patch-line code{overflow:auto;background:transparent;color:inherit;padding:1px 0;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap}.patch-line.removed{background:var(--red-bg);color:var(--red)}.patch-line.added{background:var(--teal-bg);color:var(--teal)}.locations{display:grid;gap:4px}.location{font:12px ui-monospace,SFMono-Regular,Menlo,monospace;padding:3px 0}.empty{display:grid;place-items:center;min-height:320px;text-align:center;padding:30px}.empty strong{font-size:22px}.details{margin-top:16px;background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:12px 14px}.details summary{cursor:pointer;font-weight:800}.scan-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:14px;font-size:12px}.scan-grid div{overflow-wrap:anywhere}.scan-grid span{display:block;color:var(--muted);margin-bottom:3px}.sr-only{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0,0,0,0);white-space:nowrap;border:0}
@media(max-width:1000px){.metrics{grid-template-columns:repeat(3,1fr)}.workspace{grid-template-columns:1fr}.explorer{border-right:0;border-bottom:1px solid var(--line);max-height:280px}.code-compare,.detail-grid,.recommendation-grid{grid-template-columns:1fr}}
@media(max-width:650px){.shell{padding:12px}.topbar,.outcome-head,.file-heading{flex-direction:column}.outcome h2{font-size:24px}.metrics{grid-template-columns:repeat(2,1fr)}.pane{padding:15px}.tabs{overflow:auto}.search{min-width:100%}.scan-grid{grid-template-columns:1fr}.actions{width:100%}.actions button{flex:1}}
@media(prefers-reduced-motion:no-preference){.panel.active{animation:appear .16s ease-out}@keyframes appear{from{opacity:.5;transform:translateY(3px)}to{opacity:1;transform:none}}}
.explorer{height:calc(100vh - 270px);min-height:600px;overflow-y:scroll;scrollbar-gutter:stable;scrollbar-color:var(--muted) var(--surface-2);scrollbar-width:auto}.explorer::-webkit-scrollbar{width:12px}.explorer::-webkit-scrollbar-track{background:var(--surface-2)}.explorer::-webkit-scrollbar-thumb{background:var(--muted);border:3px solid var(--surface-2);border-radius:8px}.metric.flagged strong,.metric.critical strong,.metric.high strong{color:var(--red)}.metric.manual_review strong,.metric.moderate strong,.metric.medium strong{color:var(--amber)}.metric.low strong{color:var(--teal)}.code-compare{height:720px}.code-panel{display:flex;flex-direction:column}.detected-panel{height:720px}.reference-stack{height:720px;grid-template-rows:repeat(2,minmax(0,1fr))}.reference-stack .code-panel{min-height:0}.code-panel .code{flex:1;max-height:none}.bar-fill.vulnerable{background:var(--red)}.bar-fill.patched{background:var(--teal)}.bar-fill.retrieval{background:var(--focus)}
.top-details{margin:-10px 0 15px;background:transparent;border:0;border-radius:0;padding:0}.top-details summary{display:inline-block;color:var(--muted);font-size:13px;font-weight:750;text-decoration:underline;text-underline-offset:4px}.top-details .scan-grid{background:var(--surface);border:1px solid var(--line);border-radius:5px;padding:14px}.report-date{font-size:15px;font-weight:750;margin:0}
.outcome .top-details{margin:8px 0 0}
.outcome .top-details summary{color:var(--focus);background:transparent;border-radius:0;padding:0}.recommendation-summary{line-height:1.55}.recommendation-summary.collapsed{display:-webkit-box;-webkit-box-orient:vertical;-webkit-line-clamp:3;overflow:hidden}.summary-toggle{border:0;background:transparent;color:var(--focus);padding:0;font-weight:800;text-decoration:underline;text-underline-offset:3px}.summary-toggle:hover{color:var(--ink)}
.badge.manual_review{color:var(--focus);background:var(--focus-bg)}.metric.manual_review strong{color:var(--focus)}.finding-card>summary{list-style:none;cursor:pointer}.finding-card>summary::-webkit-details-marker{display:none}.finding-chevron{display:inline-flex;color:var(--muted);transition:transform .16s ease}.finding-card[open] .finding-chevron{transform:rotate(180deg)}
.overview-file{font-weight:550}
@media(max-width:1000px){.explorer{height:280px;min-height:0}.code-compare,.reference-stack,.detected-panel{height:auto}.code-panel .code{max-height:380px}}
</style>
</head>
<body>
<main class="shell">
  <header class="topbar"><div class="brand"><h1 class="wordmark">provtrail</h1></div><div class="actions"><button class="icon-btn" id="theme-toggle" aria-label="Switch color theme">Dark theme</button></div></header>
  <section class="outcome" aria-labelledby="outcome-title"><h2 id="outcome-title"></h2><p class="muted report-date" id="generated"></p><details class="top-details"><summary>Details</summary><div class="scan-grid" id="scan-details"></div></details><div class="metrics" id="metrics"></div></section>
  <nav class="tabs" aria-label="Report views"><button class="tab" data-tab="files" aria-selected="true">Files</button><button class="tab" data-tab="findings" aria-selected="false">Findings</button><button class="tab" data-tab="recommendations" aria-selected="false">Recommendations</button></nav>
  <section id="files" class="panel active"><div class="workspace"><aside class="explorer"><p class="section-title">Project directory</p><div class="tree" id="tree"></div></aside><article class="pane" id="file-pane"></article></div></section>
  <section id="findings" class="panel"><div class="toolbar"><label class="sr-only" for="search">Search findings</label><input id="search" class="control search" type="search" placeholder="Search path, function, advisory, or title"><select id="status-filter" class="control" aria-label="Filter by status"><option value="active">Needs attention</option><option value="flagged">Flagged</option><option value="manual_review">Manual review</option><option value="all">All analyzed</option></select><select id="severity-filter" class="control" aria-label="Filter by severity"><option value="all">All severities</option><option>critical</option><option>high</option><option>moderate</option><option>medium</option><option>low</option><option>unknown</option></select><span class="muted" id="result-count"></span></div><div class="table-wrap"><table><thead><tr><th>Status</th><th>Severity</th><th>Location</th><th>Function</th><th>Advisory</th><th>Confidence</th></tr></thead><tbody id="finding-rows"></tbody></table></div></section>
  <section id="recommendations" class="panel"><div id="recommendation-list" class="recommendations"></div></section>
</main>
<script id="provtrail-data" type="application/json">__REPORT_DATA__</script>
<script>
const report=JSON.parse(document.getElementById('provtrail-data').textContent);
const activeStatuses=new Set(['flagged','manual_review']);
const $=(q,root=document)=>root.querySelector(q);
const $$=(q,root=document)=>[...root.querySelectorAll(q)];
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const label=v=>String(v??'unknown').replaceAll('_',' ');
const flagIcon='<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M5 21V4m0 1h9l1.5 2L19 5v9h-9l-1.5-2L5 14"/></svg>';
const reviewIcon='<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M9.8 9a2.3 2.3 0 1 1 3.6 1.9c-.9.6-1.4 1.1-1.4 2.1m0 3.5h.01"/></svg>';
const badge=(v,kind=v)=>`<span class="badge ${esc(kind)}">${kind==='flagged'?flagIcon:kind==='manual_review'?reviewIcon:''}${esc(kind==='manual_review'?'Review':label(v))}</span>`;
const icons={
  folderClosed:'<svg class="icon folder-closed" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6.5h6l2 2h10v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M3 9h18"/></svg>',
  folderOpen:'<svg class="icon folder-open" viewBox="0 0 24 24" aria-hidden="true"><path d="M3 7h6l2 2h9a2 2 0 0 1 1.9 2.6l-2 6A2 2 0 0 1 18 19H5a2 2 0 0 1-1.9-2.6L5 11h16"/></svg>',
  file:'<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v5h5"/><path d="m9 13-2 2 2 2m4-4 2 2-2 2"/></svg>',
  back:'<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m15 18-6-6 6-6"/></svg>',
  chevron:'<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>',
  external:'<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4h6v6m0-6-9 9"/><path d="M18 13v6a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h6"/></svg>'
};
const active=report.findings.filter(f=>activeStatuses.has(f.status));
const byFile=new Map();
for(const f of active){if(!byFile.has(f.path))byFile.set(f.path,[]);byFile.get(f.path).push(f)}
let selectedFile='';

function initSummary(){
  $('#outcome-title').textContent=report.project;
  updateGeneratedTime();
  const a=report.audit;
  const severityItems=Object.entries(a.severity||{}).map(([name,count])=>[`${name[0].toUpperCase()+name.slice(1)} severity`,count,name]);
  const items=[['Flagged',a.flagged,'flagged'],['Manual review',a.manual_review,'manual_review'],...severityItems,['Affected files',byFile.size,''],['Advisories',a.unique_advisories,''],['Functions analyzed',a.total_functions,''],['Reused',a.reused_functions,'']];
  $('#metrics').innerHTML=items.map(([k,v,tone])=>`<div class="metric ${esc(tone)}"><strong>${esc(v)}</strong><span>${esc(k)}</span></div>`).join('');
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
function attentionStatus(findings){return findings.some(f=>f.status==='flagged')?'flagged':findings.some(f=>f.status==='manual_review')?'manual_review':'cleared'}
function fileStatus(path){return attentionStatus(byFile.get(path)||[])}
function branchStats(prefix){const fs=active.filter(f=>f.path.startsWith(prefix));return{count:fs.length,status:attentionStatus(fs)}}
function buildTree(){
  const root={dirs:{},files:[]};
  for(const path of report.scanned_files){const parts=path.split('/');let node=root;for(const part of parts.slice(0,-1))node=node.dirs[part]??={dirs:{},files:[]};node.files.push(parts.at(-1))}
  const hasAffected=(node,prefix)=>node.files.some(name=>byFile.has(prefix+name))||Object.entries(node.dirs).some(([name,child])=>hasAffected(child,prefix+name+'/'));
  const render=(node,prefix='')=>{
    const dirs=Object.entries(node.dirs).sort(([a],[b])=>a.localeCompare(b)).map(([name,child])=>{const childPrefix=prefix+name+'/',stats=branchStats(childPrefix),affected=hasAffected(child,childPrefix);return `<details ${affected?'open':''}><summary>${icons.folderClosed}${icons.folderOpen}<span class="file-name">${esc(name)}</span>${stats.count?`<span class="tree-count badge ${esc(stats.status)}">${stats.count}</span>`:''}</summary>${render(child,childPrefix)}</details>`}).join('');
    const files=node.files.sort().map(name=>{const path=prefix+name,count=(byFile.get(path)||[]).length,status=fileStatus(path);return `<button class="tree-file ${count?'':'unaffected'} ${path===selectedFile?'selected':''}" data-path="${esc(path)}">${icons.file}<span class="file-name">${esc(name)}</span>${count?`<span class="tree-count badge ${esc(status)}">${count}</span>`:''}</button>`}).join('');
    return dirs+files;
  };
  $('#tree').innerHTML=render(root);
  $$('.tree-file').forEach(button=>button.addEventListener('click',()=>selectFile(button.dataset.path)));
}
function codePanel(title,snippet,panelClass=''){
  if(!snippet)return `<div class="code-panel ${esc(panelClass)}"><div class="code-label"><span>${esc(title)}</span></div><div class="empty"><span class="muted">Reference source not recorded.</span></div></div>`;
  const lines=snippet.lines.map(line=>`<div class="code-line ${esc(line.marker)}"><span class="line-no">${line.number}</span><span class="line-text">${esc(line.text)||' '}</span></div>`).join('');
  return `<div class="code-panel ${esc(panelClass)}"><div class="code-label"><span>${esc(title)}</span></div><pre class="code">${lines}</pre>${snippet.truncated?`<div class="truncate">Excerpt limited to ${snippet.lines.length} of ${snippet.total_lines} lines.</div>`:''}</div>`;
}
function scoreRow(name,value,tone){const number=Number(value);if(!Number.isFinite(number))return'';const percent=Math.max(0,Math.min(100,number*100));return `<div class="score"><span>${esc(name)}</span><span class="bar"><span class="bar-fill ${esc(tone)}" style="width:${percent}%"></span></span><strong>${number.toFixed(3)}</strong></div>`}
function externalLink(url,text){return url?`<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text)} ↗</a>`:''}
function advisoryIdentifierLink(url,identifier){return url?`<a class="advisory-id-link" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(identifier)}</a>`:`<span class="advisory-heading-id">${esc(identifier)}</span>`}
function findingCard(f){
  const p=f.primary,e=f.evidence||{};
  const needsReview=f.status==='manual_review';
  const headerBadges=needsReview?badge(f.status):`${badge(f.status)} ${badge(f.severity,f.severity)}`;
  const impact=label(f.severity),potentialImpact=needsReview?`<dt>Potential impact</dt><dd><strong>${esc(impact.charAt(0).toUpperCase()+impact.slice(1))} if confirmed</strong></dd>`:'';
  const ids=[p.cve_id,p.ghsa_id,p.osv_id].filter(Boolean).join(' · ')||p.identifier;
  const identifier=String(p.cve_id||p.ghsa_id||p.osv_id||p.identifier||'Advisory').trim(),title=String(p.title||'').trim();
  const heading=title&&title.toLocaleLowerCase()!==identifier.toLocaleLowerCase()?`${esc(identifier)}: ${esc(title)}`:esc(identifier);
  const advisoryAction=p.advisory_url?`<a class="advisory-action" href="${esc(p.advisory_url)}" target="_blank" rel="noopener noreferrer" aria-label="Open ${esc(identifier)} advisory in a new tab" title="Open advisory in a new tab">${icons.external}</a>`:'';
  const affected=(p.affected_versions||[]).join(', ')||'Not recorded';
  const versions=(p.fixed_versions||[]).join(', ')||'Not recorded';
  return `<details class="finding-card" open><summary class="finding-head"><div><h3>${esc(f.name)}</h3><span class="muted">${esc(f.path)}:${f.start_line}–${f.end_line}</span></div><div class="badge-row">${headerBadges}<span class="finding-chevron">${icons.chevron}</span></div></summary><div class="finding-body"><div class="advisory-heading"><h3><span class="advisory-heading-id">${heading}</span></h3>${advisoryAction}</div><div class="code-compare">${codePanel('Project code',f.reference.candidate,'detected-panel')}<div class="reference-stack">${codePanel('Matched vulnerable reference',f.reference.vulnerable)}${codePanel('Known patched reference',f.reference.patched)}</div></div><div class="detail-grid"><section class="detail-box"><h4>Advisory</h4><dl class="facts">${potentialImpact}<dt>Identifiers</dt><dd>${esc(ids)}</dd><dt>Affected versions</dt><dd>${esc(affected)}</dd><dt>Known fixed versions</dt><dd>${esc(versions)}</dd><dt>Historical package</dt><dd>${esc(p.package_name||'Not recorded')} ${p.ecosystem?`(${esc(p.ecosystem)})`:''}</dd><dt>CWE</dt><dd>${esc((p.cwes||[]).join(', ')||'Not recorded')}</dd><dt>Reference</dt><dd>${esc(p.repo||'Not recorded')} · ${esc(p.file_path||'')}</dd></dl><p class="link-row">${externalLink(p.advisory_url,'Open advisory')} ${externalLink(p.fix_url,'Open fix commit')}</p></section><section class="detail-box"><h4>Detection evidence</h4>${scoreRow('Vulnerable',e.vulnerable_score,'vulnerable')}${scoreRow('Patched',e.patched_score,'patched')}${scoreRow('Retrieval',e.retrieval_similarity,'retrieval')}<dl class="facts"><dt>Confidence</dt><dd>${esc(label(f.confidence))}</dd><dt>Score margin</dt><dd>${Number.isFinite(Number(e.vulnerable_minus_patched))?Number(e.vulnerable_minus_patched).toFixed(3):'Not recorded'}</dd><dt>AST coverage</dt><dd>${Number.isFinite(Number(e.ast_coverage))?Number(e.ast_coverage).toFixed(3):'Not recorded'}</dd><dt>Match type</dt><dd>${esc(f.hash_match_types.join(', ')||'Region similarity')}</dd></dl><p class="muted">Similarity signals are not exploit probability.</p></section></div></div></details>`;
}
function selectFile(path){selectedFile=path;buildTree();renderFile()}
function renderFile(){
  if(!selectedFile){
    const statusRank={flagged:0,manual_review:1,cleared:2};
    const affectedFiles=[...byFile.keys()].sort((a,b)=>statusRank[fileStatus(a)]-statusRank[fileStatus(b)]||a.localeCompare(b));
    $('#file-pane').innerHTML=`<header class="file-heading"><div><h2>${esc(report.project)}</h2><span class="muted">${affectedFiles.length?`${affectedFiles.length} affected file${affectedFiles.length===1?'':'s'}`:'No affected files'}</span></div></header>${affectedFiles.length?`<div class="overview-files">${affectedFiles.map(path=>`<button class="overview-file" data-path="${esc(path)}"><span class="file-name">${esc(path)}</span><span class="tree-count">${badge(fileStatus(path))}</span></button>`).join('')}</div>`:`<div class="empty"><strong>No active findings</strong></div>`}`;
    $$('.overview-file').forEach(button=>button.addEventListener('click',()=>selectFile(button.dataset.path)));
    return;
  }
  const fs=byFile.get(selectedFile)||[];
  $('#file-pane').innerHTML=`<header class="file-heading"><div class="file-title"><button class="back-btn" id="back-project" aria-label="Back to project overview">${icons.back}<span>Back</span></button><div><h2>${esc(selectedFile)}</h2><span class="muted">${fs.length?`${fs.length} finding${fs.length===1?'':'s'} needs review`:'No active findings in this file'}</span></div></div></header>${fs.length?fs.map(findingCard).join(''):`<div class="empty"><div><strong>No active findings</strong><p class="muted">Provtrail analyzed this file without flagging a vulnerability clone.</p></div></div>`}`;
  $('#back-project').addEventListener('click',()=>selectFile(''));
}
function switchTab(id){$$('.tab').forEach(t=>t.setAttribute('aria-selected',String(t.dataset.tab===id)));$$('.panel').forEach(p=>p.classList.toggle('active',p.id===id))}
function renderRows(){
  const query=$('#search').value.trim().toLowerCase(),status=$('#status-filter').value,severity=$('#severity-filter').value;
  const rows=report.findings.filter(f=>{const statusOk=status==='all'||status==='active'&&activeStatuses.has(f.status)||f.status===status;const sevOk=severity==='all'||f.severity===severity;const hay=[f.path,f.name,f.primary.identifier,f.primary.title].join(' ').toLowerCase();return statusOk&&sevOk&&(!query||hay.includes(query))});
  $('#result-count').textContent=`${rows.length} result${rows.length===1?'':'s'}`;
  $('#finding-rows').innerHTML=rows.length?rows.map(f=>`<tr data-file="${esc(f.path)}" tabindex="0"><td>${badge(f.status)}</td><td>${badge(f.severity,f.severity)}</td><td><strong>${esc(f.path)}</strong>:${f.start_line}</td><td>${esc(f.name)}</td><td>${esc(f.primary.title)}</td><td>${esc(label(f.confidence))}</td></tr>`).join(''):`<tr><td colspan="6"><div class="empty"><span class="muted">No findings match these filters.</span></div></td></tr>`;
  $$('tr[data-file]').forEach(row=>{const open=()=>{selectFile(row.dataset.file);switchTab('files')};row.addEventListener('click',open);row.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();open()}})})
}
function renderRecommendations(){
  const root=$('#recommendation-list');
  if(!report.recommendations.length){root.innerHTML=`<div class="empty"><div><strong>No remediation actions</strong><p class="muted">The scan completed without active findings.</p></div></div>`;return}
  root.innerHTML=report.recommendations.map((r,index)=>{
    const affected=r.affected_versions.length?r.affected_versions.join(', '):'Not recorded';
    const fixed=r.fixed_versions.length?r.fixed_versions.join(', '):'Not recorded';
    const removed=r.patch_changes.removed||[],added=r.patch_changes.added||[];
    const changeText=added.length&&removed.length?`Replace the matched behavior in ${r.locations.length} location${r.locations.length===1?'':'s'} with the validation or control flow demonstrated by the known patch.`:added.length?`Add the missing safeguard demonstrated by the known patch to each matched location.`:removed.length?`Remove or constrain the behavior deleted by the known patch in each matched location.`:`Use the known patched implementation as the behavioral baseline for the matched region in ${r.reference_file||'the reference source'}.`;
    const changes=[...removed.map(line=>['Removed',line]),...added.map(line=>['Added',line])];
    const rawTitle=String(r.title||'').trim(),identifier=String(r.identifier||'').trim(),title=rawTitle||identifier||'Advisory';
    const sameTitle=identifier&&identifier.toLocaleLowerCase()===title.toLocaleLowerCase();
    const linkedIdentifier=identifier?advisoryIdentifierLink(r.advisory_url,identifier):'';
    const titleMarkup=identifier?(sameTitle?linkedIdentifier:`${linkedIdentifier}: ${esc(title)}`):esc(title);
    const description=String(r.description||'No advisory summary was recorded.').trim(),expandable=description.length>240,summaryId=`recommendation-summary-${index}`;
    const summaryControl=expandable?`<button class="summary-toggle" type="button" aria-expanded="false" aria-controls="${summaryId}">Show more</button>`:'';
    const packageName=String(r.package_name||'the upstream project');
    const versionGuidance=`Version ranges apply to upstream ${packageName} releases. For copied or adapted code, follow the code change shown here instead of changing a dependency version.`;
    return `<article class="recommendation"><h3>${titleMarkup}</h3><div class="badge-row">${badge(r.severity,r.severity)}</div><p class="recommendation-summary ${expandable?'collapsed':''}" id="${summaryId}">${esc(description)}</p>${summaryControl}<div class="recommendation-grid"><div><div class="version-box"><span class="muted">Historical affected versions</span><strong>${esc(affected)}</strong></div><div class="version-box"><span class="muted">Known fixed versions</span><strong>${esc(fixed)}</strong></div><p class="muted">${esc(versionGuidance)}</p><section class="affected-locations"><h4>Affected locations</h4><div class="locations">${r.locations.map(l=>`<span class="location">${esc(l)}</span>`).join('')}</div></section></div><div><h4>Recommended code change</h4><p>${esc(changeText)}</p>${changes.length?`<div class="patch-lines">${changes.map(([kind,line])=>{const tone=kind.toLowerCase(),marker=kind==='Removed'?'−':'+';return `<div class="patch-line ${tone}"><strong><span aria-hidden="true">${marker}</span> ${kind}</strong><code>${esc(line)}</code></div>`}).join('')}</div>`:`<p class="muted">No diagnostic patch lines were recorded. Inspect the linked fix commit before modifying code.</p>`}<p><strong>Verify:</strong> add a regression test for “${esc(title)}” at the affected locations, then rerun provtrail and confirm these matches are cleared.</p></div></div><p class="link-row">${externalLink(r.advisory_url,'Read advisory')} ${externalLink(r.fix_url,'Inspect fix commit')}</p></article>`
  }).join('');
  $$('.summary-toggle',root).forEach(button=>button.addEventListener('click',()=>{const summary=document.getElementById(button.getAttribute('aria-controls')),expanded=button.getAttribute('aria-expanded')==='true';button.setAttribute('aria-expanded',String(!expanded));button.textContent=expanded?'Show more':'Show less';summary.classList.toggle('collapsed',expanded)}))
}
function initDetails(){const values=[['Project',report.project],['Report schema',report.schema],['Tool version',report.tool_version],['Corpus version',report.corpus_version],['Root hash',report.root_hash],['Model',report.config.model],['Retrieval threshold',report.config.retrieval_threshold],['Minimum vulnerable score',report.config.minimum_vulnerable_score],['Minimum margin',report.config.minimum_margin],['Changed files',report.changed_files.length],['Deleted files',report.deleted_files.length],['Files analyzed',report.scanned_files.length],['Functions recomputed',report.audit.scanned_functions]];$('#scan-details').innerHTML=values.map(([k,v])=>`<div><span>${esc(k)}</span><strong>${esc(v??'Not recorded')}</strong></div>`).join('')}
$$('.tab').forEach(tab=>tab.addEventListener('click',()=>switchTab(tab.dataset.tab)));
['search','status-filter','severity-filter'].forEach(id=>$('#'+id).addEventListener(id==='search'?'input':'change',renderRows));
$('#theme-toggle').addEventListener('click',()=>{const dark=document.documentElement.dataset.theme!=='dark';document.documentElement.dataset.theme=dark?'dark':'light';$('#theme-toggle').textContent=dark?'Light theme':'Dark theme'});
initSummary();buildTree();renderFile();renderRows();renderRecommendations();initDetails();
</script>
</body>
</html>'''
