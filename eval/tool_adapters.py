"""Normalize ProvTrail, Semgrep, CodeQL, and OSV JSON into one finding model."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Mapping

from eval.comparison import canonical_cwe

_ADVISORY_RE = re.compile(r"\b(?:GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}|CVE-\d{4}-\d{4,})\b", re.I)


def _walk_strings(value) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)


def evidence_ids(value) -> tuple[list[str], list[str]]:
    text = "\n".join(_walk_strings(value))
    advisories = sorted({match.group(0).upper() for match in _ADVISORY_RE.finditer(text)})
    cwes = sorted({item for item in (canonical_cwe(value) for value in _walk_strings(value)) if item})
    return advisories, cwes


def _relative(path: object) -> str:
    return str(path or "").replace("\\", "/").lstrip("./")


def normalize_provtrail(payload: Mapping) -> list[dict]:
    rows = []
    for finding in payload.get("findings", []):
        result = finding.get("result", {})
        advisories, cwes = evidence_ids(result)
        rows.append({
            "path": _relative(finding.get("path")), "start_line": finding.get("start_line"),
            "end_line": finding.get("end_line"), "rule_id": "provtrail-lineage",
            "priority": result.get("priority"), "advisory_ids": advisories, "cwes": cwes,
            "message": result.get("message"),
        })
    return rows


def normalize_semgrep(payload: Mapping) -> list[dict]:
    rows = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        advisories, cwes = evidence_ids(metadata)
        rows.append({
            "path": _relative(result.get("path")), "start_line": (result.get("start") or {}).get("line"),
            "end_line": (result.get("end") or {}).get("line"), "rule_id": result.get("check_id"),
            "priority": None, "advisory_ids": advisories, "cwes": cwes,
            "severity": extra.get("severity"), "message": extra.get("message"),
        })
    return rows


def normalize_codeql(payload: Mapping) -> list[dict]:
    rows = []
    for run in payload.get("runs", []):
        rules = {
            rule.get("id"): rule
            for rule in (run.get("tool", {}).get("driver", {}).get("rules", []) or [])
        }
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            rule = rules.get(rule_id, {})
            advisories, cwes = evidence_ids(rule)
            for location in result.get("locations", []) or [{}]:
                physical = location.get("physicalLocation", {})
                region = physical.get("region", {})
                artifact = physical.get("artifactLocation", {})
                rows.append({
                    "path": _relative(artifact.get("uri")), "start_line": region.get("startLine"),
                    "end_line": region.get("endLine", region.get("startLine")), "rule_id": rule_id,
                    "priority": None, "advisory_ids": advisories, "cwes": cwes,
                    "severity": result.get("level"),
                    "message": (result.get("message") or {}).get("text"),
                })
    return rows


def normalize_osv(payload: Mapping) -> list[dict]:
    rows = []
    for result in payload.get("results", []):
        source = result.get("source", {})
        for package in result.get("packages", []) or []:
            package_value = package.get("package", {})
            for vulnerability in package.get("vulnerabilities", []) or []:
                ids = {vulnerability.get("id"), *(vulnerability.get("aliases") or [])}
                rows.append({
                    "path": _relative(source.get("path")), "start_line": None, "end_line": None,
                    "rule_id": vulnerability.get("id"), "priority": None,
                    "advisory_ids": sorted(str(value).upper() for value in ids if value),
                    "cwes": [], "package": package_value.get("name"),
                    "version": package_value.get("version"),
                    "message": vulnerability.get("summary"),
                })
    return rows


NORMALIZERS = {
    "provtrail": normalize_provtrail,
    "semgrep": normalize_semgrep,
    "codeql": normalize_codeql,
    "osv-scanner": normalize_osv,
}


def load_and_normalize(tool: str, path: Path) -> list[dict]:
    return NORMALIZERS[tool](json.loads(path.read_text(encoding="utf-8")))
