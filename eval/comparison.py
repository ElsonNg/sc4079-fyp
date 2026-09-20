"""Shared schemas, selection, normalization, and scoring for tool comparison."""

from __future__ import annotations

import hashlib
import json
import math
import random
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable, Mapping

from provtrail.pipeline.controller.parsing import parse_source


SCHEMA_VERSION = "provtrail_tool_comparison_v1"
TOOLS = ("provtrail", "semgrep", "codeql", "osv-scanner")
_CWE_RE = re.compile(r"CWE[-_ ]?0*(\d+)", re.IGNORECASE)


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: Iterable[Mapping]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(dict(row), sort_keys=True) + "\n" for row in rows)
    path.write_text(text, encoding="utf-8")


def origin_key(record: Mapping) -> tuple[str, str, str | None]:
    entry = record.get("corpus_entry") or record
    return (
        str(entry.get("ghsa_id") or record.get("ghsa_id") or ""),
        str(entry.get("file_path") or record.get("corpus_file_path") or "").replace("\\", "/"),
        entry.get("function_name"),
    )


def origin_id(key: tuple[str, str, str | None]) -> str:
    value = "\0".join("" if item is None else str(item) for item in key)
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def canonical_cwe(value: object) -> str | None:
    if isinstance(value, Mapping):
        value = value.get("cwe_id") or value.get("id") or value.get("name")
    match = _CWE_RE.search(str(value or ""))
    return f"CWE-{int(match.group(1))}" if match else None


def cwe_set(values: Iterable[object]) -> set[str]:
    return {item for value in values if (item := canonical_cwe(value))}


def _expand_compact_source(source: str, language: str) -> str:
    """Insert semantics-neutral newlines after punctuation tokens in one-line code."""
    if "\n" in source or len(source) <= 120:
        return source
    tree = parse_source(source, language=language)
    encoded = source.encode("utf-8")
    boundaries: set[int] = set()

    def walk(node) -> None:
        if not node.children:
            token = encoded[node.start_byte:node.end_byte]
            if token in {b"{", b"}", b";"}:
                boundaries.add(node.end_byte)
            return
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    if not boundaries:
        return source
    output = bytearray()
    previous = 0
    for boundary in sorted(boundaries):
        output.extend(encoded[previous:boundary])
        output.extend(b"\n")
        previous = boundary
    output.extend(encoded[previous:])
    return output.decode("utf-8")


def codeql_wrap_source(source: str, language: str) -> dict:
    """Make function expressions and method fragments valid standalone CodeQL input."""
    expanded = _expand_compact_source(source.strip(), language)
    expression_prefix = "const __provtrailComparisonTarget = (\n"
    expression_suffix = "\n);\n"
    expression = expression_prefix + expanded + expression_suffix
    if not parse_source(expression, language=language).root_node.has_error:
        wrapped, kind, prefix = expression, "function_expression", expression_prefix
    else:
        class_prefix = "class __ProvTrailComparisonTarget {\n"
        class_suffix = "\n}\n"
        wrapped = class_prefix + expanded + class_suffix
        if parse_source(wrapped, language=language).root_node.has_error:
            body_prefix = "function __provtrailComparisonTarget() {\n"
            body_suffix = "\n}\n"
            wrapped = body_prefix + expanded + body_suffix
            if parse_source(wrapped, language=language).root_node.has_error:
                raise ValueError(
                    "candidate cannot be wrapped as an expression, class method, or function body"
                )
            kind, prefix = "function_body", body_prefix
        else:
            kind, prefix = "class_method", class_prefix
    start = prefix.count("\n") + 1
    return {
        "source": wrapped,
        "wrapper_kind": kind,
        "target_start_line": start,
        "target_end_line": start + expanded.count("\n"),
    }


def aliases(record: Mapping) -> list[str]:
    entry = record.get("corpus_entry") or record
    values = {
        entry.get("ghsa_id"), entry.get("cve_id"), record.get("osv_id"), record.get("ghsa_id")
    }
    return sorted(str(value) for value in values if value)


def _stable_tiebreak(seed: int, key: tuple) -> str:
    return hashlib.sha256(f"{seed}|{key!r}".encode("utf-8")).hexdigest()


def select_diverse_origins(origins: list[dict], count: int, *, seed: int = 4079) -> list[dict]:
    """Greedy, outcome-blind stratification over language, package, category, and CWE."""
    if count < 1:
        raise ValueError("count must be positive")
    by_language: dict[str, list[dict]] = defaultdict(list)
    for row in origins:
        by_language[str(row["source_language"])].append(row)
    languages = ("javascript", "typescript")
    targets = {languages[0]: count // 2, languages[1]: count - count // 2}
    if any(len(by_language[language]) < targets[language] for language in languages):
        raise ValueError(f"insufficient language-balanced origins for {count} cases")

    # The 50-origin expansion exhausts all 25 eligible JavaScript origins.
    # Its catalog contains up to seven origins per package and three per
    # advisory, so those are the smallest feasible caps at that scale.
    package_cap = 2 if count <= 15 else max(7, math.ceil(count / 10))
    advisory_cap = 1 if count <= 15 else 3
    selected: list[dict] = []
    package_counts: Counter = Counter()
    advisory_counts: Counter = Counter()
    used_packages: set[str] = set()
    used_cwes: set[str] = set()
    used_categories: set[str] = set()

    for language in languages:
        candidates = list(by_language[language])
        while sum(row["source_language"] == language for row in selected) < targets[language]:
            eligible = [
                row for row in candidates
                if row not in selected
                and package_counts[row["package_name"]] < package_cap
                and advisory_counts[row["ghsa_id"]] < advisory_cap
            ]
            if not eligible:
                raise ValueError(f"diversity constraints cannot select {targets[language]} {language} origins")
            eligible.sort(key=lambda row: (
                -(row["package_name"] not in used_packages),
                -len(set(row["cwes"]) - used_cwes),
                -(row["category"] not in used_categories),
                package_counts[row["package_name"]],
                _stable_tiebreak(seed, origin_key(row)),
            ))
            chosen = eligible[0]
            selected.append(chosen)
            package_counts[chosen["package_name"]] += 1
            advisory_counts[chosen["ghsa_id"]] += 1
            used_packages.add(chosen["package_name"])
            used_cwes.update(chosen["cwes"])
            used_categories.add(chosen["category"])

    rng = random.Random(seed)
    rng.shuffle(selected)
    return selected


def alert_matches_ground_truth(tool: str, alert: Mapping, truth: Mapping) -> bool:
    """Decide whether an alert flags the labelled target.

    General static analyzers are credited for any target-overlapping alert. CWE
    and advisory identity are reported separately rather than used as gates.
    """
    expected_aliases = {str(value).upper() for value in truth.get("advisory_aliases", [])}
    alert_aliases = {str(value).upper() for value in alert.get("advisory_ids", [])}
    if tool == "osv-scanner":
        return bool(expected_aliases & alert_aliases)
    if tool == "provtrail":
        return (
            alert.get("priority") == "automatic_vulnerability"
            and bool(expected_aliases & alert_aliases)
        )
    tool_target = (truth.get("tool_targets") or {}).get(tool, {})
    expected_path = str(tool_target.get("path") or truth.get("target_path") or "").replace("\\", "/")
    alert_path = str(alert.get("path") or "").replace("\\", "/")
    if expected_path and not (alert_path == expected_path or alert_path.endswith("/" + expected_path)):
        return False
    target_start = tool_target.get("start_line", truth.get("target_start_line"))
    target_end = tool_target.get("end_line", truth.get("target_end_line"))
    alert_start = alert.get("start_line")
    alert_end = alert.get("end_line", alert_start)
    if None in {target_start, target_end, alert_start, alert_end}:
        return bool(alert.get("manually_adjudicated_relevant"))
    return int(alert_start) <= int(target_end) and int(alert_end) >= int(target_start)


def alert_identity_evidence(alert: Mapping, truth: Mapping) -> tuple[bool, bool]:
    """Return advisory-alias and CWE alignment without affecting detection."""
    expected_aliases = {str(value).upper() for value in truth.get("advisory_aliases", [])}
    alert_aliases = {str(value).upper() for value in alert.get("advisory_ids", [])}
    expected_cwes = cwe_set(truth.get("cwes", []))
    alert_cwes = cwe_set(alert.get("cwes", []))
    return bool(expected_aliases & alert_aliases), bool(expected_cwes & alert_cwes)


def score_findings(cases: Iterable[Mapping], truths: Iterable[Mapping], findings: Iterable[Mapping]) -> dict:
    case_map = {row["case_id"]: dict(row) for row in cases}
    truth_map = {row["case_id"]: dict(row) for row in truths}
    grouped: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for finding in findings:
        grouped[(str(finding["tool"]), str(finding["case_id"]))].append(dict(finding))

    rows = []
    for tool in TOOLS:
        for case_id, case in case_map.items():
            truth = truth_map[case_id]
            records = grouped.get((tool, case_id), [])
            executions = [row for row in records if row.get("record_type") == "execution"]
            alerts = [row for row in records if row.get("record_type", "finding") == "finding"]
            relevant = [alert for alert in alerts if alert_matches_ground_truth(tool, alert, truth)]
            advisory_attributed = any(alert_identity_evidence(alert, truth)[0] for alert in relevant)
            cwe_aligned = any(alert_identity_evidence(alert, truth)[1] for alert in relevant)
            completed = (
                bool(executions[-1].get("completed", False))
                if executions else False
            )
            target_extracted = (
                executions[-1].get("target_extracted")
                if executions and case["arm"] in {"real_source", "detached_clone"}
                else None
            )
            expected = truth["expected_status"]
            detected = bool(relevant)
            outcome = (
                "execution_error" if not completed else
                "true_positive" if expected == "vulnerable" and detected else
                "false_negative" if expected == "vulnerable" else
                "false_positive" if detected else "true_negative"
            )
            rows.append({
                "tool": tool,
                "case_id": case_id,
                "origin_id": truth["origin_id"],
                "arm": case["arm"],
                "expected_status": expected,
                "detected": detected,
                "outcome": outcome,
                "target_extracted": target_extracted,
                "relevant_alert_count": len(relevant),
                "advisory_attributed": advisory_attributed,
                "cwe_aligned": cwe_aligned,
                "background_alert_count": len(alerts) - len(relevant),
            })

    summaries = {}
    for tool in TOOLS:
        for arm in sorted({row["arm"] for row in rows}):
            scoped = [row for row in rows if row["tool"] == tool and row["arm"] == arm]
            completed = [row for row in scoped if row["outcome"] != "execution_error"]
            positive = [row for row in completed if row["expected_status"] == "vulnerable"]
            negative = [row for row in completed if row["expected_status"] == "patched"]
            tp = sum(row["outcome"] == "true_positive" for row in positive)
            fp = sum(row["outcome"] == "false_positive" for row in negative)
            extraction_rows = [row for row in scoped if row["target_extracted"] is not None]
            extracted = sum(row["target_extracted"] is True for row in extraction_rows)
            summaries[f"{tool}/{arm}"] = {
                "cases": len(scoped),
                "completed": len(completed),
                "execution_coverage": len(completed) / len(scoped) if scoped else None,
                "target_extraction_cases": len(extraction_rows),
                "target_extracted": extracted,
                "target_extraction_coverage": (
                    extracted / len(extraction_rows) if extraction_rows else None
                ),
                "true_positive": tp,
                "false_negative": len(positive) - tp,
                "false_positive": fp,
                "true_negative": len(negative) - fp,
                "vulnerable_recall": tp / len(positive) if positive else None,
                "patched_false_positive_rate": fp / len(negative) if negative else None,
                "advisory_attributed_cases": sum(row["advisory_attributed"] for row in completed),
                "cwe_aligned_cases": sum(row["cwe_aligned"] for row in completed),
                "background_alerts": sum(row["background_alert_count"] for row in scoped),
            }
    return {"schema": SCHEMA_VERSION, "summary": summaries, "results": rows}
