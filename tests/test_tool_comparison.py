import hashlib
import json

import pytest

from eval.comparison import (
    alert_matches_ground_truth,
    canonical_cwe,
    codeql_wrap_source,
    score_findings,
    select_diverse_origins,
)
from eval.tool_adapters import normalize_codeql, normalize_osv, normalize_provtrail, normalize_semgrep
from scripts.build_tool_comparison import build
from scripts.materialize_tool_comparison import _resolve_target
from provtrail.pipeline.controller.parsing import extract_function_units
from provtrail.pipeline.controller.parsing import parse_source
from scripts.run_tool_comparison import _codeql_extraction


def _origin(index, language, package=None, ghsa=None):
    return {
        "ghsa_id": ghsa or f"GHSA-test-{index:04d}",
        "file_path": f"src/{index}.{'ts' if language == 'typescript' else 'js'}",
        "function_name": f"fn{index}",
        "source_language": language,
        "package_name": package or f"pkg-{index}",
        "category": f"category-{index % 4}",
        "cwes": [f"CWE-{20 + index}"],
    }


def test_canonical_cwe_normalizes_tool_spellings():
    assert canonical_cwe("external/cwe/cwe-079") == "CWE-79"
    assert canonical_cwe({"cwe_id": "CWE_0022"}) == "CWE-22"
    assert canonical_cwe("security") is None


def test_selection_is_deterministic_and_language_balanced():
    origins = [
        _origin(i, "javascript" if i < 20 else "typescript")
        for i in range(40)
    ]
    first = select_diverse_origins(origins, 15, seed=4079)
    second = select_diverse_origins(list(reversed(origins)), 15, seed=4079)
    assert [row["function_name"] for row in first] == [row["function_name"] for row in second]
    assert sum(row["source_language"] == "javascript" for row in first) == 7
    assert sum(row["source_language"] == "typescript" for row in first) == 8


def test_osv_requires_exact_advisory_alias():
    truth = {"advisory_aliases": ["GHSA-aaaa-bbbb-cccc"], "cwes": ["CWE-79"]}
    assert alert_matches_ground_truth(
        "osv-scanner", {"advisory_ids": ["GHSA-aaaa-bbbb-cccc"]}, truth
    )
    assert not alert_matches_ground_truth(
        "osv-scanner", {"advisory_ids": ["GHSA-xxxx-yyyy-zzzz"]}, truth
    )


def test_static_alert_requires_path_and_span_but_not_cwe_overlap():
    truth = {
        "advisory_aliases": ["GHSA-a"], "cwes": ["CWE-79"],
        "target_path": "src/a.js", "target_start_line": 10, "target_end_line": 20,
    }
    matching = {"cwes": ["CWE-079"], "path": "src/a.js", "start_line": 12, "end_line": 13}
    assert alert_matches_ground_truth("codeql", matching, truth)
    assert not alert_matches_ground_truth("codeql", {**matching, "start_line": 30}, truth)
    assert alert_matches_ground_truth("semgrep", {**matching, "cwes": ["CWE-22"]}, truth)


def test_codeql_uses_wrapped_target_path_and_span():
    truth = {
        "cwes": ["CWE-79"], "target_path": "detached/src/C1.js",
        "target_start_line": 1, "target_end_line": 3,
        "tool_targets": {"codeql": {
            "path": "src/C1.js", "start_line": 2, "end_line": 4,
        }},
    }
    alert = {"cwes": ["CWE-79"], "path": "src/C1.js", "start_line": 3, "end_line": 3}
    assert alert_matches_ground_truth("codeql", alert, truth)


@pytest.mark.parametrize(("source", "kind"), [
    ("function (value) { return value; }", "function_expression"),
    ("decode(value) { return value; }", "class_method"),
])
def test_codeql_wrapper_produces_valid_standalone_source_and_spans(source, kind):
    wrapped = codeql_wrap_source(source, "javascript")
    assert wrapped["wrapper_kind"] == kind
    assert not parse_source(wrapped["source"], language="javascript").root_node.has_error
    target_lines = wrapped["source"].splitlines()[
        wrapped["target_start_line"] - 1:wrapped["target_end_line"]
    ]
    assert source.splitlines()[0] in "\n".join(target_lines)


def test_codeql_missing_target_is_an_execution_coverage_failure(tmp_path):
    case = {"input": {"kind": "github_source", "target_path": "src/a.js",
                      "target_start_line": 10, "target_end_line": 20}}
    result = _codeql_extraction(case, tmp_path, [], tmp_path)
    assert result["target_extracted"] is False
    assert result["execution_error"].startswith("target_not_extracted:")


def test_score_findings_keeps_background_alerts_out_of_false_positives():
    cases = [
        {"case_id": "C1", "arm": "detached_clone"},
        {"case_id": "C2", "arm": "detached_clone"},
    ]
    truths = [
        {"case_id": "C1", "origin_id": "O1", "expected_status": "vulnerable",
         "advisory_aliases": ["GHSA-a"], "cwes": ["CWE-79"], "target_path": "a.js",
         "target_start_line": 1, "target_end_line": 5},
        {"case_id": "C2", "origin_id": "O1", "expected_status": "patched",
         "advisory_aliases": ["GHSA-a"], "cwes": ["CWE-79"], "target_path": "b.js",
         "target_start_line": 1, "target_end_line": 5},
    ]
    findings = [
        {"record_type": "execution", "tool": "semgrep", "case_id": "C1", "completed": True},
        {"record_type": "execution", "tool": "semgrep", "case_id": "C2", "completed": True},
        {"tool": "semgrep", "case_id": "C1", "path": "a.js", "start_line": 2,
         "end_line": 2, "cwes": ["CWE-79"], "advisory_ids": []},
        {"tool": "semgrep", "case_id": "C2", "path": "b.js", "start_line": 20,
         "end_line": 20, "cwes": ["CWE-22"], "advisory_ids": []},
    ]
    result = score_findings(cases, truths, findings)
    semgrep = result["summary"]["semgrep/detached_clone"]
    assert semgrep["true_positive"] == 1
    assert semgrep["false_positive"] == 0
    assert semgrep["background_alerts"] == 1


def test_execution_error_is_not_scored_as_miss():
    cases = [{"case_id": "C1", "arm": "real_source"}]
    truths = [{"case_id": "C1", "origin_id": "O1", "expected_status": "vulnerable",
               "advisory_aliases": ["GHSA-a"], "cwes": [], "target_path": "a.js"}]
    findings = [{"tool": "codeql", "case_id": "C1", "execution_error": "timeout"}]
    result = score_findings(cases, truths, findings)
    summary = result["summary"]["codeql/real_source"]
    assert summary["completed"] == 0
    assert summary["false_negative"] == 0


def test_real_pilot_builds_opaque_balanced_cases():
    cases, truths, metadata = build(15, 4079, False)
    assert metadata["catalog_origin_count"] >= 50
    assert len(cases) == len(truths) == 90
    assert {row["arm"] for row in cases} == {
        "real_source", "detached_clone", "dependency_metadata"
    }
    assert all("expected_status" not in row for row in cases)
    assert sum(row["expected_status"] == "vulnerable" for row in truths) == 45
    detached = [row for row in cases if row["arm"] == "detached_clone"]
    assert all(len(extract_function_units(row["input"]["source"], filename="candidate.ts")) == 1
               for row in detached)


def test_expanded_comparison_selects_50_balanced_origins():
    cases, truths, metadata = build(50, 4079, False)
    assert metadata["origin_count"] == 50
    assert len(cases) == len(truths) == 300
    origins = {row["origin_id"]: row["source_language"] for row in cases}
    assert sum(language == "javascript" for language in origins.values()) == 25
    assert sum(language == "typescript" for language in origins.values()) == 25


def test_materialized_target_lines_are_one_based():
    source = "const before = true;\nconst target = () => true;\n"
    unit = extract_function_units(source, filename="example.js")[0]
    target_hash = hashlib.sha256(unit.source.encode("utf-8")).hexdigest()

    assert _resolve_target(source, "example.js", target_hash, unit.name) == (2, 2)


def test_normalizers_extract_common_security_identity():
    semgrep = normalize_semgrep({"results": [{
        "check_id": "js.xss", "path": "src/a.js", "start": {"line": 2}, "end": {"line": 3},
        "extra": {"metadata": {"cwe": "CWE-079"}, "message": "xss", "severity": "ERROR"},
    }]})[0]
    assert semgrep["cwes"] == ["CWE-79"]

    codeql = normalize_codeql({"runs": [{
        "tool": {"driver": {"rules": [{"id": "js/xss", "properties": {"tags": ["external/cwe/cwe-079"]}}]}},
        "results": [{"ruleId": "js/xss", "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "src/a.js"}, "region": {"startLine": 4}
        }}]}],
    }]})[0]
    assert codeql["cwes"] == ["CWE-79"]

    osv = normalize_osv({"results": [{"source": {"path": "package-lock.json"}, "packages": [{
        "package": {"name": "x", "version": "1.0.0"},
        "vulnerabilities": [{"id": "GHSA-2345-6789-cfgh", "aliases": ["CVE-2025-1234"]}],
    }]}]})[0]
    assert osv["advisory_ids"] == ["CVE-2025-1234", "GHSA-2345-6789-CFGH"]

    provtrail = normalize_provtrail({"findings": [{
        "path": "src/a.js", "start_line": 1, "end_line": 5,
        "result": {"priority": "automatic_vulnerability", "lineages": [{
            "associated_advisories": [{"ghsa_id": "GHSA-2345-6789-cfgh", "cwes": ["CWE-79"]}]
        }]},
    }]})[0]
    assert provtrail["priority"] == "automatic_vulnerability"
    assert "GHSA-2345-6789-CFGH" in provtrail["advisory_ids"]
