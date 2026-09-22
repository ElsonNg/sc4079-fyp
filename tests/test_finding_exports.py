import json
from pathlib import Path

import jsonschema

from provtrail.cli.main import main
from provtrail.pipeline.controller.finding_exports import build_sarif, format_ai, project_findings


SCHEMA = json.loads((Path(__file__).parent / "fixtures" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8"))


def _report(root: str = "/tmp/project") -> dict:
    alias = {"cve_id": "CVE-2026-1234", "ghsa_id": "GHSA-test", "package_name": "axios"}
    findings = []
    for index, (path, priority) in enumerate((
        ("src\\space name.js", "automatic_vulnerability"),
        ("src\\review.js", "manual_review"),
        ("src\\safe.js", "informational_lineage"),
    )):
        findings.append({
            "function_id": f"function-{index}", "function_hash": f"hash-{index}",
            "path": path, "name": f"function{index}", "start_line": index, "end_line": index + 2,
            "result": {
                "priority": priority,
                "lineages": [{"confidence": "high", "associated_advisories": [alias]}],
                "package_applicabilities": [{"package": "axios", "status": "affected"}],
                "vulnerability_states": [{
                    "fix_boundary_id": f"boundary-{index}",
                    "status": "vulnerable" if index == 0 else "uncertain",
                    "abstention_reason": "E_MARGIN_AMBIGUOUS",
                    "advisories": [{"cve_id": "CVE-2026-5678", "package_name": "axios"}] if index == 0 else [],
                }],
            },
        })
    findings[1]["review_explanation"] = {
        "status": "generated", "llm_verdict": "dismissed", "fix_boundary_id": "boundary-1",
    }
    return {"schema": "provtrail_scan_v5", "target_root": root, "findings": findings}


def test_sarif_schema_and_ai_have_same_actionable_findings():
    report = _report()
    sarif = build_sarif(report, tool_version="0.1.0")
    jsonschema.validate(sarif, SCHEMA)
    results = sarif["runs"][0]["results"]
    ai = format_ai(report)

    assert len(project_findings(report)) == len(results) == 2
    by_rule = {item["ruleId"]: item for item in results}
    assert set(by_rule) == {"provtrail/vulnerable-code", "provtrail/manual-review"}
    assert by_rule["provtrail/vulnerable-code"]["level"] == "error"
    assert by_rule["provtrail/manual-review"]["level"] == "note"
    vulnerable = by_rule["provtrail/vulnerable-code"]
    assert vulnerable["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "src/space%20name.js"
    assert vulnerable["locations"][0]["physicalLocation"]["region"] == {"startLine": 1, "endLine": 3}
    assert by_rule["provtrail/manual-review"]["properties"]["provtrail"]["llmVerdict"] == "dismissed"
    assert "CVE-2026-1234" in ai and "CVE-2026-5678" in ai and "GHSA-test" in ai
    assert "axios:affected" in ai and "ollama=dismissed" in ai
    assert "safe.js" not in ai
    assert "total=2 vuln=1 review=1" in ai


def test_empty_report_is_valid_sarif_and_ai():
    report = {"schema": "provtrail_scan_v5", "target_root": "/tmp/project", "findings": []}
    sarif = build_sarif(report, tool_version="0.1.0")
    jsonschema.validate(sarif, SCHEMA)
    assert sarif["runs"][0]["results"] == []
    assert format_ai(report).endswith("total=0 vuln=0 review=0\n")


def test_exports_keep_review_but_omit_opinion_for_a_different_boundary():
    report = _report()
    explanation = report["findings"][1]["review_explanation"]
    for boundary_id in (None, "different-fix"):
        explanation["fix_boundary_id"] = boundary_id
        results = build_sarif(report, tool_version="0.1.0")["runs"][0]["results"]
        review = next(item for item in results if item["ruleId"] == "provtrail/manual-review")
        assert review["properties"]["provtrail"]["llmVerdict"] is None
        ai = format_ai(report)
        assert "ollama=" not in ai
        assert "total=2 vuln=1 review=1" in ai


def test_saved_report_ai_stdout_and_collisions(tmp_path, capsys):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report(str(tmp_path))), encoding="utf-8")
    sarif_path = tmp_path / "output.sarif"

    assert main(["report", str(path), "--ai-output", "-", "--sarif-output", str(sarif_path)]) == 1
    captured = capsys.readouterr()
    assert captured.out.startswith("ProvTrail AI v1\n")
    assert "SCAN RESULT" not in captured.out
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["runs"][0]["results"]

    assert main(["report", str(path), "--ai-output", "-", "--json"]) == 2
    assert "cannot be combined" in capsys.readouterr().err
    assert main(["report", str(path), "--sarif-output", str(path)]) == 2
    assert "must be distinct" in capsys.readouterr().err
    assert main(["report", str(path), "--sarif-output", "-"]) == 2
    assert "requires a file path" in capsys.readouterr().err


def test_default_report_output_is_unchanged(tmp_path, capsys):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report(str(tmp_path))), encoding="utf-8")
    assert main(["report", str(path)]) == 1
    assert "PROVTRAIL SCAN RESULT" in capsys.readouterr().out


def test_scan_rejects_colliding_paths_before_loading_corpus(tmp_path, capsys):
    target = tmp_path / "project"
    target.mkdir()
    assert main(["scan", str(target), "--json", "--ai-output", "-"]) == 2
    assert "cannot be combined" in capsys.readouterr().err
    assert main(["scan", str(target), "--sarif-output", str(target / ".provtrail" / "latest-scan.json")]) == 2
    assert "must be distinct" in capsys.readouterr().err


def test_export_order_and_fingerprints_are_stable():
    report = _report()
    first = build_sarif(report, tool_version="0.1.0")["runs"][0]["results"]
    report["findings"].reverse()
    second = build_sarif(report, tool_version="0.1.0")["runs"][0]["results"]
    assert first == second
