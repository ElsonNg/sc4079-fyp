import json

from cli.main import _scan_progress, main
from pipeline.controller.reporting import (
    audit_summary,
    final_metrics,
    format_attention,
    format_audit_summary,
    format_verbose,
    report_view,
)


def _report() -> dict:
    return {
        "schema": "provtrail_scan_v1",
        "target_root": "/tmp/project",
        "total_files": 3,
        "total_functions": 3,
        "scanned_functions": 3,
        "reused_functions": 0,
        "changed_files": ["src/a.js"],
        "findings": [
            {
                "function_id": "src/a.js::0:10",
                "path": "src/a.js",
                "name": "request",
                "start_line": 0,
                "end_line": 4,
                "result": {
                    "status": "flagged",
                    "provenance_confidence": "high",
                    "hash_match_types": [],
                    "hash_matches": [
                        {
                            "ghsa_id": "GHSA-test",
                            "cve_id": "CVE-2026-1234",
                            "osv_id": "GHSA-test",
                            "side": "vulnerable",
                            "match_type": "abstracted",
                            "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}],
                            "severity": "high",
                            "package_name": "axios",
                            "ecosystem": "npm",
                            "affected_versions": ["1.0.0", "< 1.15.0"],
                            "fixed_versions": ["1.15.0"],
                            "repo": "axios/axios",
                            "fix_commit_sha": "abc123",
                            "file_path": "lib/http.js",
                            "function_name": "request",
                        }
                    ],
                    "aggregates": [],
                    "evidence": [],
                },
            },
            {
                "function_id": "src/b.js::0:10",
                "path": "src/b.js",
                "name": "otherRequest",
                "start_line": 0,
                "end_line": 4,
                "review_explanation": {
                    "status": "generated",
                    "model": "qwen3:8b",
                    "relevance_tier": 2,
                    "llm_verdict": "needs_review",
                    "verdict_rationale": "Redirect validation is not visible in this region.",
                    "security_mechanism": "Redirect destinations must be validated.",
                    "review_steps": ["Trace redirect destinations through the request path."],
                },
                "result": {
                    "status": "manual_review",
                    "provenance_confidence": "ambiguous",
                    "hash_match_types": [],
                    "hash_matches": [],
                    "aggregates": [
                        {
                            "pair_id": "pair-1",
                            "best_similarity": 0.88,
                            "support_count": 2,
                            "candidate_region_ids": [],
                            "granularities": ["changed", "block"],
                            "top_matches": [
                                {
                                    "pair_id": "pair-1",
                                    "similarity": 0.88,
                                    "rank": 1,
                                    "candidate_region_id": "candidate:b",
                                    "candidate_granularity": "changed",
                                    "corpus_granularity": "changed",
                                    "ghsa_id": "GHSA-test",
                                    "cve_id": "CVE-2026-1234",
                                    "osv_id": "GHSA-test",
                                    "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}],
                                    "severity": "high",
                                    "package_name": "axios",
                                    "ecosystem": "npm",
                                    "affected_versions": ["1.0.0", "< 1.15.0"],
                                    "fixed_versions": ["1.15.0"],
                                    "fix_commit_sha": "abc123",
                                    "file_path": "lib/http.js",
                                    "function_name": "request",
                                }
                            ],
                        }
                    ],
                    "evidence": [
                        {
                            "pair_id": "pair-1",
                            "vulnerable_score": 0.91,
                            "patched_score": 0.62,
                            "vulnerable_minus_patched": 0.29,
                            "retrieval_similarity": 0.88,
                        }
                    ],
                },
            },
            {
                "function_id": "src/c.js::0:10",
                "path": "src/c.js",
                "name": "safe",
                "start_line": 0,
                "end_line": 2,
                "result": {
                    "status": "cleared",
                    "hash_matches": [],
                    "aggregates": [],
                    "evidence": [],
                },
            },
        ],
    }


def test_audit_summary_counts_findings_and_unique_advisories():
    summary = audit_summary(_report())

    assert summary["findings"] == 2
    assert summary["flagged"] == 1
    assert summary["manual_review"] == 1
    assert summary["cleared"] == 1
    assert summary["unique_advisories"] == 1
    assert summary["severity"] == {"high": 2}


def test_final_metrics_separate_deterministic_and_llm_outcomes():
    metrics = final_metrics(_report())

    assert metrics["deterministic_flagged"] == 1
    assert metrics["llm_escalated"] == 0
    assert metrics["llm_dismissed"] == 0
    assert metrics["llm_needs_review"] == 1
    assert metrics["attention"] == {"high": 2, "medium": 0, "low": 0}
    assert metrics["final_findings"] == 2


def test_audit_summary_has_divided_sections_and_final_counts():
    output = format_audit_summary(_report())

    assert "PROVTRAIL SCAN RESULT" in output
    assert "✖ 2 vulnerability clone finding(s) · 2 requiring attention (!)" in output
    assert "SCAN OVERVIEW" in output
    assert "RESULTS" in output
    assert "DETERMINISTIC RESULTS" not in output
    assert "SEVERITY" in output
    assert "FINAL METRICS" in output
    assert "advisories:            1" in output
    assert "security advisories" not in output
    assert "unique advisories:" not in output
    assert "Deterministic flagged: 1" in output
    assert "LLM needs review:      1" in output
    assert "LLM unavailable:" not in output
    assert "LLM not run:" not in output
    assert "escalation rate:" not in output
    assert "LLM review coverage:" not in output
    assert "target recall:" not in output
    assert "total escalated:" not in output
    assert output.count("─" * 72) >= 5


def test_final_findings_counts_every_item_still_requiring_attention():
    report = _report()
    output = format_attention(report)
    assert "ATTENTION" in output
    assert "High:                  2" in output
    assert "Medium:                0" in output
    assert "Low:                   0" in output
    assert "Total:                 2" in output

    report["findings"][1]["review_explanation"]["llm_verdict"] = "dismissed"
    assert final_metrics(report)["final_findings"] == 1
    assert "Total:                 1" in format_attention(report)
    assert "✖ 2 vulnerability clone finding(s) · 1 requiring attention (!)" in format_audit_summary(report)


def test_verbose_report_contains_cve_and_version_metadata():
    output = format_verbose(_report())

    assert "CVE-2026-1234 / GHSA-test" in output
    assert "affected versions:" in output
    assert "1.0.0, < 1.15.0" in output
    assert "fixed versions:" in output
    assert "1.15.0" in output
    assert "score margin:           0.290" in output
    assert "local explanation:      generated" in output
    assert "model:                qwen3:8b" in output
    assert "LLM verdict:          needs_review" in output
    assert "relevance tier:       2 / 3" in output
    assert "Redirect validation is not visible in this region." in output
    assert "Trace redirect destinations through the request path." in output


def test_report_view_excludes_cleared_by_default_and_can_include_them():
    report = _report()

    assert len(report_view(report)["findings"]) == 2
    assert len(report_view(report, include_cleared=True)["findings"]) == 3
    assert report_view(report)["findings"][1]["review_explanation"]["model"] == "qwen3:8b"


def test_cli_report_reads_saved_json_without_detector(tmp_path, capsys):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(_report()), encoding="utf-8")

    exit_code = main(["report", str(path), "--verbose"])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "CVE-2026-1234" in output
    assert "affected versions:" in output


def test_cli_report_returns_zero_when_all_findings_are_cleared(tmp_path, capsys):
    report = _report()
    report["findings"] = [report["findings"][-1]]
    path = tmp_path / "cleared.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    assert main(["report", str(path)]) == 0
    assert "No vulnerability clone findings" in capsys.readouterr().out


def test_scan_progress_is_written_to_stderr(capsys):
    _scan_progress({"phase": "detector_start"})
    _scan_progress(
        {
            "phase": "function_complete",
            "function_index": 2,
            "function_count": 5,
            "name": "request",
            "status": "flagged",
            "source": "scanned",
        }
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "loading model and AST-region index" in captured.err
    assert "[function 2/5] request: flagged (scanned)" in captured.err
