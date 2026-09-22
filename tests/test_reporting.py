import json

from provtrail.cli.main import _scan_progress, main
from provtrail.pipeline.controller.reporting import (
    audit_summary,
    final_metrics,
    format_attention,
    format_audit_summary,
    format_verbose,
    report_view,
)


def _alias() -> dict:
    return {
        "ghsa_id": "GHSA-test", "cve_id": "CVE-2026-1234", "osv_id": "GHSA-test",
        "cwes": [{"cwe_id": "CWE-918", "name": "SSRF"}], "severity": "high",
        "package_name": "axios", "ecosystem": "npm",
        "affected_versions": ["1.0.0", "< 1.15.0"], "fixed_versions": ["1.15.0"],
    }


def _lineage(*, lineage_id="lineage-test", score=0.90, confidence="high", alias=None) -> dict:
    return {
        "lineage_id": lineage_id, "confidence": confidence, "score": score,
        "repo": "axios/axios", "file_path": "lib/http.js",
        "reference_function": "request", "associated_advisories": [alias or _alias()],
        "evidence_pair_ids": ["pair-1"],
    }


def _report() -> dict:
    return {
        "schema": "provtrail_scan_v5",
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
                    "priority": "automatic_vulnerability",
                    "hash_match_types": [],
                    "hash_matches": [
                        {
                            **_alias(),
                            "side": "vulnerable",
                            "match_type": "abstracted",
                            "repo": "axios/axios",
                            "fix_commit_sha": "abc123",
                            "file_path": "lib/http.js",
                            "function_name": "request",
                        }
                    ],
                    "aggregates": [],
                    "evidence": [],
                    "lineages": [_lineage()],
                    "vulnerability_states": [{
                        "lineage_id": "lineage-test", "fix_boundary_id": "boundary-test",
                        "fix_commit_sha": "abc123", "status": "vulnerable",
                        "vulnerable_score": 1.0, "patched_score": 0.0,
                        "contrast_score": 1.0, "contradictions": [],
                    }],
                    "package_applicabilities": [],
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
                    "priority": "manual_review",
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
                    "lineages": [_lineage()],
                    "vulnerability_states": [{
                        "lineage_id": "lineage-test", "fix_boundary_id": "boundary-test",
                        "fix_commit_sha": "abc123", "status": "uncertain",
                        "vulnerable_score": 0.91, "patched_score": 0.62,
                        "contrast_score": 0.29, "contradictions": [],
                    }],
                    "package_applicabilities": [],
                },
            },
            {
                "function_id": "src/c.js::0:10",
                "path": "src/c.js",
                "name": "safe",
                "start_line": 0,
                "end_line": 2,
                "result": {
                    "priority": "informational_lineage",
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
    assert summary["automatic_vulnerability"] == 1
    assert summary["manual_review"] == 1
    assert summary["informational_lineage"] == 1
    assert summary["none"] == 0
    assert summary["unique_advisories"] == 1
    assert summary["severity"] == {"high": 2}


def test_final_metrics_separate_deterministic_and_llm_outcomes():
    metrics = final_metrics(_report())

    assert metrics["deterministic_automatic"] == 1
    assert metrics["llm_escalated"] == 0
    assert metrics["llm_dismissed"] == 0
    assert metrics["llm_needs_review"] == 1
    assert metrics["attention"] == {"high": 2, "medium": 0, "low": 0}
    assert metrics["final_findings"] == 2


def test_audit_summary_has_divided_sections_and_final_counts():
    output = format_audit_summary(_report())

    assert "PROVTRAIL SCAN RESULT" in output
    assert "✖ 2 finding(s) require attention" in output
    assert "SCAN OVERVIEW" in output
    assert "RESULTS" in output
    assert "DETERMINISTIC RESULTS" not in output
    assert "automatic vulnerability: 1" in output
    assert "manual review:           1" in output
    assert "informational lineage:   1" in output
    assert "security advisories" not in output
    assert "unique advisories:" not in output
    assert "advisories:              1" in output
    assert "LLM unavailable:" not in output
    assert "LLM not run:" not in output
    assert "escalation rate:" not in output
    assert "LLM review coverage:" not in output
    assert "target recall:" not in output
    assert "total escalated:" not in output
    assert output.count("─" * 72) >= 3


def test_final_findings_counts_every_item_still_requiring_attention():
    report = _report()
    output = format_attention(report)
    assert "ATTENTION" in output
    assert "High                  2" in output
    assert "Medium                0" in output
    assert "Low                   0" in output

    report["findings"][1]["review_explanation"]["llm_verdict"] = "dismissed"
    assert final_metrics(report)["final_findings"] == 1
    assert "High                  1" in format_attention(report)
    assert "✖ 2 finding(s) require attention" in format_audit_summary(report)


def test_verbose_report_contains_lineage_and_boundary_metadata():
    output = format_verbose(_report())

    assert "Finding 1: AUTOMATIC_VULNERABILITY" in output
    assert "lineage: lineage-test (high, 0.900)" in output
    assert "fix boundary: abc123 — vulnerable (contrast 1.000)" in output
    assert "Finding 2: MANUAL_REVIEW" in output
    assert "fix boundary: abc123 — uncertain (contrast 0.290)" in output


def test_report_view_excludes_informational_by_default_and_can_include_them():
    report = _report()

    assert len(report_view(report)["findings"]) == 2
    assert len(report_view(report, include_informational=True)["findings"]) == 3
    assert report_view(report)["findings"][1]["review_explanation"]["model"] == "qwen3:8b"


def test_report_primary_lineage_follows_the_verified_boundary():
    report = _report()
    result = report["findings"][0]["result"]
    later_alias = {**_alias(), "ghsa_id": "GHSA-later", "cve_id": "CVE-LATER"}
    result["lineages"].append(_lineage(
        lineage_id="lineage-later", score=0.95, alias=later_alias,
    ))

    detail = report_view(report)["findings"][0]

    assert detail["primary_lineage"]["lineage_id"] == "lineage-test"
    assert {item["cve_id"] for item in detail["advisories"]} == {
        "CVE-2026-1234",
    }


def test_report_retains_low_confidence_lineages_but_primary_stays_credible():
    report = _report()
    result = report["findings"][1]["result"]
    strong = {**_alias(), "ghsa_id": "GHSA-strong", "cve_id": "CVE-STRONG"}
    noise = {**_alias(), "ghsa_id": "GHSA-noise", "cve_id": "CVE-NOISE"}
    result["lineages"] = [
        _lineage(),
        _lineage(lineage_id="lineage-strong", score=0.95, alias=strong),
        _lineage(lineage_id="lineage-noise", score=0.99, confidence="low", alias=noise),
    ]

    detail = report_view(report)["findings"][1]

    assert detail["primary_lineage"]["lineage_id"] == "lineage-test"
    assert {item["lineage_id"] for item in detail["lineages"]} == {
        "lineage-test", "lineage-strong", "lineage-noise",
    }
    assert {item["ghsa_id"] for item in detail["advisories"]} == {
        "GHSA-test",
    }


def test_cli_report_reads_saved_json_without_detector(tmp_path, capsys):
    path = tmp_path / "scan.json"
    path.write_text(json.dumps(_report()), encoding="utf-8")

    exit_code = main(["report", str(path), "--verbose"])

    assert exit_code == 1
    output = capsys.readouterr().out
    assert "Finding 1: AUTOMATIC_VULNERABILITY" in output
    assert "lineage: lineage-test (high, 0.900)" in output


def test_cli_report_returns_zero_when_all_findings_are_cleared(tmp_path, capsys):
    report = _report()
    report["findings"] = [report["findings"][-1]]
    path = tmp_path / "cleared.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    assert main(["report", str(path)]) == 0
    assert "✔ No actionable findings" in capsys.readouterr().out


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
