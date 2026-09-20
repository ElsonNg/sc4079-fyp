import json
import re
import shutil
import subprocess
from datetime import datetime, timezone

from provtrail.cli.main import main
from provtrail.corpus.models.corpus import CorpusEntry, DiagnosticLine
from provtrail.pipeline.controller.html_reporting import (
    _advisory_summary,
    _candidate_lines,
    build_html_report_data,
    render_html_report,
)
from provtrail.pipeline.controller.region_extraction import enumerate_candidate_regions
from provtrail.pipeline.scanning.scanner import ScanConfig, ScanSummary


VULNERABLE = "function request(url) {\n  return fetch(url);\n}"
PATCHED = """function request(url) {
  if (!url.startsWith('https://trusted.example/')) throw new Error('blocked');
  return fetch(url);
}"""


def _entry() -> CorpusEntry:
    return CorpusEntry(
        ghsa_id="GHSA-test", cve_id="CVE-2026-1234", osv_id="GHSA-test",
        advisory_title="Request URL validation can be bypassed",
        advisory_description="Untrusted URLs may reach the request handler.",
        advisory_url="https://github.com/advisories/GHSA-test",
        package_name="demo-http", ecosystem="npm", repo="demo/http",
        fix_commit_sha="abc123", file_path="lib/request.js", function_name="request",
        vulnerable_function=VULNERABLE, patched_function=PATCHED,
        diagnostic_lines=[DiagnosticLine(
            kind="added", patched_line=1,
            text="  if (!url.startsWith('https://trusted.example/')) throw new Error('blocked');",
        )],
        severity="high", affected_versions=["< 2.0.0"], fixed_versions=["2.0.0"],
    )


def _alias() -> dict:
    return {
        "ghsa_id": "GHSA-test", "cve_id": "CVE-2026-1234", "osv_id": "GHSA-test",
        "severity": "high", "package_name": "demo-http", "ecosystem": "npm",
        "affected_versions": ["< 2.0.0"], "fixed_versions": ["2.0.0"],
        "advisory_title": "Request URL validation can be bypassed",
        "advisory_description": "Untrusted URLs may reach the request handler.",
        "advisory_url": "https://github.com/advisories/GHSA-test",
    }


def _summary(source: str = VULNERABLE) -> ScanSummary:
    alias = _alias()
    result = {
        "priority": "automatic_vulnerability",
        "hash_match_types": ["exact"],
        "hash_matches": [{
            **alias, "side": "vulnerable", "match_type": "exact",
            "lineage_id": "lineage-test", "fix_boundary_id": "boundary-test",
            "repo": "demo/http", "fix_commit_sha": "abc123",
            "file_path": "lib/request.js", "function_name": "request",
            "advisories": [alias],
        }],
        "candidate_region_count": 0, "retrieval_match_count": 0,
        "aggregates": [], "evidence": [],
        "lineages": [{
            "lineage_id": "lineage-test", "confidence": "high", "score": 1.0,
            "repo": "demo/http", "file_path": "lib/request.js",
            "reference_function": "request", "associated_advisories": [alias],
            "evidence_pair_ids": ["boundary-test"],
        }],
        "vulnerability_states": [{
            "lineage_id": "lineage-test", "fix_boundary_id": "boundary-test",
            "fix_commit_sha": "abc123", "status": "vulnerable",
            "vulnerable_score": 1.0, "patched_score": 0.0, "contrast_score": 1.0,
            "fix_evidence": ["exact vulnerable-side hash match"],
            "contradictions": [], "advisories": [alias],
        }],
        "package_applicabilities": [{
            "lineage_id": "lineage-test", "package": "demo-http",
            "ecosystem": "npm", "status": "unknown", "evidence": [],
        }],
        "parser_supported": True,
    }
    return ScanSummary(
        target_root="/private/work/demo", root_hash="root-hash", previous_root_hash=None,
        changed_files=["src/request.js"], deleted_files=[],
        scanned_files=["src/clean.js", "src/request.js"],
        total_files=2, total_functions=2, scanned_functions=2, reused_functions=0,
        priority_counts={"automatic_vulnerability": 1, "none": 1},
        findings=[{
            "function_id": "src/request.js::0:20", "path": "src/request.js",
            "name": "request", "node_type": "function_declaration",
            "start_line": 4, "end_line": 6, "source": source, "result": result,
        }],
        state_path="/private/work/demo/.provtrail/scan-state.json",
    )


def _build(summary=None):
    return build_html_report_data(
        summary or _summary(), entries=[_entry()],
        config=ScanConfig(corpus_version="corpus-test"),
        generated_at=datetime(2026, 8, 16, tzinfo=timezone.utc), tool_version="test",
    )


def test_html_report_is_directory_centered_and_minimal():
    data = _build()
    output = render_html_report(data)
    for expected in (
        "Project</strong>", 'id="tree"', "LLM second opinion",
        "Flagged (Exact)",
        "Flagged (Inferred)", "Needs Review", "Evidence chain",
        "Hide low-confidence lineages", "Project matched region",
        "Vulnerable reference", "Patched reference",
        "Recommended action", "View full comparison",
        "View info", "Scan Info", 'id="finding-info-dialog"',
        'id="comparison-dialog"', 'id="scan-info-dialog"',
        "Retrieval similarity", "Minimum vulnerable score",
        'class="metrics fix-boundary-table"', "referenceDiff(finding)",
        "referenceDiffSnippets(reference.vulnerable,reference.patched)",
        'codePanel("Project matched region",reference.candidate,"project-reference")',
        'diff.vulnerable,"vulnerable-reference"',
        'diff.patched,"patched-reference"',
        "Vulnerable reference − removed", "Patched reference + added",
    ):
        assert expected in output
    for removed in (
        "data-tab=", ">Recommendations</button>", ">Dependencies</button>",
        "LLM Decision", "Flagged · Exact", "Flagged · Inferred", "/private/work/demo",
        "Open advisory", "Open fix commit",
    ):
        assert removed not in output
    assert "const flagIcon=" in output
    assert "const reviewIcon=" in output
    assert "const dismissedIcon=" in output
    assert 'class="marker llm-flagged"' in output
    assert 'class="marker llm-dismissed"' in output
    assert "--violet:" in output
    assert 'class="external-link"' in output
    assert 'Advisory <span aria-hidden="true">↗</span>' in output
    assert 'Fix Commit <span aria-hidden="true">↗</span>' in output
    assert ".lineage-confidence.high{font-weight:900" in output
    assert output.index('<h4>Recommended action</h4>') < output.index('<h4>Evidence chain</h4>')
    assert "LLM Verdict" in output
    assert data["findings"][0]["outcome"] == "flagged_exact"
    assert data["findings"][0]["lineages"][0]["reference"]["candidate"]
    assert data["findings"][0]["lineages"][0]["reference"]["vulnerable"]
    assert data["findings"][0]["lineages"][0]["reference"]["patched"]
    assert data["outcome_counts"] == {
        "flagged_exact": 1, "flagged_inferred": 0, "manual_review": 0,
    }


def test_inferred_and_review_outcomes_have_distinct_copy_and_scores():
    summary = _summary()
    result = summary.findings[0]["result"]
    result["hash_matches"] = []
    result["hash_match_types"] = []
    result["evidence"] = [{
        "pair_id": "pair-1", "candidate_region_id": "candidate-1",
        "retrieval_similarity": 0.88, "structural_vulnerable": 0.90,
        "structural_patched": 0.60, "token_vulnerable": 0.84,
        "token_patched": 0.51, "api_anchor_vulnerable": 0.75,
        "api_anchor_patched": 0.30, "vulnerable_score": 0.83,
        "patched_score": 0.47, "vulnerable_minus_patched": 0.36,
        "ast_coverage": 0.72,
    }]
    data = _build(summary)
    finding = data["findings"][0]
    assert finding["outcome"] == "flagged_inferred"
    assert "independent region" in finding["reason"].lower()
    assert finding["diagnostics"]["supporting_region_count"] == 1
    assert finding["evidence"]["structural_vulnerable"] == 0.90

    result["priority"] = "manual_review"
    finding = _build(summary)["findings"][0]
    assert finding["outcome"] == "manual_review"
    assert "cannot be resolved confidently" in finding["reason"]


def test_llm_verdict_is_presented_as_review_only_second_opinion():
    summary = _summary()
    summary.findings[0]["result"]["priority"] = "manual_review"
    summary.findings[0]["review_explanation"] = {
        "status": "generated",
        "llm_verdict": "flagged",
        "verdict_rationale": "The candidate retains the **unsafe** `URL` flow.",
        "security_mechanism": "The upstream fix **validates** the URL before fetching.",
        "model": "test-model",
    }
    data = _build(summary)
    finding = data["findings"][0]
    assert finding["outcome"] == "manual_review"
    assert finding["review_explanation"]["verdict_rationale"] == (
        "The candidate retains the **unsafe** `URL` flow."
    )
    output = render_html_report(data)
    assert '<p class="second-opinion">Second opinion only</p>' in output
    assert "The candidate retains the **unsafe** `URL` flow." in output
    assert 'replace(/`([^`\\n]+)`/g,"<code>$1</code>")' in output
    assert 'replace(/\\*\\*([^*\\n]+)\\*\\*/g,"<strong>$1</strong>")' in output
    assert 'if(finding.outcome!=="manual_review")return ""' in output
    assert 'id="hide-llm-dismissed"' not in output
    assert 'id="problems-only"' not in output
    assert "if(!findings.some(visibleFinding))return false" in output
    assert 'id="filter-state"' in output
    assert 'aria-pressed="false"' in output
    assert "LLM Flagged" in output
    assert "LLM Dismissed" in output
    assert "LLM Uncertain" in output


def test_html_payload_escapes_script_terminators_but_round_trips_source():
    dangerous = "function request() { return '</script><script>alert(1)</script>'; }"
    output = render_html_report(_build(_summary(dangerous)))
    assert dangerous not in output
    match = re.search(
        r'<script id="report-data" type="application/json">(.*?)</script>',
        output, re.DOTALL,
    )
    payload = json.loads(match.group(1))
    reconstructed = "\n".join(
        line["text"] for line in payload["findings"][0]["reference"]["candidate"]["lines"]
    )
    assert reconstructed == dangerous


def test_advisory_excerpt_keeps_complete_leading_summary():
    description = """## Summary
An important issue affects request().

- First condition
- Second condition

## Details
This longer section should not appear.
"""
    excerpt = _advisory_summary(description)
    assert "First condition" in excerpt
    assert "## Details" not in excerpt


def test_target_package_is_resolved_separately(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "demo-http", "version": "1.5.0"}), encoding="utf-8"
    )
    summary = _summary()
    summary.target_root = str(tmp_path)
    finding = _build(summary)["findings"][0]
    assert finding["target_package"]["name"] == "demo-http"
    assert finding["target_package"]["version"] == "1.5.0"
    assert finding["lineages"][0]["reference_packages"] == [
        {"name": "demo-http", "ecosystem": "npm"}
    ]


def test_candidate_highlight_uses_local_verified_region():
    source = """function request(url) {
  const parsed = new URL(url);
  if (parsed.hostname === 'trusted.example') return fetch(url);
  throw new Error('blocked');
}"""
    finding = {"function_id": "src/request.js::0:100"}
    region = next(
        item.region
        for item in enumerate_candidate_regions(source, candidate_id=finding["function_id"])
        if item.region.granularity == "changed"
    )
    lines = _candidate_lines(finding, source, {"candidate_region_id": region.region_id})
    assert lines
    assert len(lines) < len(source.splitlines())


def test_embedded_javascript_has_valid_syntax(tmp_path):
    if shutil.which("node") is None:
        return
    scripts = re.findall(
        r"<script(?: [^>]*)?>(.*?)</script>", render_html_report(_build()), re.DOTALL
    )
    path = tmp_path / "report.js"
    path.write_text(scripts[-1], encoding="utf-8")
    result = subprocess.run(
        ["node", "--check", str(path)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_cli_scan_writes_redesigned_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr("provtrail.cli.commands.scan.load_entries", lambda *_args, **_kwargs: [_entry()])
    monkeypatch.setattr("provtrail.cli.commands.scan.scan_directory", lambda *_args, **_kwargs: _summary())
    monkeypatch.setattr(
        "provtrail.cli.commands.scan.build_default_detector_factory", lambda *_args, **_kwargs: lambda: None
    )
    assert main(["scan", str(tmp_path)]) == 1
    json_path = tmp_path / ".provtrail" / "latest-scan.json"
    html_path = tmp_path / ".provtrail" / "latest-scan.html"
    assert json.loads(json_path.read_text(encoding="utf-8"))["schema"] == "provtrail_scan_v5"
    assert "source" not in json_path.read_text(encoding="utf-8")
    assert "Flagged (Exact)" in html_path.read_text(encoding="utf-8")
