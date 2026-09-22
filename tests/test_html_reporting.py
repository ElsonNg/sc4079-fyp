import json
import re
import shutil
import subprocess
from copy import deepcopy
from datetime import datetime, timezone

import pytest

from provtrail.cli.main import main
from provtrail.corpus.models.corpus import CorpusEntry, DiagnosticLine
from provtrail.pipeline.controller.html_reporting import (
    _advisory_summary,
    _candidate_lines,
    _excerpt,
    build_html_report_data,
    render_html_report,
)
from provtrail.pipeline.controller.region_extraction import enumerate_candidate_regions
from provtrail.pipeline.scanning.scanner import ScanConfig, ScanSummary
from provtrail.pipeline.controller.finding_exports import project_findings


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


def test_html_report_bundles_offline_resources_and_decision_views():
    data = _build()
    output = render_html_report(data)
    assert "__REPORT_" not in output
    assert '<script src=' not in output
    assert '/private/work/demo' not in output
    assert 'id="count-patched"' in output
    assert 'aria-labelledby="comparison-title"' in output
    assert data["findings"][0]["outcome"] == "flagged_exact"
    boundary = data["findings"][0]["boundaries"][0]
    assert boundary["state"]["fix_boundary_id"] == "boundary-test"
    assert all(boundary["reference"][side] for side in ("candidate", "vulnerable", "patched"))
    assert data["outcome_counts"] == {
        "flagged_exact": 1, "flagged_inferred": 0, "manual_review": 0, "patched": 0,
    }
    assert data["coverage"]["corpus_entries"] == 1


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
    result["vulnerability_states"][0]["evidence_pair_ids"] = ["pair-1"]
    data = _build(summary)
    finding = data["findings"][0]
    assert finding["outcome"] == "flagged_inferred"
    assert "specific upstream fix" in finding["reason"]
    assert "independent" not in finding["reason"]
    assert finding["evidence"]["structural_vulnerable"] == 0.90

    result["priority"] = "manual_review"
    result["vulnerability_states"][0].update(status="uncertain", abstention_reason="E_MARGIN_AMBIGUOUS")
    finding = _build(summary)["findings"][0]
    assert finding["outcome"] == "manual_review"
    assert "too similar to distinguish confidently" in finding["reason"]


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
    assert finding["review_explanation"]["reference_matches"] is False
    summary.findings[0]["review_explanation"]["fix_boundary_id"] = "boundary-test"
    bound = _build(summary)["findings"][0]
    assert bound["review_explanation"]["reference_matches"] is True
    assert bound["outcome"] == "manual_review"


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
    assert finding["boundaries"][0]["advisories"][0]["package_name"] == "demo-http"


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
    assert "Vulnerable matches" in html_path.read_text(encoding="utf-8")


def _add_unrelated_candidate(result):
    alias = {**_alias(), "ghsa_id": "GHSA-noise", "cve_id": "CVE-NOISE", "severity": "critical"}
    result["lineages"].append({
        "lineage_id": "lineage-noise", "score": 1.0, "confidence": "low",
        "repo": "other/library", "file_path": "other.js", "reference_function": "unrelated",
        "associated_advisories": [alias], "evidence_pair_ids": ["boundary-noise:changed"],
    })
    result["vulnerability_states"].append({
        "lineage_id": "lineage-noise", "fix_boundary_id": "boundary-noise",
        "fix_commit_sha": "other-fix", "status": "uncertain", "abstention_reason": "T_FAILED",
        "advisories": [alias], "evidence_pair_ids": ["boundary-noise:changed"],
    })
    result["evidence"].append({
        "pair_id": "boundary-noise:changed", "vulnerable_minus_patched": 0.99,
        "vulnerable_score": 0.99, "patched_score": 0.0,
    })


def test_headline_scores_advisory_and_exports_follow_the_same_boundary():
    summary = _summary()
    result = summary.findings[0]["result"]
    result["hash_matches"] = []
    result["evidence"] = [{
        "pair_id": "boundary-test:changed", "candidate_span": {"start_line": 1, "end_line": 1},
        "reference_granularity": "changed", "candidate_granularity": "changed",
        "vulnerable_score": 0.9, "patched_score": 0.8, "vulnerable_minus_patched": 0.1,
    }]
    _add_unrelated_candidate(result)
    finding = _build(summary)["findings"][0]
    boundary = finding["boundaries"][0]
    assert finding["primary"]["cve_id"] == "CVE-2026-1234"
    assert finding["severity"] == "high"
    assert finding["evidence"]["pair_id"] == "boundary-test:changed"
    assert boundary["state"]["vulnerable_score"] == 1.0
    assert finding["evidence"]["vulnerable_score"] == 0.9
    assert [line["number"] for line in finding["reference"]["candidate"]["lines"] if line["marker"]] == [6]
    assert len(finding["boundaries"]) == 2
    exported = project_findings(summary.to_dict())[0]
    assert "CVE-NOISE" not in exported.advisory_ids
    assert exported.reason == finding["reason"]


def test_two_fixes_in_one_lineage_keep_their_advisories_and_states_separate():
    summary = _summary()
    result = summary.findings[0]["result"]
    unrelated_alias = {**_alias(), "ghsa_id": "GHSA-earlier", "cve_id": "CVE-EARLIER", "severity": "critical"}
    result["lineages"][0]["associated_advisories"].insert(0, unrelated_alias)
    result["vulnerability_states"].insert(0, {
        "lineage_id": "lineage-test", "fix_boundary_id": "boundary-earlier",
        "fix_commit_sha": "old-fix", "status": "patched", "advisories": [unrelated_alias],
    })
    finding = _build(summary)["findings"][0]
    assert finding["primary"]["fix_commit_sha"] == "abc123"
    assert finding["severity"] == "high"
    assert finding["boundaries"][1]["state"]["status"] == "patched"
    assert finding["boundaries"][1]["advisories"][0]["cve_id"] == "CVE-EARLIER"
    assert "CVE-EARLIER" not in project_findings(summary.to_dict())[0].advisory_ids


def test_patched_results_keep_source_and_choose_the_patched_boundary():
    summary = _summary(PATCHED)
    result = summary.findings[0]["result"]
    result["priority"] = "informational_lineage"
    result["hash_matches"][0]["side"] = "patched"
    result["vulnerability_states"][0]["status"] = "patched"
    _add_unrelated_candidate(result)
    result["lineages"][1].update(confidence="high", score=2.0)
    data = _build(summary)
    finding = data["findings"][0]
    assert data["outcome_counts"]["patched"] == 1
    assert finding["outcome"] == "patched"
    assert finding["primary"]["fix_commit_sha"] == "abc123"
    assert finding["reference"]["candidate"] and finding["reference"]["patched"]
    assert project_findings(summary.to_dict()) == []


def test_uncertainty_explains_failed_correspondence_without_inventing_a_verdict():
    summary = _summary()
    result = summary.findings[0]["result"]
    result["priority"] = "manual_review"
    result["hash_matches"] = []
    result["vulnerability_states"][0].update(status="uncertain", abstention_reason="T_FAILED")
    finding = _build(summary)["findings"][0]
    assert "Generic structure alone" in finding["reason"]
    result["vulnerability_states"] = []
    unknown = _build(summary)["findings"][0]
    assert unknown["boundaries"][0]["state"] == {}
    assert "cannot resolve" in unknown["reason"]


def test_long_sources_preserve_complete_context_and_original_coordinates():
    source = "\n".join(f"  const value{index} = {index};" for index in range(200))
    snippet = _excerpt(source, first_line=10, focus_lines={150}, marker="detected")
    assert snippet["truncated"]
    assert len(snippet["lines"]) == 120
    assert snippet["full_source"] == source
    assert snippet["highlight_lines"] == [160]
    assert any(line["number"] == 160 and line["marker"] == "detected" for line in snippet["lines"])


def _run_view(data, assertions, tmp_path):
    if shutil.which("node") is None:
        pytest.skip("Node is required to execute the report view")
    output = render_html_report(data)
    script = re.findall(r"<script>(.*?)</script>", output, re.DOTALL)[0]
    script = re.sub(r"\ninit\(\);\s*$", "", script)
    payload_path = tmp_path / "view.json"
    payload_path.write_text(json.dumps({"data": data, "script": script, "assertions": assertions}), encoding="utf-8")
    runner = tmp_path / "view.cjs"
    runner.write_text(r'''
const fs = require("fs"), vm = require("vm"), assert = require("assert/strict");
const payload = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const elements = new Map();
let context;
function element(selector) {
  if (!elements.has(selector)) elements.set(selector, {
    value: "", checked: false, innerHTML: "", textContent: "", dataset: {},
    setAttribute() {}, showModal() {}, addEventListener() {},
    querySelector: child => element(selector + " " + child),
  });
  const node = elements.get(selector);
  if (selector === "#content details.finding") node.dataset.finding = vm.runInContext("matches.find(f=>visibleFinding(f)&&(!selectedFile||f.path===selectedFile))?.id", context);
  return node;
}
context = vm.createContext({assert, element, document: {
  getElementById: () => ({textContent: JSON.stringify(payload.data)}),
  querySelector: element, querySelectorAll: () => [],
}});
vm.runInContext(payload.script, context);
vm.runInContext(payload.assertions, context);
''', encoding="utf-8")
    result = subprocess.run(["node", str(runner), str(payload_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_view_search_patched_navigation_and_empty_states(tmp_path):
    data = _build()
    patched = deepcopy(data["findings"][0])
    patched.update(id="patched", path="src/patched.js", name="safeRequest", outcome="patched")
    patched["boundaries"][0]["state"]["status"] = "patched"
    data["findings"].append(patched)
    data["scanned_files"].append("src/patched.js")
    _run_view(data, r'''
assert.equal(matches.filter(visibleFinding).length, 1);
viewFilter = "patched";
render();
assert(element("#content").innerHTML.includes("safeRequest"));
assert(element("#tree").innerHTML.includes("patched.js"));
assert(!element("#tree").innerHTML.includes("request.js"));
viewFilter = "all";
element("#search").value = "safeRequest";
render();
assert(!element("#content").innerHTML.includes('data-finding="src/request.js::0:20"'));
assert(!element("#tree").innerHTML.includes("request.js"));
element("#search").value = "CVE-2026-1234";
assert.equal(matches.filter(visibleFinding).length, 2);
element("#search").value = "no-such-finding";
render();
assert(element("#content").innerHTML.includes("No findings match this view"));
assert(element("#tree").innerHTML.includes("No files match"));
assert.equal(score(null), "Not recorded");
assert.equal(score(0), "0.000");
openScanInfo();
assert(element("#scan-info-body").innerHTML.includes("Minimum edit-side score"));
assert(element("#scan-info-body").innerHTML.includes("0.9"));
''', tmp_path)


def test_complete_comparison_contains_project_and_untruncated_source(tmp_path):
    source = "\n".join(f"project_line_{index}" for index in range(200))
    data = _build(_summary(source))
    _run_view(data, r'''
openComparison(report.findings[0].id, 0);
assert(element("#comparison-body").innerHTML.includes("Project code"));
assert(element("#comparison-body").innerHTML.includes("project_line_199"));
assert(element("#comparison-body").innerHTML.includes("Patched reference"));
assert(!element("#comparison-body").innerHTML.includes("Vulnerable reference"));
comparisonMode = "vulnerable";
renderComparison();
assert(element("#comparison-body").innerHTML.includes("Vulnerable reference"));
assert(!element("#comparison-body").innerHTML.includes("Patched reference"));
assert(codePanel("Project", report.findings[0].reference.candidate).includes("Partial source excerpt"));
assert(codePanel("Project", {lines:[{number:12,text:"one;line;function",marker:""}],total_lines:1}).includes("one;line;function"));
''', tmp_path)
