import json
import re
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone

from cli.main import main
from corpus.controller.store import get_connection, load_entries, save_entries
from corpus.models.corpus import CorpusEntry, DiagnosticLine
from pipeline.controller.html_reporting import (
    _candidate_lines,
    build_html_report_data,
    render_html_report,
)
from pipeline.controller.region_extraction import (
    enumerate_candidate_regions,
    extract_vulnerability_regions,
)
from pipeline.controller.region_retrieval import _region_fingerprint
from pipeline.controller.scanning import ScanConfig, ScanSummary, corpus_fingerprint


VULNERABLE = """function request(url) {
  return fetch(url);
}"""

PATCHED = """function request(url) {
  if (!url.startsWith('https://trusted.example/')) throw new Error('blocked');
  return fetch(url);
}"""


def _entry() -> CorpusEntry:
    return CorpusEntry(
        ghsa_id="GHSA-test",
        cve_id="CVE-2026-1234",
        osv_id="GHSA-test",
        advisory_title="Request URL validation can be bypassed",
        advisory_description="Untrusted URLs may reach the request handler.",
        advisory_url="https://github.com/advisories/GHSA-test",
        advisory_references=["https://nvd.nist.gov/vuln/detail/CVE-2026-1234"],
        package_name="demo-http",
        ecosystem="npm",
        repo="demo/http",
        fix_commit_sha="abc123",
        file_path="lib/request.js",
        function_name="request",
        vulnerable_function=VULNERABLE,
        patched_function=PATCHED,
        diagnostic_lines=[
            DiagnosticLine(
                kind="added",
                patched_line=1,
                text="  if (!url.startsWith('https://trusted.example/')) throw new Error('blocked');",
            )
        ],
        severity="high",
        affected_versions=["< 2.0.0"],
        fixed_versions=["2.0.0"],
    )


def _summary(source: str = VULNERABLE) -> ScanSummary:
    match = {
        "ghsa_id": "GHSA-test",
        "cve_id": "CVE-2026-1234",
        "osv_id": "GHSA-test",
        "side": "vulnerable",
        "match_type": "exact",
        "severity": "high",
        "package_name": "demo-http",
        "ecosystem": "npm",
        "affected_versions": ["< 2.0.0"],
        "fixed_versions": ["2.0.0"],
        "repo": "demo/http",
        "fix_commit_sha": "abc123",
        "file_path": "lib/request.js",
        "function_name": "request",
    }
    return ScanSummary(
        target_root="/private/work/demo",
        root_hash="root-hash",
        previous_root_hash=None,
        changed_files=["src/request.js"],
        deleted_files=[],
        scanned_files=["src/clean.js", "src/request.js"],
        total_files=2,
        total_functions=2,
        scanned_functions=2,
        reused_functions=0,
        status_counts={"flagged": 1, "cleared": 1},
        findings=[
            {
                "function_id": "src/request.js::0:20",
                "path": "src/request.js",
                "name": "request",
                "node_type": "function_declaration",
                "start_line": 4,
                "end_line": 6,
                "source": source,
                "result": {
                    "status": "flagged",
                    "provenance_confidence": "high",
                    "hash_match_types": ["exact"],
                    "hash_matches": [match],
                    "aggregates": [],
                    "evidence": [],
                    "candidate_region_count": 0,
                    "retrieval_match_count": 0,
                    "parser_supported": True,
                    "message": "High-confidence vulnerable-side hash match",
                },
            },
            {
                "function_id": "src/clean.js::0:10",
                "path": "src/clean.js",
                "name": "clean",
                "node_type": "function_declaration",
                "start_line": 0,
                "end_line": 0,
                "source": "function clean() {}",
                "result": {
                    "status": "cleared",
                    "provenance_confidence": "none",
                    "hash_match_types": [],
                    "hash_matches": [],
                    "aggregates": [],
                    "evidence": [],
                    "candidate_region_count": 0,
                    "retrieval_match_count": 0,
                    "parser_supported": True,
                },
            },
        ],
        state_path="/private/work/demo/.provtrail/scan-state.json",
    )


def test_html_report_is_self_contained_and_includes_core_views():
    data = build_html_report_data(
        _summary(),
        entries=[_entry()],
        config=ScanConfig(corpus_version="corpus-test"),
        generated_at=datetime(2026, 8, 16, tzinfo=timezone.utc),
        tool_version="test",
    )
    output = render_html_report(data)

    assert "Project Directory" in output
    assert ">Findings<" in output
    assert "<th>Severity</th><th>LLM Decision</th><th>Location</th>" in output
    assert ">Recommendations<" in output
    assert "folder-closed" in output
    assert "Back to project overview" in output
    assert "function selectFile(path){selectedFile=path;$$('.tree-file').forEach" in output
    assert "function selectFile(path){selectedFile=path;buildTree();renderFile()}" not in output
    assert "code-compare" in output
    assert "reference-stack" in output
    assert ".code-compare{height:720px}" in output
    assert "grid-template-columns:46px max-content;min-width:100%;width:max-content" in output
    assert "overflow-y:scroll" in output
    assert ".metric.manual_review strong" in output
    assert ".bar-fill.vulnerable" in output
    assert ".bar-fill.patched" in output
    assert ".bar-fill.retrieval" in output
    assert "Project code" in output
    assert "<summary>Details</summary>" in output
    assert ".outcome .top-details summary{color:var(--focus);background:transparent;border-radius:0;padding:0}" in output
    assert "$('#outcome-title').textContent=report.project" in output
    assert "need attention`:'No vulnerability clone findings'" not in output
    assert "function updateGeneratedTime()" in output
    assert "value='just now'" in output
    assert "60_000" in output
    assert "3_600_000" in output
    assert "86_400_000" in output
    assert "setInterval(updateGeneratedTime" not in output
    assert output.index('id="generated"') < output.index("<summary>Details</summary>")
    assert output.index("<summary>Details</summary>") < output.index('id="metrics"')
    assert "flagIcon" in output
    assert "reviewIcon" in output
    assert '<circle cx="12" cy="12" r="9"/>' in output
    assert "kind==='manual_review'?'Review'" in output
    assert ".badge.manual_review{color:var(--focus);background:var(--focus-bg)}" in output
    assert ".badge.llm_dismissed{color:var(--muted);background:var(--surface-2)}" in output
    assert ".badge.llm_escalate{color:var(--amber);background:var(--amber-bg)}" in output
    assert ".tree-file.llm_dismissed,.tree summary.llm_dismissed{color:var(--muted)}" in output
    assert ".tree-file.flagged{color:var(--red)}" not in output
    assert ".tree-file.llm_escalate,.tree summary.llm_escalate{color:var(--amber)}" in output
    assert "attentionStatus(findings)" in output
    assert "if(findings.some(f=>f.status==='flagged'))return'flagged'" in output
    assert "const statusRank={flagged:0,llm_escalate:1,manual_review:2,llm_dismissed:3,cleared:4}" in output
    assert "statusRank[fileStatus(a)]-statusRank[fileStatus(b)]||a.localeCompare(b)" in output
    assert 'affectedFiles.map(path=>{const status=fileStatus(path),findings=byFile.get(path)||[];return `<button class="overview-file ${esc(status)}"' in output
    assert ".overview-file{font-weight:550}" in output
    assert ".overview-file.flagged .file-name{color:var(--red)}" not in output
    assert ".overview-file.llm_escalate .file-name{color:var(--amber)}" in output
    assert "function findingCard(f,openByDefault=false)" in output
    assert "<details class=\"finding-card\"${openByDefault?' open':''}>" in output
    assert "fs.map(f=>findingCard(f,fs.length===1))" in output
    assert "function countMarkers(findings)" in output
    assert ".count-marker.flagged{color:var(--red)}" in output
    assert ".count-marker.llm_escalate{color:var(--amber)}" in output
    assert ".count-marker.manual_review{color:var(--focus)}" in output
    assert ".count-marker.llm_dismissed{color:var(--muted)}" in output
    assert '<summary class="finding-head">' in output
    assert "finding-chevron" in output
    assert "llmStatus=verdict==='dismissed'?'llm_dismissed':verdict==='flagged'?'llm_escalate':''" in output
    assert "needsReview?(llmStatus?badge(llmStatus,llmStatus):badge(f.status))" in output
    assert "LLM Dismissed" in output
    assert "LLM Escalate" in output
    assert "function llmDecision(finding)" in output
    assert "if(finding.status!=='manual_review')return'<span class=\"muted\">—</span>'" in output
    assert "${llmDecision(f)}</td><td><strong>${esc(f.path)}" in output
    assert 'colspan="7"' in output
    assert "<dt>Potential impact</dt>" in output
    assert "if confirmed</strong>" in output
    assert "</div></div></header>${fs.length?fs.map(f=>findingCard(f,fs.length===1))" in output
    assert '<h1 class="wordmark">provtrail</h1>' in output
    assert ".wordmark{margin:0;color:var(--teal)" in output
    assert 'class="mark"' not in output
    assert "Request URL validation can be bypassed" in output
    assert "title.toLocaleLowerCase()!==identifier.toLocaleLowerCase()" in output
    assert "p.cve_id||p.ghsa_id||p.osv_id||p.identifier" in output
    assert 'class="advisory-action"' not in output
    assert "icons.external" not in output
    assert 'class="advisory-id-link"' in output
    assert "const linkedIdentifier=advisoryIdentifierLink(p.advisory_url,identifier)" in output
    assert "`${linkedIdentifier}: ${esc(title)}`" in output
    assert 'class="affected-locations"' in output
    assert "background:var(--location-bg)" in output
    assert "Version ranges apply to upstream" in output
    assert "For copied or adapted code" in output
    assert "These ranges describe the source advisory" not in output
    assert "description.length>240" in output
    assert "Show more" in output
    assert "Show less" in output
    assert "-webkit-line-clamp:3" in output
    assert ".summary-toggle{border:0;background:transparent;color:var(--focus);padding:0;font-weight:inherit;text-decoration:underline;text-underline-offset:3px}" in output
    assert ".summary-toggle:hover" not in output
    assert ".patch-line.removed{background:var(--red-bg);color:var(--red)}" in output
    assert ".patch-line.added{background:var(--teal-bg);color:var(--teal)}" in output
    assert "kind==='Removed'?'−':'+'" in output
    assert "https://github.com/advisories/GHSA-test" in output
    assert "Copy summary" not in output
    assert "Why this needs attention" not in output
    assert "Evidence is inconclusive" not in output
    assert "Scan complete · review required" not in output
    assert "Best-effort analysis" not in output
    assert "affected region highlighted" not in output
    assert "<span>JavaScript</span>" not in output
    assert "linear-gradient" not in output
    assert "radial-gradient" not in output
    assert "border-left" not in output
    assert "<link " not in output
    assert "<script src=" not in output
    assert "/private/work/demo" not in output
    assert data["findings"][1]["reference"]["candidate"] is None
    assert all(
        line["marker"] == "detected"
        for line in data["findings"][0]["reference"]["candidate"]["lines"]
    )
    assert data["recommendations"][0]["affected_versions"] == ["< 2.0.0"]
    assert data["recommendations"][0]["patch_changes"]["added"]


def test_html_payload_escapes_script_terminators_but_round_trips_source():
    dangerous = "function request() { return '</script><script>alert(1)</script>'; }"
    data = build_html_report_data(_summary(dangerous), entries=[_entry()], config=ScanConfig())
    output = render_html_report(data)

    assert dangerous not in output
    match = re.search(
        r'<script id="provtrail-data" type="application/json">(.*?)</script>',
        output,
        re.DOTALL,
    )
    assert match is not None
    payload = json.loads(match.group(1))
    reconstructed = "\n".join(
        line["text"] for line in payload["findings"][0]["reference"]["candidate"]["lines"]
    )
    assert reconstructed == dangerous


def test_candidate_highlight_uses_local_verified_region_when_available():
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
    output = render_html_report(
        build_html_report_data(_summary(), entries=[_entry()], config=ScanConfig())
    )
    scripts = re.findall(r"<script(?: [^>]*)?>(.*?)</script>", output, re.DOTALL)
    script_path = tmp_path / "report.js"
    script_path.write_text(scripts[-1], encoding="utf-8")

    result = subprocess.run(
        ["node", "--check", str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_manual_review_explanation_is_embedded_in_its_finding():
    summary = _summary()
    summary.findings[0]["result"]["status"] = "manual_review"
    summary.findings[0]["review_explanation"] = {
        "status": "generated",
        "model": "qwen3:8b",
        "generated_at": "2026-08-17T10:00:00+08:00",
        "relevance_tier": 2,
        "llm_verdict": "needs_review",
        "verdict_rationale": "The request path is present, but redirect handling is outside the region.",
        "security_mechanism": "Every redirect destination must be validated.",
        "supporting_evidence": ["The original request path remains."],
        "contradicting_evidence": ["A validation branch is also present."],
        "review_steps": ["Trace validation across every redirect."],
        "limitations": ["Runtime configuration was not evaluated."],
        "error_code": None,
    }
    summary.explanation_run = {
        "enabled": True,
        "provider": "ollama",
        "model": "qwen3:8b",
        "generated": 1,
        "reused": 0,
        "unavailable": 0,
    }

    data = build_html_report_data(summary, entries=[_entry()], config=ScanConfig())
    output = render_html_report(data)

    assert data["schema"] == "provtrail_html_report_v2"
    assert data["explanation_run"]["model"] == "qwen3:8b"
    assert data["findings"][0]["review_explanation"]["status"] == "generated"
    assert "LLM Explanation" in output
    assert "By ${model}" in output
    assert "Verdict: ${verdictText}" in output
    assert "LLM verdict: ${verdictText}" not in output
    assert "Tier ${tier} of 3" not in output
    assert "Totally irrelevant" not in output
    assert "Independent advisory-relevance opinion" in output
    assert "if(verdict==='dismissed')return" in output
    assert 'class="review-explanation dismissed"' in output
    assert ".review-explanation.dismissed .verdict-rationale" in output
    assert "reviews.some(f=>llmVerdict(f)==='flagged')" in output
    assert "reviews.some(f=>llmVerdict(f)!=='dismissed')" in output
    assert "Trace validation across every redirect." in output
    assert "Review explanation model" in output
    assert "Explanations unavailable" in output


def test_existing_corpus_database_is_migrated_and_metadata_round_trips(tmp_path):
    path = tmp_path / "corpus.db"
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE corpus_entries (
        ghsa_id TEXT NOT NULL, cve_id TEXT, osv_id TEXT, cwes TEXT NOT NULL DEFAULT '[]',
        severity TEXT NOT NULL DEFAULT 'unknown', package_name TEXT NOT NULL,
        ecosystem TEXT NOT NULL, repo TEXT NOT NULL, fix_commit_sha TEXT NOT NULL,
        file_path TEXT NOT NULL, function_name TEXT, vulnerable_function TEXT NOT NULL,
        patched_function TEXT NOT NULL, diagnostic_lines TEXT NOT NULL DEFAULT '[]',
        affected_versions TEXT NOT NULL DEFAULT '[]', fixed_versions TEXT NOT NULL DEFAULT '[]',
        osv_confirmed INTEGER NOT NULL DEFAULT 0,
        UNIQUE (ghsa_id, fix_commit_sha, file_path, function_name))"""
    )
    conn.commit()
    conn.close()

    migrated = get_connection(path)
    columns = {row[1] for row in migrated.execute("PRAGMA table_info(corpus_entries)")}
    migrated.close()
    assert {"advisory_title", "advisory_description", "advisory_url", "advisory_references"} <= columns

    save_entries([_entry()], path)
    loaded = load_entries(path)
    assert loaded[0].advisory_title == "Request URL validation can be bypassed"
    assert loaded[0].advisory_references == ["https://nvd.nist.gov/vuln/detail/CVE-2026-1234"]


def test_advisory_metadata_changes_corpus_fingerprint():
    original = _entry()
    renamed = original.model_copy(update={"advisory_title": "Updated advisory title"})

    assert corpus_fingerprint([original]) != corpus_fingerprint([renamed])


def test_advisory_title_is_indexed_as_descriptive_pair_metadata():
    pairs = extract_vulnerability_regions(_entry())
    renamed = [pair.model_copy(update={"advisory_title": "Updated title"}) for pair in pairs]

    assert all(pair.advisory_title == "Request URL validation can be bypassed" for pair in pairs)
    assert _region_fingerprint(pairs, "test-model") != _region_fingerprint(renamed, "test-model")


def test_cli_scan_writes_json_and_html_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr("cli.main.load_entries", lambda *_args, **_kwargs: [_entry()])
    monkeypatch.setattr("cli.main.scan_directory", lambda *_args, **_kwargs: _summary())
    monkeypatch.setattr("cli.main.build_default_detector_factory", lambda *_args, **_kwargs: lambda: None)

    exit_code = main(["scan", str(tmp_path)])

    assert exit_code == 1
    json_path = tmp_path / ".provtrail" / "latest-scan.json"
    html_path = tmp_path / ".provtrail" / "latest-scan.html"
    assert json_path.exists()
    assert html_path.exists()
    assert json.loads(json_path.read_text(encoding="utf-8"))["schema"] == "provtrail_scan_v3"
    assert "source" not in json_path.read_text(encoding="utf-8")
    assert "Project Directory" in html_path.read_text(encoding="utf-8")


def test_cli_explain_review_wires_ollama_options_and_persists_result(monkeypatch, tmp_path):
    summary = _summary()
    calls = []

    def explain(received_summary, **kwargs):
        calls.append((received_summary, kwargs))
        received_summary.findings[0]["review_explanation"] = {
            "status": "generated",
            "model": kwargs["ollama_config"].model,
            "relevance_tier": 1,
            "llm_verdict": "dismissed",
            "verdict_rationale": "The advisory mechanism is absent.",
        }
        received_summary.explanation_run = {
            "enabled": True,
            "provider": "ollama",
            "model": kwargs["ollama_config"].model,
            "generated": 1,
            "reused": 0,
            "unavailable": 0,
        }

    monkeypatch.setattr("cli.main.load_entries", lambda *_args, **_kwargs: [_entry()])
    monkeypatch.setattr("cli.main.scan_directory", lambda *_args, **_kwargs: summary)
    monkeypatch.setattr("cli.main.build_default_detector_factory", lambda *_args, **_kwargs: lambda: None)
    monkeypatch.setattr("cli.main.enrich_manual_review_findings", explain)

    exit_code = main(
        [
            "scan",
            str(tmp_path),
            "--explain-review",
            "--ollama-model",
            "qwen3:8b",
            "--ollama-host",
            "localhost:11434",
            "--ollama-timeout",
            "30",
        ]
    )

    assert exit_code == 1
    assert len(calls) == 1
    _, kwargs = calls[0]
    assert kwargs["ollama_config"].model == "qwen3:8b"
    assert kwargs["ollama_config"].host == "localhost:11434"
    assert kwargs["ollama_config"].timeout == 30
    assert kwargs["cache_path"].name == "review-explanations.json"
    saved = json.loads((tmp_path / ".provtrail" / "latest-scan.json").read_text())
    assert saved["explanation_run"]["generated"] == 1
    assert saved["findings"][0]["review_explanation"]["llm_verdict"] == "dismissed"
