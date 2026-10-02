"""Human review lifecycle across CLI, incremental scans and offline artifacts."""

import copy
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from provtrail.cli.commands.exports import write_exports, write_text_atomic
from provtrail.cli.main import main
from provtrail.pipeline.controller.finding_exports import build_sarif, format_ai
from provtrail.pipeline.controller.html_reporting import build_html_report_data, load_html_report_data, write_html_report
from provtrail.pipeline.controller.reporting import audit_summary, report_exit_code, report_view
from provtrail.pipeline.models.result import RegionDetectionResult
from provtrail.pipeline.scanning.dismissals import (
    apply_dismissals, dismissal_lock, dismissal_path, finding_id, is_dismissed,
    load_dismissals, make_dismissal, save_dismissals,
)
from provtrail.pipeline.scanning.scanner import ScanConfig, scan_directory


FIXTURE = json.loads((Path(__file__).parent / "fixtures/region_model_contracts.json").read_text(encoding="utf-8"))["payloads"]["vulnerable"]["payload"]


class Detector:
    def __init__(self, priority="manual_review"):
        self.calls = 0
        self.priority = priority

    def detect(self, source, candidate_id=None, language=None):
        self.calls += 1
        payload = copy.deepcopy(FIXTURE)
        payload.update(priority=self.priority, candidate_id=candidate_id, decision_policy="expanded_ast_v1")
        for state in payload["vulnerability_states"]:
            state["status"] = {"automatic_vulnerability": "vulnerable", "manual_review": "uncertain", "informational_lineage": "patched"}[self.priority]
        return RegionDetectionResult.model_validate(payload)


def scan(root, detector=None, config=None, custom=False):
    config = config or ScanConfig(corpus_version="test-v1")
    summary = scan_directory(root, detector=detector or Detector(), config=config)
    directory = root / ("reports" if custom else ".provtrail")
    directory.mkdir(exist_ok=True)
    report_path = directory / ("custom.json" if custom else "latest-scan.json")
    html_path = directory / "details.html"
    sarif_path = directory / "findings.sarif"
    ai_path = directory / "findings.txt"
    payload = summary.to_dict()
    payload["artifacts"] = {"html": str(html_path), "sarif": str(sarif_path), "ai": str(ai_path)}
    write_text_atomic(report_path, json.dumps(payload))
    data = build_html_report_data(summary, entries=[], config=config, report_path=report_path)
    write_html_report(html_path, data)
    write_exports(payload, sarif_path=sarif_path, ai_path=ai_path)
    return summary, report_path, html_path


def source(root, filename="source.js", text="function first(x) { return x + 1; }\n"):
    path = root / filename
    path.write_text(text, encoding="utf-8")
    return path


def test_dismiss_updates_all_artifacts_preserves_evidence_and_undo_restores_queue(tmp_path, capsys):
    source(tmp_path, text="function first(x) { return x + 1; }\nfunction second(x) { return x + 2; }\n")
    summary, report_path, html_path = scan(tmp_path)
    identity = summary.findings[0]["finding_id"]
    original_html = load_html_report_data(html_path)
    state_before = (tmp_path / ".provtrail/scan-state.json").read_bytes()
    reason = "Reviewed <script>alert(1)</script>; caller validates input"
    assert main(["dismiss", str(tmp_path), "--finding", identity, "--reason", reason]) == 0
    report = json.loads(report_path.read_text())
    assert report["findings"][0]["result"] == summary.findings[0]["result"]
    assert is_dismissed(report["findings"][0])
    assert audit_summary(report)["manual_review"] == 1
    assert audit_summary(report)["dismissed"] == 1
    assert report["active_priority_counts"] == {"automatic_vulnerability": 0, "manual_review": 1}
    assert report["priority_counts"]["manual_review"] == 2
    assert (tmp_path / ".provtrail/scan-state.json").read_bytes() == state_before
    assert len(report_view(report)["findings"]) == 1
    assert len(report_view(report, include_dismissed=True)["findings"]) == 2
    assert "html_finding" not in report["dismissal_history"][0]
    assert len(json.loads((html_path.parent / "findings.sarif").read_text())["runs"][0]["results"]) == 1
    assert "total=1 vuln=0 review=1" in (html_path.parent / "findings.txt").read_text()
    updated_html = load_html_report_data(html_path)
    assert updated_html["findings"][0]["boundaries"] == original_html["findings"][0]["boundaries"]
    assert updated_html["audit"]["dismissed"] == 1
    assert updated_html["outcome_counts"]["manual_review"] == 1
    assert str(tmp_path) not in html_path.read_text(encoding="utf-8")
    assert reason not in html_path.read_text(encoding="utf-8")  # Embedded data escapes script terminators.
    capsys.readouterr()
    assert main(["dismissed", str(tmp_path), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)["dismissals"]
    assert len(rows) == 1 and rows[0]["status"] == "dismissed" and rows[0]["reason"] == reason
    assert main(["dismiss", str(tmp_path), "--finding", identity[:12], "--undo"]) == 0
    restored = json.loads(report_path.read_text())
    assert not any(is_dismissed(item) for item in restored["findings"])
    assert audit_summary(restored)["manual_review"] == 2
    assert load_dismissals(tmp_path) == []
    assert load_html_report_data(html_path)["dismissal_history"] == []


def test_unchanged_dismissal_survives_cache_reuse_cache_removal_and_unrelated_changes(tmp_path):
    source(tmp_path)
    detector = Detector()
    summary, _report, _html = scan(tmp_path, detector)
    assert main(["dismiss", str(tmp_path), "--finding", summary.findings[0]["finding_id"]]) == 0
    calls = detector.calls
    source(tmp_path, "other.js", "function unrelated() { return 99; }\n")
    next_scan = scan_directory(tmp_path, detector=detector, config=ScanConfig(corpus_version="test-v1"))
    reviewed = next(item for item in next_scan.findings if item["path"] == "source.js")
    assert is_dismissed(reviewed) and detector.calls == calls + 1
    (tmp_path / ".provtrail/scan-state.json").unlink()
    fresh = scan_directory(tmp_path, detector=Detector(), config=ScanConfig(corpus_version="unrelated-corpus-update"))
    assert is_dismissed(next(item for item in fresh.findings if item["path"] == "source.js"))
    assert len(load_dismissals(tmp_path)) == 1
    # A fully cached scan must not initialize a detector to apply review state.
    def forbidden():
        pytest.fail("Unchanged scan initialized the detector")
    cached = scan_directory(tmp_path, detector_factory=forbidden, config=ScanConfig(corpus_version="unrelated-corpus-update"))
    assert cached.scanned_functions == 0 and audit_summary(cached.to_dict())["dismissed"] == 1


@pytest.mark.parametrize("edit", [
    "// Changed surrounding code\nfunction first(x) { return x + 1; }\n",
    "function first(x) { return x + 2; }\n",
])
def test_file_and_function_changes_reopen_review_and_keep_reason(tmp_path, edit):
    path = source(tmp_path)
    original, report_path, _html = scan(tmp_path)
    identity = original.findings[0]["finding_id"]
    assert main(["dismiss", str(tmp_path), "--finding", identity, "--reason", "Checked caller"]) == 0
    path.write_text(edit, encoding="utf-8")
    old_records = dismissal_path(tmp_path).read_bytes()
    assert main(["dismiss", str(tmp_path), "--finding", identity]) == 2
    assert dismissal_path(tmp_path).read_bytes() == old_records
    updated, _report, html = scan(tmp_path)
    assert not is_dismissed(updated.findings[0])
    assert updated.findings[0]["dismissal"]["status"] == "reopened"
    assert updated.findings[0]["dismissal"]["reason"] == "Checked caller"
    assert updated.dismissal_history[0]["status"] == "file_changed"
    assert report_exit_code(updated.to_dict()) == 1
    history = load_html_report_data(html)["dismissal_history"][0]
    assert history["historical"] and history["finding_id"] == identity


def test_duplicate_code_other_files_and_anonymous_functions_are_not_dismissed_together(tmp_path):
    text = "const a = function () { return 1; };\nconst b = function () { return 1; };\n"
    source(tmp_path, "a.js", text)
    source(tmp_path, "b.js", text)
    summary, _report, _html = scan(tmp_path)
    assert len(summary.findings) == 4
    assert len({item["finding_id"] for item in summary.findings}) == 4
    assert main(["dismiss", str(tmp_path), "--finding", summary.findings[0]["finding_id"]]) == 0
    next_scan = scan_directory(tmp_path, detector=Detector(), config=ScanConfig(corpus_version="test-v1"))
    assert sum(is_dismissed(item) for item in next_scan.findings) == 1
    assert audit_summary(next_scan.to_dict())["findings"] == 3


@pytest.mark.parametrize("operation", ["rename", "delete"])
def test_missing_and_renamed_files_retain_expired_history(tmp_path, operation):
    path = source(tmp_path)
    summary, _report, _html = scan(tmp_path)
    assert main(["dismiss", str(tmp_path), "--finding", summary.findings[0]["finding_id"]]) == 0
    if operation == "rename":
        path.rename(tmp_path / "renamed.js")
    else:
        path.unlink()
    updated, _report, html = scan(tmp_path)
    assert updated.dismissal_history[0]["status"] == "file_missing"
    assert not any(is_dismissed(item) for item in updated.findings)
    assert load_html_report_data(html)["dismissal_history"][0]["path"] == "source.js"


def test_new_boundary_or_priority_change_requires_new_review(tmp_path):
    source(tmp_path)
    summary, _report, _html = scan(tmp_path)
    original = summary.findings[0]
    record = make_dismissal(original, "Reviewed existing advisory")
    changed = copy.deepcopy(original)
    extra = copy.deepcopy(changed["result"]["vulnerability_states"][0])
    extra["fix_boundary_id"] = "new-fix"
    changed["result"]["vulnerability_states"].append(extra)
    report = {"findings": [changed]}
    apply_dismissals(report, [record])
    assert not is_dismissed(changed) and changed["finding_id"] != original["finding_id"]
    assert report["dismissal_history"][0]["status"] == "finding_changed"
    changed = copy.deepcopy(original)
    changed["result"]["priority"] = "automatic_vulnerability"
    apply_dismissals({"findings": [changed]}, [record])
    assert not is_dismissed(changed)
    # Human state is separate from a model's relevance opinion.
    same = copy.deepcopy(original)
    same["review_explanation"] = {"status": "generated", "llm_verdict": "flagged"}
    apply_dismissals({"findings": [same]}, [record])
    assert is_dismissed(same)


def test_resolved_finding_keeps_review_history_without_an_actionable_result(tmp_path):
    source(tmp_path)
    original, _report, _html = scan(tmp_path)
    identity = original.findings[0]["finding_id"]
    assert main(["dismiss", str(tmp_path), "--finding", identity, "--reason", "Reviewed old boundary"]) == 0
    updated, _report, html = scan(tmp_path, Detector("informational_lineage"), ScanConfig(corpus_version="updated-reference"))
    assert updated.dismissal_history[0]["status"] == "no_longer_present"
    assert updated.dismissal_history[0]["reason"] == "Reviewed old boundary"
    assert not is_dismissed(updated.findings[0])
    assert report_exit_code(updated.to_dict()) == 0
    assert audit_summary(updated.to_dict())["informational_lineage"] == 1
    assert load_html_report_data(html)["dismissal_history"][0]["finding_id"] == identity


def test_dependency_context_changes_expire_dismissal_and_reject_stale_scan(tmp_path, capsys):
    source(tmp_path)
    summary, _report, _html = scan(tmp_path)
    item = summary.findings[0]
    package = item["result"]["package_applicabilities"][0]["package"]
    assert main(["dismiss", str(tmp_path), "--finding", item["finding_id"]]) == 0
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {package: "1.2.3"}}), encoding="utf-8")
    capsys.readouterr()
    assert main(["dismissed", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["dismissals"][0]["status"] == "finding_changed"
    assert main(["dismiss", str(tmp_path), "--finding", item["finding_id"]]) == 2
    updated = scan_directory(tmp_path, detector=Detector(), config=ScanConfig(corpus_version="test-v1"))
    assert updated.reused_functions == 1 and not is_dismissed(updated.findings[0])


def test_all_dismissed_exit_zero_and_saved_report_exports_respect_current_decisions(tmp_path, capsys):
    source(tmp_path)
    summary, report_path, _html = scan(tmp_path, Detector("automatic_vulnerability"))
    assert main(["dismiss", str(tmp_path), "--finding", summary.findings[0]["finding_id"]]) == 0
    report = json.loads(report_path.read_text())
    assert report_exit_code(report) == 0
    assert build_sarif(report, tool_version="test")["runs"][0]["results"] == []
    assert format_ai(report).endswith("total=0 vuln=0 review=0\n")
    capsys.readouterr()
    assert main(["report", str(tmp_path), "--json", "--include-dismissed"]) == 0
    details = json.loads(capsys.readouterr().out)
    assert len(details["findings"]) == 1 and details["audit"]["dismissed"] == 1
    source(tmp_path, text="function first(x) { return x + 2; }\n")
    assert main(["report", str(tmp_path), "--json"]) == 1
    assert len(json.loads(capsys.readouterr().out)["findings"]) == 1


def test_custom_report_paths_and_idempotent_dismissal(tmp_path):
    source(tmp_path)
    summary, report_path, html_path = scan(tmp_path, custom=True)
    assert load_html_report_data(html_path)["review_report_path"] == "reports/custom.json"
    identity = summary.findings[0]["finding_id"]
    assert main(["dismiss", str(tmp_path), "--report", "reports/custom.json", "--finding", identity[:12], "--reason", "First reason"]) == 0
    original = load_dismissals(tmp_path)[0]
    assert main(["dismiss", str(report_path), "--finding", identity, "--reason", "Another reason"]) == 0
    assert load_dismissals(tmp_path)[0] == original
    assert load_html_report_data(html_path)["audit"]["dismissed"] == 1


def test_corrupt_review_state_never_hides_findings_or_gets_overwritten(tmp_path, capsys):
    source(tmp_path)
    summary, _report, _html = scan(tmp_path)
    dismissal_path(tmp_path).write_text("{broken", encoding="utf-8")
    updated = scan_directory(tmp_path, detector=Detector(), config=ScanConfig(corpus_version="test-v1"))
    assert not is_dismissed(updated.findings[0])
    assert "no human dismissals applied" in capsys.readouterr().err
    assert main(["dismiss", str(tmp_path), "--finding", summary.findings[0]["finding_id"]]) == 2
    assert dismissal_path(tmp_path).read_text() == "{broken"


def test_old_report_and_concurrent_writer_cannot_create_review_decisions(tmp_path):
    source(tmp_path)
    summary, report_path, _html = scan(tmp_path)
    identity = summary.findings[0]["finding_id"]
    with dismissal_lock(tmp_path):
        assert main(["dismiss", str(tmp_path), "--finding", identity]) == 2
    assert not dismissal_path(tmp_path).exists()
    old = json.loads(report_path.read_text())
    old["findings"][0].pop("file_hash")
    write_text_atomic(report_path, json.dumps(old))
    assert main(["dismiss", str(tmp_path), "--finding", identity]) == 2
    assert not dismissal_path(tmp_path).exists()


def test_history_can_be_listed_after_scan_artifacts_are_removed(tmp_path, capsys):
    source(tmp_path)
    summary, report_path, _html = scan(tmp_path)
    assert main(["dismiss", str(tmp_path), "--finding", summary.findings[0]["finding_id"]]) == 0
    report_path.unlink()
    capsys.readouterr()
    assert main(["dismissed", str(tmp_path), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)["dismissals"]
    assert rows[0]["status"] == "scan_unavailable"


def test_dismissed_manual_review_skips_model_generation(tmp_path, monkeypatch):
    from provtrail.pipeline.controller.review_explanation import OllamaExplanationConfig, enrich_manual_review_findings
    source(tmp_path)
    summary, _report, _html = scan(tmp_path)
    save_dismissals(tmp_path, [make_dismissal(summary.findings[0], "Checked")])
    summary = scan_directory(tmp_path, detector=Detector(), config=ScanConfig(corpus_version="test-v1"))
    def forbidden(*args, **kwargs):
        pytest.fail("Dismissed review requested model generation")
    monkeypatch.setattr("provtrail.pipeline.controller.review_explanation.OllamaReviewExplainer.ensure_model_available", forbidden)
    stats = enrich_manual_review_findings(summary, entries=[], scan_config=ScanConfig(), ollama_config=OllamaExplanationConfig(), cache_path=tmp_path / ".provtrail/review-explanations.json")
    assert stats.generated == stats.reused == stats.unavailable == 0


def test_offline_html_filters_history_and_quotes_copied_commands(tmp_path):
    if shutil.which("node") is None:
        pytest.skip("Node is needed to exercise offline report behavior")
    source(tmp_path)
    summary, _report, html_path = scan(tmp_path)
    assert main(["dismiss", str(tmp_path), "--finding", summary.findings[0]["finding_id"]]) == 0
    source(tmp_path, text="// changed surrounding code\nfunction first(x) { return x + 1; }\n")
    _summary, _report, html_path = scan(tmp_path)
    data_path = tmp_path / "report-data.json"
    data_path.write_text(json.dumps(load_html_report_data(html_path)), encoding="utf-8")
    harness = tmp_path / "check-report.cjs"
    script_path = Path(__file__).parents[1] / "src/provtrail/pipeline/controller/report_view.js"
    harness.write_text(r'''
const fs = require("fs"), vm = require("vm"), assert = require("assert");
const data = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const elements = {};
for (const id of ["search", "review-project", "review-report", "review-reason", "review-command", "review-copy-status", "review-title", "review-location", "review-instructions", "review-reason-label", "copy-review-command", "review-dialog", "show-all-files", "tree-count", "tree"]) {
  elements["#" + id] = {value: "", checked: false, textContent: "", hidden: false, innerHTML: "", showModal() { this.open = true; }};
}
elements["#report-data"] = {textContent: JSON.stringify(data)};
const sandbox = {console, document: {getElementById: id => elements["#" + id], querySelector: key => elements[key], querySelectorAll: () => []}, assert};
vm.createContext(sandbox);
const script = fs.readFileSync(process.argv[3], "utf8").replace(/init\(\);\s*$/, "");
vm.runInContext(script, sandbox);
vm.runInContext(`
assert.equal(currentMatches.length, 1);
assert.equal(historyMatches.length, 1);
assert.equal(matches.filter(visibleFinding).length, 1);
assert.equal(matches.filter(visibleFinding)[0].dismissal.status, "reopened");
viewFilter = "dismissed";
assert.equal(matches.filter(visibleFinding).length, 1);
assert.equal(matches.filter(visibleFinding)[0].historical, true);
assert.equal(matches.filter(visibleFinding)[0].dismissal.status, "file_changed");
renderTree();
assert.ok($("#tree").innerHTML.includes("source.js"));
assert.ok(reviewPanel(currentMatches[0]).includes("Review reopened"));
assert.ok(reviewPanel(historyMatches[0]).includes("Remove previous dismissal"));
openReview(historyMatches[0].id);
assert.ok(reviewCommand.endsWith("--undo"));
assert.equal($("#review-reason-label").hidden, true);
openReview(currentMatches[0].id);
$("#review-project").value = "C:/a'b/project";
$("#review-reason").value = "Reviewed 'caller'; $() and backticks stay literal";
$("#review-report").value = "reports/custom.json";
updateReviewCommand();
assert.ok(reviewCommand.includes("'C:/a''b/project'"));
assert.ok(reviewCommand.includes("--reason='Reviewed ''caller''; $() and backticks stay literal'"));
assert.ok(reviewCommand.includes("--report='reports/custom.json'"));
assert.ok(!reviewCommand.includes("--undo"));
assert.ok($("#review-command").innerHTML.includes('class="command-program"'));
assert.ok($("#review-command").innerHTML.includes('class="command-option">--reason</span>'));
$("#review-reason").value = "<script>alert('x')</script>";
updateReviewCommand();
assert.ok(!$("#review-command").innerHTML.includes("<script>"));
assert.ok($("#review-command").innerHTML.includes("&lt;script&gt;"));
viewFilter = "all";
assert.equal(matches.filter(visibleFinding).length, 1);
currentMatches[0].dismissal.status = "dismissed";
viewFilter = "attention";
assert.equal(matches.filter(visibleFinding).length, 0);
viewFilter = "dismissed";
assert.equal(matches.filter(visibleFinding).length, 2);
`, sandbox);
vm.runInContext(`(async () => {
  let copiedText;
  globalThis.navigator = {clipboard: {async writeText(text) { copiedText = text; }}};
  await copyReviewCommand();
  assert.equal(copiedText, reviewCommand);
  assert.ok(!copiedText.includes('class="command-'));
  navigator.clipboard.writeText = async () => { throw new Error("Clipboard unavailable"); };
  let selectedNode;
  $("#review-command").focus = () => {};
  document.createRange = () => ({selectNodeContents(node) { selectedNode = node; }});
  globalThis.window = {getSelection: () => ({removeAllRanges() {}, addRange() {}})};
  document.execCommand = command => command === "copy";
  await copyReviewCommand();
  assert.equal(selectedNode, $("#review-command"));
  assert.ok($("#review-copy-status").textContent.startsWith("Copied."));
})()`, sandbox).catch(error => { console.error(error); process.exitCode = 1; });
''', encoding="utf-8")
    result = subprocess.run(["node", str(harness), str(data_path), str(script_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
