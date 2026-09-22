"use strict";

const report = JSON.parse(document.getElementById("report-data").textContent);
const $ = selector => document.querySelector(selector);
const $$ = selector => Array.from(document.querySelectorAll(selector));
const esc = value => String(value ?? "").replace(/[&<>"']/g, char => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
}[char]));
const markdown = value => esc(value).replace(/`([^`\n]+)`/g, "<code>$1</code>").replace(/\*\*([^*\n]+)\*\*/g, "<strong>$1</strong>").replace(/\n/g, "<br>");
const label = value => String(value ?? "unknown").replaceAll("_", " ").replace(/\b\w/g, char => char.toUpperCase());
const score = value => value === null || value === undefined || value === "" ? "Not recorded" : Number.isFinite(Number(value)) ? Number(value).toFixed(3) : "Not recorded";
const vulnerable = finding => ["flagged_exact", "flagged_inferred"].includes(finding.outcome);
const matches = report.findings.filter(finding => vulnerable(finding) || ["manual_review", "patched"].includes(finding.outcome));
const byId = new Map(report.findings.map(finding => [finding.id, finding]));
const decisionLabel = finding => vulnerable(finding) ? "Vulnerable match" : finding.outcome === "patched" ? "Patched match" : "Review required";
const decisionTone = finding => vulnerable(finding) ? "vulnerable" : finding.outcome === "patched" ? "patched" : "review";
let selectedFile = "";
let viewFilter = "attention";
let comparison = null;
let comparisonMode = "patched";

function facts(rows) {
  return '<dl class="facts">' + rows.filter(([, value]) => value !== null && value !== undefined && value !== "")
    .map(([name, value]) => `<dt>${esc(name)}</dt><dd>${esc(value)}</dd>`).join("") + "</dl>";
}

function externalLink(url, text) {
  return url ? `<a class="button external-link" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${esc(text)}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M14 3h7v7M21 3 10 14M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/></svg><span class="sr-only"> (opens in a new tab)</span></a>` : "";
}

// The overview and file navigation share one filter so their counts always agree.
function visibleFinding(finding) {
  if (viewFilter === "attention" && finding.outcome === "patched") return false;
  if (viewFilter === "vulnerable" && !vulnerable(finding)) return false;
  if (["manual_review", "patched"].includes(viewFilter) && finding.outcome !== viewFilter) return false;
  const query = $("#search").value.trim().toLowerCase();
  const terms = [finding.path, finding.name, finding.primary.title, finding.primary.identifier];
  for (const boundary of finding.boundaries) {
    terms.push(boundary.lineage.repo, boundary.lineage.reference_function);
    for (const alias of boundary.advisories) terms.push(alias.identifier, alias.title, alias.ghsa_id, alias.package_name);
  }
  return !query || terms.filter(Boolean).join(" ").toLowerCase().includes(query);
}

function renderTree() {
  const visible = matches.filter(visibleFinding);
  const counts = new Map();
  for (const finding of visible) counts.set(finding.path, (counts.get(finding.path) || 0) + 1);
  const query = $("#search").value.trim().toLowerCase();
  const paths = report.scanned_files.filter(path => counts.has(path) || (
    $("#show-all-files").checked && (!query || path.toLowerCase().includes(query))
  ));
  $("#tree-count").textContent = `${paths.length} of ${report.scanned_files.length}`;
  $("#tree").innerHTML = paths.sort().map(path => `<button class="tree-file" data-path="${esc(path)}" ${path === selectedFile ? 'aria-current="page"' : ""}><span>${esc(path)}</span><span class="file-count">${counts.get(path) || 0}</span></button>`).join("") || '<p class="muted">No files match these filters.</p>';
}

function findingCard(finding) {
  const method = finding.outcome === "flagged_exact" ? "Exact native match" : vulnerable(finding) ? "Inferred match" : "";
  const verified = finding.boundaries.filter(boundary => ["vulnerable", "patched"].includes(boundary.state.status) && !boundary.state.contradictions?.length).length;
  const uncertain = finding.outcome === "manual_review";
  return `<details class="finding" data-finding="${esc(finding.id)}">
    <summary><div class="finding-heading">
      <div class="badges"><span class="badge ${decisionTone(finding)}">${decisionLabel(finding)}</span>${method ? `<span class="badge">${method}</span>` : ""}${verified > 1 ? `<span class="badge">${verified} verified fixes</span>` : ""}</div>
      <h3>${esc(finding.primary.title || finding.name)}</h3>
      <div class="finding-meta">
        <div class="project-location"><code>${esc(finding.name)}</code><span class="location">${esc(finding.path)}:${finding.start_line}–${finding.end_line}</span></div>
        <div class="reference-advisory"><strong class="meta-label">Reference advisory</strong><div class="reference-identity"><span class="alias-id">${esc(finding.primary.identifier)}</span><strong class="severity">${esc(label(finding.severity))}</strong></div>${uncertain ? '<span class="location">Relevance unconfirmed</span>' : ""}</div>
      </div>
    </div></summary><div class="finding-body"></div></details>`;
}

function renderContent() {
  const visible = matches.filter(finding => visibleFinding(finding) && (!selectedFile || finding.path === selectedFile));
  const title = selectedFile || (viewFilter === "patched" ? "Recognised patched code" : "Review findings");
  const fileCount = new Set(visible.map(finding => finding.path)).size;
  const count = `${visible.length} function${visible.length === 1 ? "" : "s"} in ${fileCount} file${fileCount === 1 ? "" : "s"}`;
  const hasFilter = viewFilter !== "attention" || $("#search").value.trim() || selectedFile;
  const emptyTitle = hasFilter ? "No findings match this view" : "No known vulnerable matches require attention";
  const emptyText = hasFilter ? "Change the search or result view to inspect other findings." : "Open Patched matches to inspect recognised fixes. This result applies to the available corpus and scanned functions.";
  $("#content").innerHTML = `<header class="content-head"><div><h2>${esc(title)}</h2><p class="muted" aria-live="polite">${count}</p></div></header>`
    + (visible.length ? '<div class="code-legend" aria-label="Code highlight legend"><span>Highlights</span><span class="legend-item detected">Project match</span><span class="legend-item removed">Removed upstream</span><span class="legend-item added">Added upstream</span></div>' : "")
    + (visible.length ? visible.map(findingCard).join("") : `<div class="empty"><strong>${emptyTitle}</strong><p>${emptyText}</p></div>`);
  if (visible.length === 1) {
    const card = $("#content details.finding");
    card.open = true;
    populateFinding(card);
  }
}

function render() {
  $("#view-filter").value = viewFilter;
  $$(".counter").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.filter === viewFilter)));
  renderTree();
  renderContent();
}

// Only expanded findings build comparisons, keeping larger reports responsive.
function populateFinding(card) {
  const body = card.querySelector(".finding-body");
  if (!card.open || body.dataset.loaded) return;
  const finding = byId.get(card.dataset.finding);
  const boundaries = finding.boundaries;
  const otherVerified = boundaries.slice(1).filter(item => ["vulnerable", "patched"].includes(item.state.status) && !item.state.contradictions?.length);
  const alternatives = boundaries.slice(1).filter(item => !otherVerified.includes(item));
  body.innerHTML = `<div class="brief">
    <section><h4>What matched</h4><p>${esc(finding.reason)}</p></section>
    <section><h4>What to do next</h4><p>${esc(finding.recommended_action)}</p></section>
  </div>`
    + (boundaries.length ? boundaryCard(finding, boundaries[0], 0) : '<p class="notice">No boundary evidence is recorded for this finding.</p>')
    + boundaryGroup("Other verified boundaries", otherVerified, finding)
    + boundaryGroup("Alternative candidates", alternatives, finding)
    + llmAdvice(finding);
  body.dataset.loaded = "true";
}

function boundaryGroup(title, boundaries, finding) {
  if (!boundaries.length) return "";
  return `<details class="details"><summary>${title} (${boundaries.length})</summary>`
    + boundaries.map(boundary => `<details class="details"><summary class="alternative-heading"><span>${esc(boundary.representative.title || boundary.lineage.reference_function || "Reference metadata unavailable")}</span><span class="badge">${esc(label(boundary.state.status || "unverified"))}</span></summary>${boundaryCard(finding, boundary, finding.boundaries.indexOf(boundary))}</details>`).join("") + "</details>";
}

function boundaryCard(finding, boundary, index) {
  const rep = boundary.representative;
  const state = boundary.state;
  const aliases = boundary.advisories.filter(alias => index !== 0 || alias.identifier !== finding.primary.identifier)
    .map(alias => `<div class="alias-entry"><div class="reference-identity"><span class="alias-id">${externalLink(alias.advisory_url, alias.identifier) || esc(alias.identifier)}</span><strong class="severity">${esc(label(alias.severity))}</strong></div><span>${esc(alias.title === alias.identifier ? "" : alias.title)}</span></div>`).join("");
  const patch = rep.patch_changes || {removed: [], added: []};
  const changes = [...patch.removed.map(line => ["removed", "−", line]), ...patch.added.map(line => ["added", "+", line])];
  const patchHtml = changes.length ? '<div class="patch-lines">' + changes.map(([kind, sign, line]) => `<div class="patch ${kind}"><strong aria-label="${kind}">${sign}</strong><code>${esc(line)}</code></div>`).join("") + "</div>" : '<p class="muted">Patch lines are unavailable. Inspect the linked upstream commit.</p>';
  const applications = finding.package_applicabilities.filter(item => item.lineage_id === boundary.lineage.lineage_id);
  const packageContext = applications.map(item => `${item.package}: ${label(item.status)}`).join(", ") || "Unknown";
  const identityWarning = state.function_identity_state === "conflict" && !state.context_correspondence_passed
    ? '<p class="unknowns">Function names conflict and contextual correspondence is not established.</p>' : "";
  const primary = index === 0;
  return `<section class="boundary">
    <div class="boundary-heading"><h4>${primary ? "Relevant upstream fix" : "Reference boundary"}</h4><span class="badge ${state.status === "patched" ? "patched" : ""}">${esc(label(state.status || "unverified"))}</span></div>
    ${!primary ? `<p>${esc(boundary.reason)}</p><p class="unknowns">${esc(boundary.recommended_action)}</p>` : ""}
    ${identityWarning}${aliases ? `<div class="alias-list">${aliases}</div>` : ""}${patchHtml}
    <div class="links">${externalLink(rep.advisory_url, "Advisory")}${externalLink(rep.fix_url, "Fix commit")}
      <button class="button" data-compare="${esc(finding.id)}" data-boundary="${index}">Compare complete source</button>
      <button class="button" data-info="${esc(finding.id)}" data-boundary="${index}">View boundary evidence</button>
    </div>
    <div class="comparison">${codePanel("Project matched region", boundary.reference.candidate)}${codePanel("Vulnerable reference", boundary.reference.vulnerable)}${codePanel("Patched reference", boundary.reference.patched)}</div>
    <details class="details"><summary>Advisory and package context</summary>${rep.advisory_summary ? `<p class="advisory-description">${markdown(rep.advisory_summary)}</p>` : ""}${facts([
      ["Repository", boundary.lineage.repo], ["Reference file", boundary.lineage.file_path],
      ["Reference function", boundary.lineage.reference_function], ["Fix commit", state.fix_commit_sha],
      ["Lineage confidence", label(boundary.lineage.confidence)], ["Reference packages", [...new Set(boundary.advisories.map(alias => alias.package_name).filter(Boolean))].join(", ")],
      ["Target package", finding.target_package.name || "Unknown"], ["Package applicability", packageContext],
    ])}<p class="unknowns">The reference package identifies upstream source. Unknown target ownership does not invalidate a code match or establish an installed dependency.</p></details>
  </section>`;
}

function llmAdvice(finding) {
  if (finding.outcome !== "manual_review") return "";
  const explanation = finding.review_explanation || {};
  if (!explanation.status) return "";
  if (explanation.status !== "generated") {
    const text = explanation.status === "unavailable" ? "Local second opinion unavailable for this scan." : "Optional local second opinion was not generated.";
    return `<p class="source-note">${text}</p>`;
  }
  if (!explanation.reference_matches) return '<p class="source-note">The saved model opinion does not identify this selected boundary. Regenerate it with <code>--explain-review</code> before using it to assess this reference.</p>';
  const verdict = {flagged: "Investigate", dismissed: "Likely unrelated", needs_review: "Uncertain"}[explanation.llm_verdict] || "Uncertain";
  return `<details class="details llm-advice"><summary>Optional model advice: ${verdict}</summary><p class="unknowns">Second opinion only. This does not change the detector decision or the exported review status.</p>
    <p>${markdown(explanation.verdict_rationale || "")}</p>${explanation.security_mechanism ? `<h4>Security mechanism</h4><p>${markdown(explanation.security_mechanism)}</p>` : ""}<p class="muted">Model: ${esc(explanation.model || "Not recorded")}</p></details>`;
}

// Preserve original line numbers, including when the focused view omits context.
function codePanel(title, snippet, complete = false) {
  if (!snippet) return `<section class="code-panel"><div class="code-label">${esc(title)}</div><p class="source-note">Source unavailable.</p></section>`;
  let lines = snippet.lines;
  if (complete && snippet.full_source != null) {
    const highlights = new Set(snippet.highlight_lines || []);
    lines = snippet.full_source.split(/\r?\n/).map((text, index) => ({number: snippet.first_line + index, text, marker: highlights.has(snippet.first_line + index) ? snippet.highlight_kind : ""}));
  }
  let visible = lines;
  if (!complete) {
    const focus = lines.flatMap((line, index) => line.marker ? [index] : []);
    visible = focus.length ? lines.filter((line, index) => focus.some(anchor => Math.abs(index - anchor) <= 2)) : lines.slice(0, 8);
    visible = visible.slice(0, 60);
  }
  let previous = null;
  const rows = visible.map(line => {
    const gap = previous !== null && line.number > previous + 1 ? '<div class="code-gap" aria-label="Context omitted">…</div>' : "";
    previous = line.number;
    return `${gap}<div class="code-line ${esc(line.marker || "")}"><span class="line-no">${line.number}</span><span class="line-text">${esc(line.text) || " "}</span></div>`;
  }).join("");
  const truncated = complete ? snippet.truncated && snippet.full_source == null : snippet.truncated || visible.length < lines.length;
  const count = truncated ? `<span class="code-count" title="Partial source excerpt">${visible.length} of ${snippet.total_lines} lines</span>` : "";
  const note = complete && truncated ? '<p class="source-note">Complete source was not recorded.</p>' : "";
  return `<section class="code-panel"><div class="code-label"><span>${esc(title)}</span>${count}</div><pre class="code">${rows}</pre>${note}</section>`;
}

function openComparison(id, index) {
  const finding = byId.get(id);
  comparison = {finding, boundary: finding.boundaries[index]};
  $("#comparison-title").textContent = `${finding.name}: complete source comparison`;
  $("#comparison-location").textContent = `${finding.path}:${finding.start_line} · ${comparison.boundary.representative.identifier || "Unattributed reference"}`;
  renderComparison();
  $("#comparison-dialog").showModal();
}

function renderComparison() {
  if (!comparison) return;
  const reference = comparison.boundary.reference;
  const panels = [codePanel("Project code", reference.candidate, true)];
  if (comparisonMode !== "patched") panels.push(codePanel("Vulnerable reference", reference.vulnerable, true));
  if (comparisonMode !== "vulnerable") panels.push(codePanel("Patched reference", reference.patched, true));
  $("#comparison-body").innerHTML = `<div class="comparison ${panels.length === 2 ? "two" : ""}">${panels.join("")}</div>`;
  $$("[data-comparison-mode]").forEach(button => button.setAttribute("aria-pressed", String(button.dataset.comparisonMode === comparisonMode)));
}

function openFindingInfo(id, index) {
  const finding = byId.get(id), boundary = finding.boundaries[index];
  const state = boundary.state, observation = boundary.observation;
  $("#finding-info-title").textContent = `Evidence for ${boundary.representative.identifier || "this boundary"}`;
  $("#finding-info-location").textContent = `${finding.path}:${finding.start_line} · ${boundary.lineage.reference_function || "Unknown reference function"}`;
  const rows = [["Boundary score", state.vulnerable_score, state.patched_score], ["Structure", state.structural_vulnerable, state.structural_patched], ["Tokens", state.token_vulnerable, state.token_patched], ["Patch edit", state.edit_vulnerable, state.edit_patched]];
  const scores = boundary.hash_matches.length
    ? `<p>Hash evidence: ${esc(boundary.hash_matches.map(match => `${match.match_type} ${match.side}-side match`).join(", "))}. Region scores were not needed for this match.</p>`
    : '<table class="metrics"><thead><tr><th>Boundary signal</th><th>Vulnerable</th><th>Patched</th></tr></thead><tbody>' + rows.map(([name, left, right]) => `<tr><td>${name}</td><td>${score(left)}</td><td>${score(right)}</td></tr>`).join("") + '</tbody></table>';
  $("#finding-info-body").innerHTML = `<div class="dialog-grid">
    <section class="info-box"><h3>Decision for this boundary</h3><p>${esc(boundary.reason)}</p>${facts([
      ["Boundary", state.fix_boundary_id], ["Fix commit", state.fix_commit_sha], ["State", label(state.status)],
      ["Reason code", state.abstention_reason], ["Boundary contrast", boundary.hash_matches.length ? "Not used for hash match" : score(state.contrast_score)],
      ["Edit strategy", state.edit_strategy], ["Conflicting evidence", (state.contradictions || []).join(" · ")],
    ])}</section>
    <section class="info-box"><h3>Boundary scores</h3>${scores}<p class="source-note">These are similarity measurements for this fix, not probabilities of exploitability.</p></section>
    <section class="info-box"><h3>Verification checks</h3>${facts([
      ["Structure gate", state.structure_gate_passed == null ? "Not recorded" : state.structure_gate_passed ? "Passed" : "Not passed"],
      ["Token gate", state.token_gate_passed == null ? "Not recorded" : state.token_gate_passed ? "Passed" : "Not passed"],
      ["Context correspondence", state.context_correspondence_passed == null ? "Not recorded" : state.context_correspondence_passed ? "Established" : "Not established"],
      ["Function identity", label(state.function_identity_state)], ["Evidence notes", (state.fix_evidence || []).join(" · ")],
    ])}</section>
    <section class="info-box"><h3>Selected project observation</h3><p class="unknowns">This local observation supplies the highlighted span. The boundary verdict may aggregate several observations.</p>${facts([
      ["Region pair", observation.pair_id || "Not recorded"], ["Retrieval similarity", score(observation.retrieval_similarity)],
      ["AST coverage", score(observation.ast_coverage)], ["Project language", finding.source_language],
      ["Reference language", boundary.representative.source_language || "Not recorded"],
    ])}</section></div>`;
  $("#finding-info-dialog").showModal();
}

function openScanInfo() {
  const audit = report.audit, config = report.config, coverage = report.coverage, run = report.explanation_run || {};
  $("#scan-info-body").innerHTML = `<div class="dialog-grid">
    <section class="info-box"><h3>Coverage</h3>${facts([
      ["Files scanned", report.scanned_files.length], ["Functions analyzed", audit.total_functions],
      ["Functions recomputed", audit.scanned_functions], ["Functions reused", audit.reused_functions],
      ["Functions marked unsupported", coverage.unsupported_functions], ["Observed languages", coverage.languages.join(", ")],
      ["Corpus entries", coverage.corpus_entries], ["Reference packages", coverage.reference_packages],
    ])}<p class="unknowns">No-match functions are not proof of safety. File exclusion and whole-file parsing counts are not recorded in this report.</p></section>
    <section class="info-box"><h3>Detector configuration</h3>${facts([
      ["Tool version", report.tool_version], ["Report schema", report.schema], ["Corpus version", report.corpus_version],
      ["Embedding model", config.model], ["Retrieval top K", config.retrieval_top_k], ["Retrieval threshold", config.retrieval_threshold],
      ["Minimum structure score", config.minimum_structure_score], ["Minimum token score", config.minimum_token_score],
      ["Minimum edit-side score", config.minimum_edit_side_score], ["Minimum edit margin", config.minimum_edit_margin],
    ])}</section>
    <section class="info-box"><h3>Incremental scan</h3>${facts([
      ["Root hash", report.root_hash], ["Previous root hash", report.previous_root_hash || "First scan"],
      ["Changed files", report.changed_files.length], ["Deleted files", report.deleted_files.length],
    ])}<p class="unknowns">Patched matches describe the current source. This report does not compare finding lifecycles across scans.</p></section>
    <section class="info-box"><h3>Optional model advice</h3>${facts([
      ["Enabled", run.enabled ? "Yes" : "No"], ["Model", run.model], ["Generated", run.generated], ["Reused", run.reused], ["Unavailable", run.unavailable],
    ])}<p class="unknowns">Model advice does not change detector verdicts or the inclusion of manual reviews in AI and SARIF exports.</p></section></div>`;
  $("#scan-info-dialog").showModal();
}

function init() {
  $("#project-title").textContent = report.project;
  $("#summary-meta").textContent = `${report.scanned_files.length} files · ${report.audit.total_functions} functions · Generated ${new Date(report.generated_at).toLocaleString()}`;
  $("#count-vulnerable").textContent = matches.filter(vulnerable).length;
  $("#count-review").textContent = matches.filter(finding => finding.outcome === "manual_review").length;
  $("#count-patched").textContent = matches.filter(finding => finding.outcome === "patched").length;
  const warnings = [];
  if (report.coverage.corpus_entries === 0) warnings.push("The corpus is empty. This scan cannot establish coverage of known vulnerabilities.");
  if (report.coverage.unsupported_functions) warnings.push(`${report.coverage.unsupported_functions} functions were marked unsupported. Inspect scan details.`);
  if (report.audit.total_functions === 0) warnings.push("No functions were analyzed. Check the selected directory and supported source files.");
  $("#coverage-warning").textContent = warnings.join(" ");
  $("#coverage-warning").hidden = !warnings.length;

  $$(".counter").forEach(button => button.addEventListener("click", () => {
    viewFilter = viewFilter === button.dataset.filter ? "attention" : button.dataset.filter;
    selectedFile = "";
    render();
  }));
  $("#search").addEventListener("input", () => { selectedFile = ""; render(); });
  $("#view-filter").addEventListener("change", event => { viewFilter = event.target.value; selectedFile = ""; render(); });
  $("#show-all-files").addEventListener("change", renderTree);
  $("#clear-filter").addEventListener("click", () => { viewFilter = "attention"; selectedFile = ""; $("#search").value = ""; render(); });
  $("#overview").addEventListener("click", () => { selectedFile = ""; render(); });
  $("#tree").addEventListener("click", event => {
    const button = event.target.closest("[data-path]");
    if (button) { selectedFile = button.dataset.path; render(); }
  });
  $("#content").addEventListener("toggle", event => {
    if (event.target.matches("details.finding")) populateFinding(event.target);
  }, true);
  $("#content").addEventListener("click", event => {
    const button = event.target.closest("[data-compare], [data-info]");
    if (!button) return;
    const index = Number(button.dataset.boundary);
    if (button.dataset.compare) openComparison(button.dataset.compare, index);
    else openFindingInfo(button.dataset.info, index);
  });
  $$("[data-comparison-mode]").forEach(button => button.addEventListener("click", () => { comparisonMode = button.dataset.comparisonMode; renderComparison(); }));
  $("#scan-info").addEventListener("click", openScanInfo);
  $("#theme-toggle").addEventListener("click", () => {
    const dark = document.documentElement.dataset.theme !== "dark";
    document.documentElement.dataset.theme = dark ? "dark" : "light";
    $("#theme-toggle").textContent = dark ? "Light theme" : "Dark theme";
    $("#theme-toggle").setAttribute("aria-pressed", String(dark));
  });
  $$("dialog").forEach(dialog => dialog.addEventListener("click", event => { if (event.target === dialog) dialog.close(); }));
  render();
}

init();
