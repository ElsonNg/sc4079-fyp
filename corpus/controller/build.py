"""Coverage-first construction of the npm JavaScript/TypeScript corpus."""

from __future__ import annotations

from datetime import datetime, timezone

import requests

from corpus.controller.deduplication import deduplicate_entries, fingerprint_entry
from corpus.controller.extraction import CleanlinessRejection, compute_diagnostic_lines, extract_commit_refs, extract_function_pairs_from_commit
from corpus.controller.github import fetch_advisories
from corpus.controller.osv import fetch_osv_vuln
from corpus.controller.release import ReleaseEvidenceError, assess_high_impact, resolve_release_boundary, validate_osv_agreement
from corpus.models.commit import ExtractedFunctionPair
from corpus.models.corpus import AttritionReport, BuildResult, CorpusEntry, QuarantineRecord

POLICY_VERSION = "npm-js-ts-evidence-v1"
BOOTSTRAP_ENTRIES = [
    ("GHSA-7q8q-rj6j-mhjq", "axios", "axios", "1417285c69344bbcc6420a021f67dee0c6fedb2d"),
    ("GHSA-rv95-896h-c2vc", "expressjs", "express", "0867302ddbde0e9463d0564fea5861feb708c2dd"),
]


def bootstrap_validate(session: requests.Session | None = None) -> None:
    for ghsa_id, owner, repo, sha in BOOTSTRAP_ENTRIES:
        print(f"\n=== {ghsa_id} ({owner}/{repo}@{sha[:12]}) ===")
        try:
            pairs, skipped = extract_function_pairs_from_commit(owner, repo, sha, session=session)
        except CleanlinessRejection as exc:
            print(f"  REJECTED by evidence filter: {exc.reason}")
            continue
        print(f"  {len(pairs)} function pair(s) extracted ({skipped} identical skipped)")


def _entry_from_pair(pair: ExtractedFunctionPair, **evidence) -> CorpusEntry:
    entry = CorpusEntry(
        **evidence,
        file_path=pair.file_path,
        function_name=pair.function_name,
        vulnerable_function=pair.vulnerable_function,
        patched_function=pair.patched_function,
        diagnostic_lines=compute_diagnostic_lines(pair.vulnerable_function, pair.patched_function, language=pair.source_language),
        source_language=pair.source_language,
        vulnerable_runtime=pair.vulnerable_runtime,
        patched_runtime=pair.patched_runtime,
        patch_hunk=pair.patch_hunk,
        primary_evidence=pair.is_primary,
    )
    return fingerprint_entry(entry)


def _quarantine(result: BuildResult, report: AttritionReport, reason: str, *, ghsa_id: str, package_name: str = "", repo: str = "", sha: str = "", detail: str = "") -> None:
    result.quarantine.append(QuarantineRecord(reason_code=reason, ghsa_id=ghsa_id, package_name=package_name, repo=repo, fix_commit_sha=sha, detail=detail))
    report.quarantined += 1
    report.rejection_reasons[reason] = report.rejection_reasons.get(reason, 0) + 1


def build_corpus_result(packages: tuple[str, ...] | None = None, ecosystem: str = "npm", session: requests.Session | None = None) -> BuildResult:
    """Discover all reviewed npm advisories; ``packages`` only restricts diagnostics."""
    result = BuildResult(source_manifest={
        "policy_version": POLICY_VERSION,
        "ecosystem": "npm JavaScript/TypeScript",
        "github_advisory_type": "reviewed",
        "github_advisory_endpoint": "https://api.github.com/advisories",
        "osv_endpoint": "https://api.osv.dev/v1/vulns/{GHSA}",
        "npm_registry": "https://registry.npmjs.org",
        "withdrawn_excluded": True,
        "severity_gate": False,
        "package_restriction": sorted(packages) if packages else None,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    })
    report = AttritionReport(package=", ".join(sorted(packages)) if packages else "all npm packages")
    result.reports.append(report)
    advisories = fetch_advisories(ecosystem=ecosystem, session=session)
    report.advisories_found = len(advisories)
    restriction = set(packages or ())

    for advisory in sorted(advisories, key=lambda item: item.ghsa_id):
        if advisory.withdrawn_at:
            report.advisories_withdrawn += 1
            continue
        npm_vulnerabilities = [v for v in advisory.vulnerabilities if v.package_ecosystem.lower() == ecosystem.lower() and (not restriction or v.package_name in restriction)]
        if not npm_vulnerabilities:
            report.advisories_wrong_package += 1
            continue
        report.advisories_processed += 1
        try:
            osv = fetch_osv_vuln(advisory.ghsa_id, session=session)
        except (requests.RequestException, ValueError) as exc:
            for vulnerability in npm_vulnerabilities:
                _quarantine(result, report, "osv_missing", ghsa_id=advisory.ghsa_id, package_name=vulnerability.package_name, detail=str(exc))
            continue

        commit_refs = sorted(set(extract_commit_refs(advisory.references)))
        report.fix_commit_refs_found += len(commit_refs)
        if not commit_refs:
            report.advisories_without_commit_refs += 1
            for vulnerability in npm_vulnerabilities:
                _quarantine(result, report, "fix_commit_missing", ghsa_id=advisory.ghsa_id, package_name=vulnerability.package_name)
            continue

        for vulnerability in sorted(npm_vulnerabilities, key=lambda item: item.package_name):
            package = vulnerability.package_name
            try:
                affected_versions, fixed_versions = validate_osv_agreement(advisory.ghsa_id, package, vulnerability, osv)
            except ReleaseEvidenceError as exc:
                _quarantine(result, report, exc.reason_code, ghsa_id=advisory.ghsa_id, package_name=package, detail=exc.detail)
                continue

            for owner, repo_name, sha in commit_refs:
                repo = f"{owner}/{repo_name}"
                try:
                    boundary = resolve_release_boundary(package, affected_versions, fixed_versions, sha, repo, session=session)
                    pairs, skipped = extract_function_pairs_from_commit(owner, repo_name, sha, session=session)
                except ReleaseEvidenceError as exc:
                    _quarantine(result, report, exc.reason_code, ghsa_id=advisory.ghsa_id, package_name=package, repo=repo, sha=sha, detail=exc.detail)
                    continue
                except CleanlinessRejection as exc:
                    report.fix_commits_rejected_unclean += 1
                    _quarantine(result, report, exc.reason, ghsa_id=advisory.ghsa_id, package_name=package, repo=repo, sha=sha)
                    continue
                report.fix_commits_processed += 1
                report.osv_confirmed_count += 1
                report.function_pairs_skipped_identical += skipped
                high_impact, impact = assess_high_impact(repo, package, session=session)
                for pair in pairs:
                    result.entries.append(_entry_from_pair(
                        pair,
                        ghsa_id=advisory.ghsa_id,
                        cve_id=advisory.cve_id or next((alias for alias in osv.aliases if alias.startswith("CVE-")), None),
                        osv_id=osv.id, advisory_title=advisory.summary,
                        advisory_description=advisory.description, advisory_url=advisory.html_url,
                        advisory_references=advisory.references, cwes=advisory.cwes,
                        severity=advisory.severity, package_name=package, ecosystem=ecosystem,
                        repo=repo, fix_commit_sha=sha, affected_versions=affected_versions,
                        fixed_versions=fixed_versions, osv_confirmed=True, release_boundary=boundary,
                        high_impact=high_impact, impact_metadata=impact,
                    ))
                    report.function_pairs_extracted += 1

    result.entries, removed = deduplicate_entries(result.entries)
    report.duplicates_removed = removed
    report.corpus_entries_final = len(result.entries)
    report.high_impact_entries = sum(entry.high_impact for entry in result.entries)
    return result


def build_corpus(packages: tuple[str, ...] | None = None, ecosystem: str = "npm", session: requests.Session | None = None) -> tuple[list[CorpusEntry], list[AttritionReport]]:
    result = build_corpus_result(packages=packages, ecosystem=ecosystem, session=session)
    return result.entries, result.reports


def print_attrition_report(report: AttritionReport) -> None:
    print(f"\n=== Attrition report: {report.package} ===")
    labels = (
        ("advisories found", report.advisories_found), ("advisories withdrawn", report.advisories_withdrawn),
        ("advisories processed", report.advisories_processed), ("fix-commit refs found", report.fix_commit_refs_found),
        ("fix commits processed", report.fix_commits_processed), ("quarantined", report.quarantined),
        ("duplicates removed", report.duplicates_removed), ("final corpus entries", report.corpus_entries_final),
        ("high-impact entries", report.high_impact_entries),
    )
    for label, value in labels:
        print(f"  {label + ':':32}{value}")
    for reason, count in sorted(report.rejection_reasons.items()):
        print(f"    - {reason}: {count}")
