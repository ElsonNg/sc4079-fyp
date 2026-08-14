import requests

from corpus.controller.extraction import (
    CleanlinessRejection,
    compute_diagnostic_lines,
    extract_commit_refs,
    extract_function_pairs_from_commit,
)
from corpus.controller.github import fetch_advisories
from corpus.controller.osv import fetch_osv_by_commits, fetch_osv_vuln
from corpus.models.commit import ExtractedFunctionPair
from corpus.models.corpus import AttritionReport, CorpusEntry
from corpus.models.osv import OSVVulnerability

BOOTSTRAP_ENTRIES = [
    # (ghsa_id, owner, repo, sha) - already-verified, known-good entries used to validate
    # the extraction mechanics end-to-end before trusting the automated pull on the rest.
    ("GHSA-7q8q-rj6j-mhjq", "axios", "axios", "1417285c69344bbcc6420a021f67dee0c6fedb2d"),
    (
        "GHSA-rv95-896h-c2vc",
        "expressjs",
        "express",
        "0867302ddbde0e9463d0564fea5861feb708c2dd",
    ),
]


def bootstrap_validate(session: requests.Session | None = None) -> None:
    """Runs fetch diff -> extract function pair on the two known-good GHSA entries and
    prints the results for manual eyeballing, per the build plan's bootstrap step."""
    for ghsa_id, owner, repo, sha in BOOTSTRAP_ENTRIES:
        print(f"\n=== {ghsa_id} ({owner}/{repo}@{sha[:12]}) ===")
        try:
            pairs = extract_function_pairs_from_commit(owner, repo, sha, session=session)
        except CleanlinessRejection as e:
            print(f"  REJECTED by cleanliness filter: {e.reason}")
            continue
        print(f"  {len(pairs)} function pair(s) extracted")
        for pair in pairs:
            print(f"  --- {pair.file_path} :: {pair.function_name or '<anonymous>'}")
            print(f"      vulnerable ({len(pair.vulnerable_function.splitlines())} lines) / "
                  f"patched ({len(pair.patched_function.splitlines())} lines)")


def _versions_from_osv(
    osv_vuln: OSVVulnerability, package_name: str, ecosystem: str
) -> tuple[list[str], list[str]]:
    affected_versions: list[str] = []
    fixed_versions: list[str] = []
    for affected in osv_vuln.affected:
        if affected.package is None:
            continue
        if affected.package.name != package_name or affected.package.ecosystem != ecosystem:
            continue
        for r in affected.ranges:
            for event in r.events:
                if event.introduced is not None:
                    affected_versions.append(event.introduced)
                if event.fixed is not None:
                    fixed_versions.append(event.fixed)
        affected_versions.extend(affected.versions)
    return affected_versions, fixed_versions


def _entry_from_pair(
    pair: ExtractedFunctionPair,
    *,
    ghsa_id: str,
    cve_id: str | None,
    osv_id: str | None,
    cwes,
    severity: str,
    package: str,
    ecosystem: str,
    repo: str,
    sha: str,
    affected_versions: list[str],
    fixed_versions: list[str],
    confirmed: bool,
) -> CorpusEntry:
    return CorpusEntry(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        osv_id=osv_id,
        cwes=cwes,
        severity=severity,
        package_name=package,
        ecosystem=ecosystem,
        repo=repo,
        fix_commit_sha=sha,
        file_path=pair.file_path,
        function_name=pair.function_name,
        vulnerable_function=pair.vulnerable_function,
        patched_function=pair.patched_function,
        diagnostic_lines=compute_diagnostic_lines(
            pair.vulnerable_function, pair.patched_function
        ),
        affected_versions=affected_versions,
        fixed_versions=fixed_versions,
        osv_confirmed=confirmed,
    )


def _build_for_package(
    package: str, ecosystem: str, session: requests.Session | None
) -> tuple[list[CorpusEntry], AttritionReport]:
    report = AttritionReport(package=package)
    entries: list[CorpusEntry] = []

    advisories = fetch_advisories(ecosystem=ecosystem, affects=package, session=session)
    report.advisories_found = len(advisories)

    advisories = [
        a
        for a in advisories
        if any(
            v.package_name == package and v.package_ecosystem == ecosystem
            for v in a.vulnerabilities
        )
    ]
    report.advisories_wrong_package = report.advisories_found - len(advisories)

    for advisory in advisories:
        if advisory.withdrawn_at:
            report.advisories_withdrawn += 1
            continue
        report.advisories_processed += 1

        commit_refs = extract_commit_refs(advisory.references)
        report.fix_commit_refs_found += len(commit_refs)
        if not commit_refs:
            report.advisories_without_commit_refs += 1
            continue

        try:
            osv_vuln = fetch_osv_vuln(advisory.ghsa_id, session=session)
        except requests.HTTPError:
            osv_vuln = None

        identifiers_to_match = {advisory.ghsa_id}
        if advisory.cve_id:
            identifiers_to_match.add(advisory.cve_id)
        affected_versions, fixed_versions = [], []
        if osv_vuln is not None:
            identifiers_to_match.add(osv_vuln.id)
            identifiers_to_match.update(osv_vuln.aliases)
            affected_versions, fixed_versions = _versions_from_osv(osv_vuln, package, ecosystem)

        cve_id = advisory.cve_id or next(
            (alias for alias in (osv_vuln.aliases if osv_vuln else []) if alias.startswith("CVE-")),
            None,
        )

        shas = [sha for _, _, sha in commit_refs]
        batch = fetch_osv_by_commits(shas, session=session)
        confirmed_by_sha = {
            sha: any(v.id in identifiers_to_match for v in result.vulns)
            for sha, result in zip(shas, batch)
        }

        for owner, repo, sha in commit_refs:
            try:
                pairs = extract_function_pairs_from_commit(owner, repo, sha, session=session)
            except CleanlinessRejection as e:
                report.fix_commits_rejected_unclean += 1
                report.rejection_reasons[e.reason] = report.rejection_reasons.get(e.reason, 0) + 1
                continue

            report.fix_commits_processed += 1
            confirmed = confirmed_by_sha.get(sha, False)
            if confirmed:
                report.osv_confirmed_count += 1
            else:
                report.osv_unconfirmed_count += 1

            for pair in pairs:
                entries.append(
                    _entry_from_pair(
                        pair,
                        ghsa_id=advisory.ghsa_id,
                        cve_id=cve_id,
                        osv_id=osv_vuln.id if osv_vuln else None,
                        cwes=advisory.cwes,
                        severity=advisory.severity,
                        package=package,
                        ecosystem=ecosystem,
                        repo=f"{owner}/{repo}",
                        sha=sha,
                        affected_versions=affected_versions,
                        fixed_versions=fixed_versions,
                        confirmed=confirmed,
                    )
                )
                report.function_pairs_extracted += 1

    report.corpus_entries_final = len(entries)
    return entries, report


def build_corpus(
    packages: tuple[str, ...] = ("axios", "express"),
    ecosystem: str = "npm",
    session: requests.Session | None = None,
) -> tuple[list[CorpusEntry], list[AttritionReport]]:
    all_entries: list[CorpusEntry] = []
    reports: list[AttritionReport] = []
    for package in packages:
        entries, report = _build_for_package(package, ecosystem, session)
        all_entries.extend(entries)
        reports.append(report)
    return all_entries, reports


def print_attrition_report(report: AttritionReport) -> None:
    print(f"\n=== Attrition report: {report.package} ===")
    print(f"  advisories found:              {report.advisories_found}")
    print(f"  advisories wrong-package:      {report.advisories_wrong_package}")
    print(f"  advisories withdrawn:          {report.advisories_withdrawn}")
    print(f"  advisories processed:          {report.advisories_processed}")
    print(f"  fix-commit refs found:         {report.fix_commit_refs_found}")
    print(f"  advisories w/o commit refs:    {report.advisories_without_commit_refs}")
    print(f"  fix commits rejected (unclean):{report.fix_commits_rejected_unclean}")
    for reason, count in report.rejection_reasons.items():
        print(f"    - {reason}: {count}")
    print(f"  fix commits processed:         {report.fix_commits_processed}")
    print(f"  osv-confirmed commits:         {report.osv_confirmed_count}")
    print(f"  osv-unconfirmed commits:       {report.osv_unconfirmed_count}")
    print(f"  function pairs extracted:      {report.function_pairs_extracted}")
    print(f"  final corpus entries:          {report.corpus_entries_final}")
