import json

import pytest

from corpus.controller.deduplication import deduplicate_entries, fingerprint_entry
from corpus.controller.extraction import is_production_js_file
from corpus.controller.release import ReleaseEvidenceError, validate_osv_agreement, version_satisfies_range
from corpus.controller.snapshot import promote_snapshot
from corpus.controller.store import load_entries
from corpus.models.corpus import BuildResult, CorpusEntry
from corpus.models.github import GitHubVulnerability
from corpus.models.osv import OSVAffected, OSVEvent, OSVPackage, OSVRange, OSVVulnerability
from pipeline.controller.scanning import JS_EXTENSIONS
from pipeline.controller.parsing import extract_function_units, type_erase_source
from pipeline.controller.hashing import build_hash_index, lookup


def _osv(package="widget", aliases=None):
    return OSVVulnerability(
        id="CVE-2026-1",
        aliases=aliases or ["GHSA-demo"],
        affected=[OSVAffected(
            package=OSVPackage(name=package, ecosystem="npm"),
            versions=["1.0.0", "1.1.0"],
            ranges=[OSVRange(type="SEMVER", events=[OSVEvent(introduced="0", fixed="1.2.0")])],
        )],
    )


def test_osv_agreement_requires_alias_package_and_compatible_ranges():
    github = GitHubVulnerability(
        package_ecosystem="npm", package_name="widget",
        vulnerable_version_range=">= 1.0.0, < 1.2.0", first_patched_version="1.2.0",
    )
    affected, fixed = validate_osv_agreement("GHSA-demo", "widget", github, _osv())
    assert affected[-1] == "1.1.0"
    assert fixed[0] == "1.2.0"
    with pytest.raises(ReleaseEvidenceError, match="osv_package_mismatch"):
        validate_osv_agreement("GHSA-demo", "other", github, _osv())


@pytest.mark.parametrize("version, expected", [("1.1.9", True), ("1.2.0", False)])
def test_npm_range_compatibility(version, expected):
    assert version_satisfies_range(version, ">=1.0.0 <1.2.0") is expected


def test_all_js_ts_extensions_and_nonproduction_exclusions():
    assert {".ts", ".tsx", ".mts", ".cts"}.issubset(JS_EXTENSIONS)
    assert is_production_js_file("src/index.ts")
    assert not is_production_js_file("types/index.d.ts")
    assert not is_production_js_file("examples/demo.tsx")
    assert not is_production_js_file("dist/app.min.js")


def test_typescript_keeps_native_source_and_builds_runtime_representation():
    source = "export function greet<T>(user: User): string { return user.name as string; }"
    unit = extract_function_units(source, filename="src/greet.ts")[0]
    assert unit.language == "typescript"
    assert "user: User" in unit.source
    runtime = type_erase_source(unit.source, filename="src/greet.ts")
    assert runtime == "function greet(user) { return user.name; }"


def test_type_erased_cross_language_match_cannot_be_exact():
    native = "function greet(user: User): string { const value: string = user.name; return value.toUpperCase(); }"
    runtime = type_erase_source(native, filename="greet.ts")
    entry = CorpusEntry(
        ghsa_id="GHSA-ts", package_name="widget", ecosystem="npm", repo="acme/widget",
        fix_commit_sha="abc", file_path="greet.ts", source_language="typescript",
        vulnerable_function=native, patched_function=native.replace("toUpperCase", "trim"),
        vulnerable_runtime=runtime, patched_runtime=runtime.replace("toUpperCase", "trim"),
    )
    index = build_hash_index([entry])
    assert any(match.match_type == "type_erased" for match in lookup(runtime, index, filename="greet.js"))
    assert any(match.match_type == "exact" for match in lookup(native, index, filename="greet.ts"))


def _entry(boundary):
    return CorpusEntry(
        ghsa_id="GHSA-demo", cve_id="CVE-2026-1", package_name="widget",
        ecosystem="npm", repo="acme/widget", fix_commit_sha="abc", file_path="src/a.js",
        function_name="run", vulnerable_function="function run(){ return unsafe(value); }",
        patched_function="function run(){ return safe(value); }", release_boundary=boundary,
    )


def test_dedup_preserves_distinct_fix_boundaries():
    first = _entry({"last_affected": "1.0.0", "first_fixed": "1.1.0"})
    duplicate = first.model_copy(update={"ghsa_id": "GHSA-alias"})
    distinct = first.model_copy(update={"release_boundary": {"last_affected": "2.0.0", "first_fixed": "2.1.0"}})
    entries, removed = deduplicate_entries([first, duplicate, distinct])
    assert len(entries) == 2
    assert removed == 1
    assert {alias["ghsa_id"] for alias in entries[0].advisory_aliases} == {"GHSA-demo", "GHSA-alias"}


def test_snapshot_is_integrity_checked_and_versioned(tmp_path):
    entry = fingerprint_entry(_entry({"last_affected": "1.0.0", "first_fixed": "1.1.0"}))
    snapshot = promote_snapshot(BuildResult(entries=[entry], source_manifest={"policy": "test"}), tmp_path)
    assert len(load_entries(snapshot / "corpus.db")) == 1
    assert (snapshot / "quarantine.json").exists()
    pointer = json.loads((tmp_path / "current.json").read_text(encoding="utf-8"))
    assert pointer["snapshot_id"] == snapshot.name


def test_snapshot_promotes_same_commit_entries_with_distinct_boundaries(tmp_path):
    """Regression: a fix commit referenced by several version-range advisories (e.g. tar's
    3.x/4.x/5.x/6.x backports) produces entries that share ghsa_id/fix_commit_sha/file_path/
    function_name and differ only by release_boundary. These must not collapse to one DB row.
    """
    first = fingerprint_entry(_entry({"last_affected": "1.0.0", "first_fixed": "1.1.0"}))
    second = fingerprint_entry(_entry({"last_affected": "2.0.0", "first_fixed": "2.1.0"}))
    snapshot = promote_snapshot(BuildResult(entries=[first, second], source_manifest={"policy": "test"}), tmp_path)
    assert len(load_entries(snapshot / "corpus.db")) == 2
