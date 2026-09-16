import json

from scripts.validate_tier1_releases import (
    _finding_hashes,
    _finding_matches_target,
    _load_checkpoint,
    _release_boundary_exclusion_reason,
    _row_is_tier1_applicable,
    _select_source_files,
)


def test_tier1_matches_the_labeled_file_and_function_only():
    finding = {"path": "src/purify.ts", "name": "DOMPurify.sanitize"}

    assert _finding_matches_target(finding, "src/purify.ts", "DOMPurify.sanitize")
    assert not _finding_matches_target(finding, "src/purify.ts", "_sanitizeElements")
    assert not _finding_matches_target(finding, "src/other.ts", "DOMPurify.sanitize")


def test_tier1_exact_hash_is_authoritative_when_isolated_name_is_missing():
    finding = {
        "path": "src/filters/array.ts",
        "name": None,
        "function_hash": "exact-target-digest",
    }

    assert _finding_matches_target(
        finding, "src/filters/array.ts", "sortBy", "exact-target-digest"
    )
    assert not _finding_matches_target(
        finding, "src/filters/array.ts", "sortBy", "different-digest"
    )


def test_tier1_excludes_a_release_boundary_pair_selected_by_validation():
    base = {
        "ghsa_id": "GHSA-ghcm-xqfw-q4vr",
        "tier1_applicable": True,
        "corpus_entry": {
            "fix_commit_sha": "4e2d512bf5bf6f9de1a8f0a48da78dc4d09ac4f3",
            "file_path": "packages/mermaid/src/mermaidAPI.ts",
            "function_name": "cssImportantStyles",
        },
    }

    boundary = (
        "GHSA-ghcm-xqfw-q4vr",
        "4e2d512bf5bf6f9de1a8f0a48da78dc4d09ac4f3",
        "packages/mermaid/src/mermaidAPI.ts",
        "cssImportantStyles",
    )
    excluded = {boundary}

    assert not _row_is_tier1_applicable({**base, "kind": "vulnerable"}, excluded)
    assert not _row_is_tier1_applicable({**base, "kind": "fixed"}, excluded)


def test_tier1_checkpoint_hashes_include_target_and_legacy_noise_findings():
    scan_record = (
        set(), set(), 2, True,
        [{"function_hash": "vulnerable-hash"}],
        [{"function_hash": "patched-hash"}],
        True,
    )

    assert _finding_hashes(scan_record) == {"vulnerable-hash", "patched-hash"}


def test_tier1_excludes_boundary_when_vulnerable_release_is_already_patched():
    assert _release_boundary_exclusion_reason(
        "vulnerable-hash", "patched-hash", {"patched-hash"}
    ) == "vulnerable_boundary_absent_patched_present"
    assert _release_boundary_exclusion_reason(
        "vulnerable-hash", "patched-hash", {"vulnerable-hash"}
    ) is None


def test_tier1_file_only_target_accepts_any_function_in_that_file():
    finding = {"path": "src/purify.ts", "name": "_sanitizeElements"}

    assert _finding_matches_target(finding, "src/purify.ts", None)


def test_tier1_function_cap_is_per_package_and_keeps_target_file():
    sources = {
        "src/target.js": "function target() { return 1; }\n",
        "src/a.js": "function a() { return 1; }\n",
        "src/b.js": "function b() { return 1; }\nfunction c() { return 2; }\n",
    }
    selected, count, capped = _select_source_files(sources, "src/target.js", 2)
    assert "src/target.js" in selected
    assert count == 2
    assert capped is True


def test_tier1_function_cap_zero_means_unlimited():
    sources = {"src/target.js": "function target() { return 1; }\n", "src/a.js": "function a() { return 1; }\n"}
    selected, count, capped = _select_source_files(sources, "src/target.js", None)
    assert set(selected) == set(sources)
    assert count == 2
    assert capped is False


def test_legacy_checkpoint_without_background_byte_cap_remains_resumable(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps({
        "config": {
            "labels_sha256": "labels",
            "corpus_version": "corpus",
            "max_functions": 50,
            "result_cache_schema": 10,
        },
        "completed": {"target": {"flagged": []}},
    }), encoding="utf-8")

    completed = _load_checkpoint(checkpoint, {
        "labels_sha256": "labels",
        "corpus_version": "corpus",
        "max_functions": 50,
        "max_background_source_bytes": 1_000_000,
        "result_cache_schema": 10,
    })

    assert completed == {"target": {"flagged": []}}


def test_checkpoint_survives_label_manifest_regeneration(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps({
        "config": {
            "labels_sha256": "old-labels",
            "corpus_version": "corpus",
            "max_functions": 50,
            "max_background_source_bytes": 1_000_000,
            "result_cache_schema": 10,
        },
        "completed": {"content-addressed-target": {"flagged": []}},
    }), encoding="utf-8")

    completed = _load_checkpoint(checkpoint, {
        "labels_sha256": "new-labels",
        "corpus_version": "corpus",
        "max_functions": 50,
        "max_background_source_bytes": 1_000_000,
        "result_cache_schema": 10,
    })

    assert "content-addressed-target" in completed


def test_checkpoint_rejects_changed_background_download_cap(tmp_path):
    checkpoint = tmp_path / "checkpoint.json"
    checkpoint.write_text(json.dumps({
        "config": {
            "labels_sha256": "labels",
            "corpus_version": "corpus",
            "max_functions": 50,
            "max_background_source_bytes": 1_000_000,
            "result_cache_schema": 10,
        },
        "completed": {"target": {"flagged": []}},
    }), encoding="utf-8")

    completed = _load_checkpoint(checkpoint, {
        "labels_sha256": "labels",
        "corpus_version": "corpus",
        "max_functions": 50,
        "max_background_source_bytes": None,
        "result_cache_schema": 10,
    })

    assert completed == {}
