from scripts.validate_tier1_releases import _finding_matches_target


def test_tier1_matches_the_labeled_file_and_function_only():
    finding = {"path": "src/purify.ts", "name": "DOMPurify.sanitize"}

    assert _finding_matches_target(finding, "src/purify.ts", "DOMPurify.sanitize")
    assert not _finding_matches_target(finding, "src/purify.ts", "_sanitizeElements")
    assert not _finding_matches_target(finding, "src/other.ts", "DOMPurify.sanitize")


def test_tier1_file_only_target_accepts_any_function_in_that_file():
    finding = {"path": "src/purify.ts", "name": "_sanitizeElements"}

    assert _finding_matches_target(finding, "src/purify.ts", None)
