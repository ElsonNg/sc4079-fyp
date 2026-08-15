from corpus.controller import extraction
from corpus.controller.extraction import compute_diagnostic_lines, extract_function_pairs_from_commit
from corpus.models.commit import GitHubCommitDetail, GitHubCommitFile

# --- compute_diagnostic_lines: comment/blank-line filtering -----------------------------


def test_comment_only_added_line_is_excluded():
    # The assertOptions case in miniature: a real code change plus two narration-only
    # comment lines added alongside it. Only the code line should count.
    vulnerable = "function f(x) {\n  const v = schema[x];\n  return v;\n}"
    patched = (
        "function f(x) {\n"
        "  // explain why this changed\n"
        "  // second line of explanation\n"
        "  const v = Object.prototype.hasOwnProperty.call(schema, x) ? schema[x] : undefined;\n"
        "  return v;\n"
        "}"
    )
    diagnostics = compute_diagnostic_lines(vulnerable, patched)

    kinds_and_lines = [(d.kind, d.vulnerable_line, d.patched_line, d.text) for d in diagnostics]
    assert ("removed", 1, None, "  const v = schema[x];") in kinds_and_lines
    assert any(
        d.kind == "added" and "hasOwnProperty" in d.text for d in diagnostics
    )
    assert not any("explanation" in d.text or "explain why" in d.text for d in diagnostics)


def test_pure_blank_line_change_is_excluded():
    vulnerable = "function f() {\n  return 1;\n}"
    patched = "function f() {\n\n  return 1;\n}"
    diagnostics = compute_diagnostic_lines(vulnerable, patched)
    assert diagnostics == []


def test_real_code_change_still_captured():
    vulnerable = "function f(x) {\n  return x + 1;\n}"
    patched = "function f(x) {\n  return x + 2;\n}"
    diagnostics = compute_diagnostic_lines(vulnerable, patched)
    assert len(diagnostics) == 2
    assert {(d.kind, d.text) for d in diagnostics} == {
        ("removed", "  return x + 1;"),
        ("added", "  return x + 2;"),
    }


def test_slash_slash_inside_a_string_is_not_mistaken_for_a_comment():
    # Tree-sitter-based detection (reused from normalize_source_with_lines) must not
    # treat the "//" inside this URL string as a comment and wrongly drop the line.
    vulnerable = "function f() {\n  return 'http://a.example.com';\n}"
    patched = "function f() {\n  return 'http://b.example.com';\n}"
    diagnostics = compute_diagnostic_lines(vulnerable, patched)
    assert len(diagnostics) == 2
    assert {(d.kind, d.text) for d in diagnostics} == {
        ("removed", "  return 'http://a.example.com';"),
        ("added", "  return 'http://b.example.com';"),
    }


# --- extract_function_pairs_from_commit: identical-pair skip ----------------------------

PRE_UTILS = """const noop = () => {}

function isBuffer(val) {
  return val !== null;
}
"""

POST_UTILS = """const noop = () => {};

function isBuffer(val) {
  return val !== null && val !== undefined;
}
"""

# Hunk 1 touches only the `noop` declaration's own line (adding a trailing semicolon --
# outside the arrow function node's own span). Hunk 2 touches isBuffer's body with a
# genuine behavior change.
PATCH = (
    "@@ -1,4 +1,4 @@\n"
    "-const noop = () => {}\n"
    "+const noop = () => {};\n"
    " \n"
    " function isBuffer(val) {\n"
    "@@ -3,3 +3,3 @@\n"
    "-  return val !== null;\n"
    "+  return val !== null && val !== undefined;\n"
    " }\n"
)


def _fake_commit_detail() -> GitHubCommitDetail:
    return GitHubCommitDetail(
        sha="deadbeef",
        parent_shas=["parent1"],
        files=[
            GitHubCommitFile(
                filename="lib/utils.js",
                status="modified",
                additions=2,
                deletions=2,
                patch=PATCH,
            )
        ],
    )


def test_identical_extracted_text_is_skipped_and_counted(monkeypatch):
    monkeypatch.setattr(extraction, "fetch_commit", lambda owner, repo, sha, session=None: _fake_commit_detail())

    def fake_fetch_file_content(owner, repo, path, ref, session=None):
        return PRE_UTILS if ref == "parent1" else POST_UTILS

    monkeypatch.setattr(extraction, "fetch_file_content", fake_fetch_file_content)

    pairs, skipped_identical = extract_function_pairs_from_commit("axios", "axios", "deadbeef")

    names = {p.function_name for p in pairs}
    assert "noop" not in names, "noop's extracted text is identical pre/post -- must be dropped, not stored"
    assert "isBuffer" in names, "isBuffer genuinely changed -- must still be extracted"
    assert skipped_identical == 1
    assert len(pairs) == 1
