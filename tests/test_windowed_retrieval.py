from corpus.controller.extraction import compute_diagnostic_lines
from corpus.models.corpus import CorpusEntry
from pipeline.controller.retrieval import WINDOW_CHARS, _corpus_windows, _query_windows


def _entry(vulnerable: str, patched: str) -> CorpusEntry:
    return CorpusEntry(
        ghsa_id="KLABAN-test",
        package_name="demo",
        ecosystem="npm",
        repo="acme/demo",
        fix_commit_sha="deadbeef",
        file_path="index.js",
        function_name="demo",
        vulnerable_function=vulnerable,
        patched_function=patched,
        diagnostic_lines=compute_diagnostic_lines(vulnerable, patched),
    )


def test_corpus_windows_include_security_change_deep_in_function():
    vulnerable = "function demo() {\n" + "safe();\n" * 200 + "dangerous(userInput);\n}"
    patched = vulnerable.replace("dangerous(userInput);", "escape(userInput);")

    windows = _corpus_windows(_entry(vulnerable, patched))

    assert 1 < len(windows) <= 8
    assert any("dangerous(userInput)" in window for window in windows)
    assert all(len(window) <= WINDOW_CHARS for window in windows)


def test_query_windows_are_bounded_and_cover_both_ends():
    source = "A" * 5000 + "THE_END"
    windows = _query_windows(source)

    assert len(windows) <= 32
    assert windows[0].startswith("A")
    assert windows[-1].endswith("THE_END")
