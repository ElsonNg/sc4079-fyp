"""Regression tests for candidate-language resolution in region detection.

A scan passes candidate ids like ``src/a.ts::10:20`` whose ``::span`` suffix hides
the file extension. Before the fix these were read as JavaScript, so TypeScript
functions with type syntax failed to parse and abstained instead of flagging.
"""

from pipeline.controller.region_detection import resolve_candidate_language


def test_scan_style_id_keeps_typescript():
    assert resolve_candidate_language("src/app.ts::10:20", None) == "typescript"
    assert resolve_candidate_language("pkg/lib/x.tsx::0:99", None) == "tsx"
    assert resolve_candidate_language("src/app.js::10:20", None) == "javascript"


def test_plain_ids_still_work():
    assert resolve_candidate_language("L001.ts", None) == "typescript"
    assert resolve_candidate_language("C01", None) == "javascript"
    assert resolve_candidate_language(None, None) == "javascript"


def test_explicit_language_wins():
    # Even when the id looks like JavaScript, an explicit language is honoured.
    assert resolve_candidate_language("thing::1:2", "typescript") == "typescript"
    assert resolve_candidate_language("a.ts::1:2", "javascript") == "javascript"
