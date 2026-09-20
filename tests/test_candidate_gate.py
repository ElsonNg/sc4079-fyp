from provtrail.corpus.models.corpus import DiagnosticLine
from provtrail.pipeline.controller.candidate_gate import diagnostic_preservation_gate


def _removed(text: str) -> DiagnosticLine:
    return DiagnosticLine(kind="removed", vulnerable_line=0, text=text)


def _added(text: str) -> DiagnosticLine:
    return DiagnosticLine(kind="added", patched_line=0, text=text)


# The security-relevant vulnerable line: a CRLF-stripping regex and String/replace calls.
DIAGNOSTIC = [_removed(r"return String(value).replace(/[\r\n]+$/, '');")]


def test_passes_when_anchors_survive_renaming():
    candidate = r"function clean(v) { return String(v).replace(/[\r\n]+$/, ''); }"
    result = diagnostic_preservation_gate(candidate, DIAGNOSTIC, side="vulnerable")
    assert result.passed, result.reason
    assert r"/[\r\n]+$/" in result.literal_anchors
    assert "replace" in result.call_anchors


def test_fails_when_security_literal_dropped():
    # A rewrite that weakened the regex (dropped \r) must be rejected.
    candidate = r"function clean(v) { return String(v).replace(/[\n]+$/, ''); }"
    result = diagnostic_preservation_gate(candidate, DIAGNOSTIC, side="vulnerable")
    assert not result.passed
    assert result.reason == "literal_anchor_dropped"
    assert r"/[\r\n]+$/" in result.missing_literals


def test_flags_identical_to_original_as_not_transformed():
    original = r"function clean(v) { return String(v).replace(/[\r\n]+$/, ''); }"
    result = diagnostic_preservation_gate(
        original, DIAGNOSTIC, side="vulnerable", vulnerable_source=original
    )
    assert not result.passed
    assert result.reason == "identical_to_vulnerable"


def test_ungateable_when_no_high_signal_anchor():
    diagnostic = [_removed("result = left + right;")]
    candidate = "function f(a, b) { const s = a + b; return s; }"
    result = diagnostic_preservation_gate(candidate, diagnostic, side="vulnerable")
    assert not result.passed
    assert result.ungateable
    assert result.reason == "ungateable_no_anchor"


def test_parse_error_is_rejected():
    candidate = "function broken( { return"
    result = diagnostic_preservation_gate(candidate, DIAGNOSTIC, side="vulnerable")
    assert not result.passed
    assert result.reason == "candidate_parse_error"
    assert result.parses is False


def test_typescript_candidate_with_type_syntax_is_accepted():
    # A transformed TypeScript function keeps type annotations the JS grammar rejects;
    # the gate must not reject it as a parse error (regression: TS entries were dropped).
    diagnostic = [_removed(r"return String(value).replace(/[\r\n]+$/, '');")]
    candidate = r"function clean(v: string): string { return String(v).replace(/[\r\n]+$/, ''); }"
    result = diagnostic_preservation_gate(candidate, diagnostic, side="vulnerable")
    assert result.passed, result.reason


def test_patched_side_uses_added_lines():
    diagnostic = [
        _removed("noop();"),
        _added(r"if (isSafeProtocol(url)) { return parseUrl(url); }"),
    ]
    candidate = r"function check(u) { if (isSafeProtocol(u)) { return parseUrl(u); } }"
    result = diagnostic_preservation_gate(candidate, diagnostic, side="patched")
    assert result.passed, result.reason
    assert "isSafeProtocol" in result.call_anchors
