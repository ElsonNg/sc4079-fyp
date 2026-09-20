from provtrail.pipeline.controller.parsing import normalize_source, normalize_source_with_lines

# Raw 0-indexed lines: 0 function header, 1 `let a = 1;`, 2-6 a multi-line block comment,
# 7 `let b = 2;`, 8 `return a + b;`, 9 closing brace. Lines 2-6 are dropped entirely once
# the comment is stripped -- this is the regression case for the newline-preservation fix.
WITH_MULTILINE_COMMENT = """function example() {
    let a = 1;
    /*
     * multi
     * line
     * comment
     */
    let b = 2;
    return a + b;
}"""

NO_COMMENTS = """function example() {
    let a = 1;
    let b = 2;
    return a + b;
}"""


def test_normalize_source_with_lines_preserves_positions_across_multiline_comment():
    result = normalize_source_with_lines(WITH_MULTILINE_COMMENT)
    raw_line_numbers = [line_no for line_no, _ in result]
    texts = [text for _, text in result]

    assert raw_line_numbers == [0, 1, 7, 8, 9]
    assert texts == [
        "function example() {",
        "let a = 1;",
        "let b = 2;",
        "return a + b;",
        "}",
    ]


def test_normalize_source_with_lines_matches_normalize_source_when_no_comments():
    with_lines = [text for _, text in normalize_source_with_lines(NO_COMMENTS)]
    assert with_lines == normalize_source(NO_COMMENTS)
