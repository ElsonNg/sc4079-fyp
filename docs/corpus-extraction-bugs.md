# Corpus extraction bugs found via Stage 7 validation

**Status:** Fixed in code and applied — the corpus has been rebuilt
(`scripts/rebuild_corpus.py`) and both fixes confirmed against the live data (see
"Post-rebuild results" below).

**How found:** running Stage 7's `verify_candidate()` self-anchor check — a candidate
identical to a corpus entry's `vulnerable_function` must resolve `flagged` — against a
random 15-entry sample of the real 140-entry corpus. 8/15 didn't self-anchor.
Investigating each failure individually surfaced both bugs below; neither is a defect
in Stage 7 itself, both are upstream, in module 1's extraction pipeline
(`corpus/controller/extraction.py`).

---

## Bug 1: touched-but-unchanged function pairs

**Symptom:** several corpus entries had `vulnerable_function == patched_function`
byte-for-byte — a "before" and "after" that are the same text, saved as if they were a
real vulnerable/patched pair.

**Root cause:** "was this function touched by the fix commit?" was decided at *line*
granularity (`_touched_units` in `extraction.py`: does an actual `+`/`-` diff line fall
within the function's line range?), while the text actually stored is extracted at
*AST-node* granularity (`get_node_text()` on the function's own tree-sitter node,
`pipeline/controller/parsing.py`). These two units disagree whenever a diff line
changes something *around* a function but not *inside* its own node span — the
function gets flagged "touched" and paired up by `_match_function_units`, but the two
extracted byte-ranges come out identical.

**Real example** (`axios/axios@28c7215`, advisory `GHSA-43fc-jf86-j433` — a
prettier/lint reformat, 356 lines changed in `lib/utils.js`, not a security fix):

```diff
-const noop = () => {}
+const noop = () => {};
```

Only a trailing semicolon was added. Unified diff can't express "add one character" —
it deletes and re-adds the whole line — so the line-based check correctly sees "this
line changed" and resolves it to the `noop` arrow function. But the semicolon sits
*outside* the arrow-function node's own byte span, so `get_node_text()` returns
`() => {}` unchanged on both sides. Corpus entry saved: vulnerable = `() => {}`,
patched = `() => {}`. Same function, `replacer` (nested inside `toCamelCase`), hit the
same bug via a different route — its own signature line got reflowed as part of a
method-chain reformat, without changing the signature or body text itself.

**Impact measured:** 4 of the 8 non-self-anchoring entries in the 15-entry sample
(`noop`, `replacer`, and two anonymous units, all under `GHSA-43fc-jf86-j433`). Stage 7
handled these correctly given the input — identical text is genuinely
indistinguishable, so `manual_review` at score `0.000` was the honest answer — but the
corpus entries themselves carry no signal and shouldn't exist.

**Fix:** `extract_function_pairs_from_commit` (`corpus/controller/extraction.py`) now
checks `pre_unit.source == post_unit.source` before accepting a matched pair, and
returns `(pairs, skipped_identical_count)` instead of just `pairs`. The count is
threaded into `AttritionReport.function_pairs_skipped_identical`
(`corpus/models/corpus.py`, `corpus/controller/build.py`) so these drops are reported,
not silent, per the build plan's attrition-reporting requirement.

**Tests:** `tests/test_extraction.py::test_identical_extracted_text_is_skipped_and_counted`
reproduces the exact `noop` scenario (mocked GitHub API responses, no live network)
alongside a genuinely-changed sibling function in the same commit, confirming the
former is dropped+counted and the latter still comes through.

---

## Bug 2: comment and blank lines diluting the diagnostic-line average

**Symptom:** a genuine, meaningful security fix scored close to zero (`manual_review`
via Stage 7's margin) even though the actual code change looked clearly deliberate.

**Root cause:** `compute_diagnostic_lines` (`extraction.py`) is a plain `difflib` line
diff over `vulnerable_function.splitlines()` / `patched_function.splitlines()`, with no
awareness of what kind of line changed. A comment added purely to explain a fix counts
as a diagnostic line exactly like the code line it's explaining. Stage 7's
`_sim_at_diagnostic` (`pipeline/controller/verification.py`) averages its score across
every diagnostic line on a side — so N narration-only comment lines added alongside 1
real code line dilute that one code line's signal to `1/(N+1)` of the total.

**Real example** (`axios/axios`, advisory `GHSA-q8qp-cvcw-x6jj`, `assertOptions` — a
genuine prototype-pollution fix):

```diff
     const opt = keys[i];
-    const validator = schema[opt];
+    // Use hasOwnProperty so a polluted Object.prototype.<opt> cannot supply
+    // a non-function validator and cause a TypeError. See GHSA-q8qp-cvcw-x6jj.
+    const validator = Object.prototype.hasOwnProperty.call(schema, opt) ? schema[opt] : undefined;
```

Before the fix: 3 "added" diagnostic lines (2 comments + 1 code). The one line that
actually matters was getting 1/3 of the averaging weight it deserved.

**Fix:** `compute_diagnostic_lines` now filters both sides through
`normalize_source_with_lines` (`pipeline/controller/parsing.py`) before accepting a
line as diagnostic — the same tree-sitter-based comment detection already used
elsewhere in the pipeline (immune to a `//`-looking substring inside a string, regex,
or template literal, unlike a text-prefix heuristic), plus its existing blank-line
drop.

**Tests:** `tests/test_extraction.py` —
`test_comment_only_added_line_is_excluded` (the `assertOptions` shape in miniature),
`test_pure_blank_line_change_is_excluded`, `test_real_code_change_still_captured`
(regression guard against over-filtering), and
`test_slash_slash_inside_a_string_is_not_mistaken_for_a_comment` (guards the specific
false-positive a naive `//`-prefix check would have introduced).

---

## Post-rebuild results

The corpus was rebuilt with `PYTHONPATH=. .venv/bin/python scripts/rebuild_corpus.py`
(live GitHub Advisory API + OSV.dev, axios + express). `rebuild_corpus.py` clears
`corpus_entries` before saving — `save_entries()` only upserts by
`(ghsa_id, fix_commit_sha, file_path, function_name)`, so without an explicit clear the
rows this fix removes would otherwise sit in the table forever as stale leftovers from
the old buggy build.

Corpus size dropped 140 → 131 (the 9 rows Bug 1 was producing). Confirmed directly
against the live DB:

- `SELECT COUNT(*) FROM corpus_entries WHERE vulnerable_function = patched_function` →
  **0** (was 9).
- `assertOptions` (`GHSA-q8qp-cvcw-x6jj`) now has exactly 2 diagnostic lines (1 removed
  code line, 1 added code line) — the 2 narration-only comment lines from Bug 2 are
  gone.

Re-running the same self-anchor check that originally surfaced these bugs — now as a
proper script, `scripts/validate_e2e.py` (fixed seed, so this is a real before/after,
not a fresh random draw) — the self-anchor pass rate improved:

| | Before | After |
|---|---|---|
| Corpus size | 140 | 131 |
| Self-anchor pass rate (15-entry sample) | 7/15 | 10/15 |
| Comment/blank diagnostic lines in sample | 9 | 0 |
| Identical vulnerable==patched pairs in sample | 4 | 0 |

The remaining 5 failures in the post-rebuild sample (`isLoopbackHost` ×2,
`assertOptions`, `toFiniteNumber`, `trim`) are genuinely subtle single-line edits
scoring within Stage 7's still-uncalibrated `±0.1` margin of each other — correctly
conservative `manual_review` calls, not corpus-quality bugs. Re-run
`scripts/validate_e2e.py` once `DEFAULT_VERIFICATION_MARGIN`
(`pipeline/controller/verification.py`) gets properly calibrated in module 11 — the
pass rate should move again.

The FAISS retrieval index (`corpus/data/embeddings/`) was not touched by the rebuild
script directly — it self-detects staleness via `corpus_fingerprint` and rebuilds on
next use (`pipeline/controller/retrieval.py`).
