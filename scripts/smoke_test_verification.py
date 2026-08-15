"""Manual smoke test for pipeline.controller.verification -- real model(s), real
snippets. Prints the per-diagnostic-line score breakdown and final verdict for a
handful of (candidate, corpus entry) pairs, in the same style as
smoke_test_hierarchy.py's dump(). Useful for eyeballing before trusting the automated
assertions in tests/test_verification.py.

Same calibration caveat as smoke_test_alignment.py/smoke_test_hierarchy.py:
DEFAULT_GAP_PENALTY/DEFAULT_SPAN_MERGE_PENALTY and get_match_midpoint's probe set are
calibrated against qwen3-embedding-0.6b specifically; DEFAULT_VERIFICATION_MARGIN is
an uncalibrated placeholder for every model (see verification.py's own comment).

Run from the repo root:
    PYTHONPATH=. .venv/bin/python scripts/smoke_test_verification.py
"""
from corpus.controller.extraction import compute_diagnostic_lines
from corpus.models.corpus import CorpusEntry
from pipeline.controller.embedding import MODEL_REGISTRY
from pipeline.controller.hierarchy import EmbeddingCache
from pipeline.controller.verification import verify_candidate

BUILD_QUERY_VULNERABLE = """
function buildQuery(input) {
    const query = "SELECT * FROM users WHERE name = '" + input + "'";
    return query;
}
"""

BUILD_QUERY_PATCHED = """
function buildQuery(input) {
    const query = "SELECT * FROM users WHERE name = " + db.escape(input);
    return query;
}
"""

RENAMED_VULNERABLE_CLONE = """
function makeQuery(userInput) {
    const sql = "SELECT * FROM users WHERE name = '" + userInput + "'";
    return sql;
}
"""

RENAMED_AUTHORIZE_CLONE = """
function checkAccess(currentUser, targetResource) {
    if (currentUser.isAdmin) {
        return true;
    }
    if (targetResource.owner === currentUser.id) {
        return true;
    }
    return false;
}
"""

# examples/hierarchy_demo's fixture pair -- a pure insertion (patched only adds a new
# leading resource.locked guard), so this is the module's own fallback-path demo case.
AUTHORIZE_VULNERABLE = """
function authorize(user, resource) {
    if (user.isAdmin) {
        return true;
    }
    if (resource.owner === user.id) {
        return true;
    }
    return false;
}
"""

AUTHORIZE_PATCHED = """
function authorize(user, resource) {
    if (resource.locked) {
        return false;
    }
    if (user.isAdmin) {
        return true;
    }
    if (resource.owner === user.id) {
        return true;
    }
    return false;
}
"""


def _entry(ghsa_id: str, file_path: str, function_name: str, vulnerable: str, patched: str) -> CorpusEntry:
    return CorpusEntry(
        ghsa_id=ghsa_id,
        package_name="demo-pkg",
        ecosystem="npm",
        repo="demo/repo",
        fix_commit_sha="deadbeef",
        file_path=file_path,
        function_name=function_name,
        vulnerable_function=vulnerable,
        patched_function=patched,
        diagnostic_lines=compute_diagnostic_lines(vulnerable, patched),
    )


def show(title: str, candidate: str, entry: CorpusEntry, model_id: str) -> None:
    result = verify_candidate(candidate, entry, EmbeddingCache(), model_id=model_id)
    print(f"\n=== [{model_id}] {title} ===")
    print(f"  sim_vulnerable={result.sim_vulnerable:+.3f} (fallback={result.vulnerable_fallback_used})")
    print(f"  sim_patched   ={result.sim_patched:+.3f} (fallback={result.patched_fallback_used})")
    print(f"  verification_score={result.verification_score:+.3f}  status={result.status}")
    for d in result.diagnostic_scores:
        v = f"{d.vulnerable_score:+.3f}" if d.vulnerable_score is not None else "  ·  "
        p = f"{d.patched_score:+.3f}" if d.patched_score is not None else "  ·  "
        print(f"    [{d.kind:>7}] vuln_line={str(d.vulnerable_line):>4} v={v}  patched_line={str(d.patched_line):>4} p={p}  {d.text!r}")


if __name__ == "__main__":
    query_entry = _entry("GHSA-demo-query", "src/query.js", "buildQuery", BUILD_QUERY_VULNERABLE, BUILD_QUERY_PATCHED)
    authorize_entry = _entry("GHSA-demo-authz", "src/authorize.js", "authorize", AUTHORIZE_VULNERABLE, AUTHORIZE_PATCHED)

    for model_id in MODEL_REGISTRY:
        print(f"\n{'#' * 80}\n# model: {model_id}\n{'#' * 80}")
        show("candidate == vulnerable_function (buildQuery)", query_entry.vulnerable_function, query_entry, model_id)
        show("candidate == patched_function (buildQuery)", query_entry.patched_function, query_entry, model_id)
        show("renamed-identifier clone of vulnerable_function (buildQuery)", RENAMED_VULNERABLE_CLONE, query_entry, model_id)
        show("candidate == vulnerable_function (authorize, pure-insertion fallback case)", authorize_entry.vulnerable_function, authorize_entry, model_id)
        show("candidate == patched_function (authorize)", authorize_entry.patched_function, authorize_entry, model_id)
        show("renamed-identifier clone of vulnerable_function (authorize)", RENAMED_AUTHORIZE_CLONE, authorize_entry, model_id)
