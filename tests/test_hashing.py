from corpus.models.corpus import CorpusEntry
from pipeline.controller.hashing import (
    MIN_HASHABLE_LENGTH,
    abstract_identifiers,
    build_hash_index,
    compute_fingerprint,
    lookup,
)

TRANSFER_A = """
function transfer(sender, receiver, amount) {
    let balance = sender.balance;
    if (balance < amount) { throw new Error('insufficient'); }
    sender.balance = balance - amount;
    receiver.balance = receiver.balance + amount;
    return receiver.balance;
}
"""

# Same as TRANSFER_A: identifiers renamed only, a comment added.
TRANSFER_RENAMED = """
function transfer(from, to, amt) {
    let bal = from.balance; // check funds
    if (bal < amt) { throw new Error('insufficient'); }
    from.balance = bal - amt;
    to.balance = to.balance + amt;
    return to.balance;
}
"""

# Same shape as TRANSFER_A, but sender/receiver roles are swapped -- not a rename,
# a genuinely different function.
TRANSFER_SWAPPED = """
function transfer(sender, receiver, amount) {
    let balance = receiver.balance;
    if (balance < amount) { throw new Error('insufficient'); }
    receiver.balance = balance - amount;
    sender.balance = sender.balance + amount;
    return sender.balance;
}
"""

# Only whitespace/comment differences from TRANSFER_A.
TRANSFER_WHITESPACE = """
function transfer(sender, receiver, amount) {

    let balance = sender.balance;   // withdraw
    if (balance < amount) { throw new Error('insufficient'); }
    sender.balance   = balance - amount;
    receiver.balance = receiver.balance + amount;
    return receiver.balance;
}
"""


def test_identical_function_same_exact_hash():
    fp1 = compute_fingerprint(TRANSFER_A)
    fp2 = compute_fingerprint(TRANSFER_A)
    assert fp1.exact_hash == fp2.exact_hash


def test_whitespace_and_comment_only_changes_same_exact_hash():
    fp1 = compute_fingerprint(TRANSFER_A)
    fp2 = compute_fingerprint(TRANSFER_WHITESPACE)
    assert fp1.exact_hash == fp2.exact_hash


def test_renamed_identifiers_differ_exact_but_match_abstracted():
    fp1 = compute_fingerprint(TRANSFER_A)
    fp2 = compute_fingerprint(TRANSFER_RENAMED)
    assert fp1.exact_hash != fp2.exact_hash
    assert fp1.abstracted_hash == fp2.abstracted_hash


def test_role_swapped_variables_differ_even_when_abstracted():
    """Positional placeholders (FPARAM1/FPARAM2, not VUDDY's shared FPARAM token) are
    the whole point here: `sender`/`receiver` swapped is a different function, not a
    rename, and should not collapse to the same abstracted hash."""
    fp1 = compute_fingerprint(TRANSFER_A)
    fp3 = compute_fingerprint(TRANSFER_SWAPPED)
    assert fp1.abstracted_hash != fp3.abstracted_hash


def test_reordered_independent_locals_change_abstracted_hash():
    """Accepted trade-off vs. VUDDY's non-positional scheme, not a bug: two
    independent (no data dependency) local declarations swapped in order still
    produce a different abstracted hash, since LVAR numbering is positional by
    first-declaration order."""
    a = "function f(x) { let alpha = x + 1; let beta = x + 2; return alpha + beta; }"
    b = "function f(x) { let beta = x + 2; let alpha = x + 1; return alpha + beta; }"
    assert compute_fingerprint(a).abstracted_hash != compute_fingerprint(b).abstracted_hash


def test_object_shorthand_key_not_abstracted_but_value_is():
    src = "function f(person) { let name = person.name; return { name }; }"
    abstracted = abstract_identifiers(src)
    assert "{ LVAR1 }" in abstracted


def test_object_explicit_key_value_only_value_abstracted():
    src = "function f(obj) { let renamed = obj.value; return { value: renamed }; }"
    abstracted = abstract_identifiers(src)
    assert "value: LVAR1" in abstracted
    assert "FPARAM1.value" in abstracted


def test_for_of_and_for_in_bindings_get_lvar_tokens():
    src = """
    function process(items) {
        for (const item of items) { console.log(item); }
        for (let key in items) { console.log(key); }
    }
    """
    abstracted = abstract_identifiers(src)
    assert "for (const LVAR1 of FPARAM1)" in abstracted
    assert "for (let LVAR2 in FPARAM1)" in abstracted
    assert "item" not in abstracted
    assert "key" not in abstracted


def test_nested_arrow_and_method_params_continue_fparam_sequence():
    src = """
    function outer(items) {
        const helper = (p) => { let inner = p; return inner; };
        class C { method(m) { let local = m; return local; } }
        return helper(items);
    }
    """
    abstracted = abstract_identifiers(src)
    assert "(FPARAM2) =>" in abstracted
    assert "method(FPARAM3)" in abstracted


def test_short_function_excluded_from_hashing():
    fp = compute_fingerprint("function f(a) { return a; }")
    assert fp.abstracted_length < MIN_HASHABLE_LENGTH
    assert fp.hashable is False
    assert fp.exact_hash is None
    assert fp.abstracted_hash is None


def _entry(ghsa_id: str, vulnerable: str, patched: str) -> CorpusEntry:
    return CorpusEntry(
        ghsa_id=ghsa_id,
        package_name="pkg",
        ecosystem="npm",
        repo="owner/pkg",
        fix_commit_sha="deadbeef",
        file_path="index.js",
        vulnerable_function=vulnerable,
        patched_function=patched,
    )


def test_hash_index_round_trip_finds_vulnerable_and_patched_sides():
    entry = _entry("GHSA-test-0001", TRANSFER_A, TRANSFER_WHITESPACE.replace("balance", "bal"))
    index = build_hash_index([entry])

    vuln_matches = lookup(TRANSFER_A, index)
    assert any(m.side == "vulnerable" and m.match_type == "exact" for m in vuln_matches)

    patched_source = TRANSFER_WHITESPACE.replace("balance", "bal")
    patched_matches = lookup(patched_source, index)
    assert any(m.side == "patched" and m.match_type == "exact" for m in patched_matches)


def test_hash_index_skips_unhashable_entries():
    entry = _entry("GHSA-test-0002", "function f(a) { return a; }", "function f(a) { return -a; }")
    index = build_hash_index([entry])
    assert index.exact == {}
    assert index.abstracted == {}
