import pytest

from corpus.models.corpus import CorpusEntry
from pipeline.controller.embedding import DEFAULT_MODEL_ID
from pipeline.controller.retrieval import (
    build_faiss_index,
    build_or_load_index,
    is_stale,
    load_index,
    query,
    save_index,
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

TRANSFER_RENAMED = """
function transfer(from, to, amt) {
    let bal = from.balance;
    if (bal < amt) { throw new Error('insufficient'); }
    from.balance = bal - amt;
    to.balance = to.balance + amt;
    return to.balance;
}
"""

UNRELATED = """
function formatDate(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
}
"""

pytestmark = pytest.mark.slow


def _entry(ghsa_id: str, vulnerable_function: str) -> CorpusEntry:
    return CorpusEntry(
        ghsa_id=ghsa_id,
        package_name="demo-pkg",
        ecosystem="npm",
        repo="demo/repo",
        fix_commit_sha="deadbeef",
        file_path="src/transfer.js",
        function_name="transfer",
        vulnerable_function=vulnerable_function,
        patched_function=vulnerable_function,
    )


def _entries() -> list[CorpusEntry]:
    return [_entry("GHSA-demo-0001", TRANSFER_A), _entry("GHSA-demo-0002", UNRELATED)]


def test_renamed_variant_retrieves_matching_entry():
    index = build_faiss_index(_entries(), model_id=DEFAULT_MODEL_ID)
    matches = query(TRANSFER_RENAMED, index, k=2, threshold=0.5)
    assert matches
    assert matches[0].ghsa_id == "GHSA-demo-0001"


def test_save_and_load_round_trips_to_same_top_match(tmp_path):
    entries = _entries()
    index = build_faiss_index(entries, model_id=DEFAULT_MODEL_ID)
    save_index(index, entries, dir_path=tmp_path)

    loaded = load_index(model_id=DEFAULT_MODEL_ID, dir_path=tmp_path)
    assert loaded is not None

    original_matches = query(TRANSFER_RENAMED, index, k=2, threshold=0.0)
    loaded_matches = query(TRANSFER_RENAMED, loaded, k=2, threshold=0.0)
    assert [m.ghsa_id for m in original_matches] == [m.ghsa_id for m in loaded_matches]


def test_build_or_load_reuses_unchanged_corpus_and_rebuilds_on_change(tmp_path):
    entries = _entries()
    build_or_load_index(entries, model_id=DEFAULT_MODEL_ID, dir_path=tmp_path)
    assert not is_stale(DEFAULT_MODEL_ID, entries, dir_path=tmp_path)

    changed_entries = _entries() + [_entry("GHSA-demo-0003", TRANSFER_RENAMED)]
    assert is_stale(DEFAULT_MODEL_ID, changed_entries, dir_path=tmp_path)

    rebuilt = build_or_load_index(changed_entries, model_id=DEFAULT_MODEL_ID, dir_path=tmp_path)
    assert len(rebuilt.entries) == 3
