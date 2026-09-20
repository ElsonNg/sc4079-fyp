import numpy as np
import pytest

from provtrail.pipeline.integrations.embedding import DEFAULT_MODEL_ID, encode

TRANSFER_A = """
function transfer(sender, receiver, amount) {
    let balance = sender.balance;
    if (balance < amount) { throw new Error('insufficient'); }
    sender.balance = balance - amount;
    receiver.balance = receiver.balance + amount;
    return receiver.balance;
}
"""

# Same as TRANSFER_A: identifiers renamed only.
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


def test_encode_returns_l2_normalized_vectors():
    vectors = encode(DEFAULT_MODEL_ID, [TRANSFER_A, UNRELATED])
    assert vectors.shape[0] == 2
    norms = np.linalg.norm(vectors, axis=1)
    assert np.allclose(norms, 1.0, atol=1e-2)


def test_renamed_variant_scores_higher_than_unrelated():
    vectors = encode(DEFAULT_MODEL_ID, [TRANSFER_A, TRANSFER_RENAMED, UNRELATED])
    original, renamed, unrelated = vectors
    sim_renamed = float(np.dot(original, renamed))
    sim_unrelated = float(np.dot(original, unrelated))
    assert sim_renamed > sim_unrelated


def test_empty_input_returns_empty_array_without_error():
    vectors = encode(DEFAULT_MODEL_ID, [])
    assert vectors.shape[0] == 0
