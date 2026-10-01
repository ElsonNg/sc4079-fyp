from dataclasses import asdict
from itertools import product
import random

import pytest

from eval.ablation import exact_similarity as fast
from provtrail.pipeline.detection.verification.edit_distance import fuzzy_substring_similarity as frozen


def test_exhaustive_small_sequences_match_the_frozen_dp_exactly():
    values = [list(v) for n in range(7) for v in product("ab", repeat=n)]
    for query in values:
        for candidate in values:
            assert fast.fuzzy_substring_similarity(query, candidate) == frozen(query, candidate), (query, candidate)


def test_random_sequences_and_realistic_tokens_match_the_frozen_dp():
    rng = random.Random(4079)
    alphabet = ["ID", "LIT", "API:read", "CALL:reject", "(", ")", ">=", ">", "return", "变量", "/a+/g"]
    for _ in range(500):
        query = rng.choices(alphabet, k=rng.randrange(1, 100))
        candidate = rng.choices(alphabet, k=rng.randrange(1, 180))
        assert fast.fuzzy_substring_similarity(query, candidate) == frozen(query, candidate)


@pytest.mark.parametrize("length", [29, 30, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257])
def test_integer_word_boundaries_and_semiglobal_prefix_suffix(length):
    query = [f"t{i}" for i in range(length)]
    for candidate in [
        ["prefix"] * 10 + query + ["suffix"] * 10,
        ["prefix"] + query[:-1] + ["changed", "suffix"],
        query[1:], query[:length // 2] + ["inserted"] + query[length // 2:],
        list(reversed(query)),
    ]:
        assert fast.fuzzy_substring_similarity(query, candidate) == frozen(query, candidate)


def test_large_exact_and_one_edit_sequences_have_known_exact_scores():
    query = ["ID", "(", ")", ";"] * 2500
    assert fast.fuzzy_substring_similarity(query, list(query)) == 1.0
    changed = list(query)
    changed[5000] = "UNIQUE_SUBSTITUTION"
    # Equal lengths, not identical, and exactly one substitution apart.
    assert fast.fuzzy_substring_similarity(query, changed) == 1.0 - 1 / len(query)
    assert fast.fuzzy_substring_similarity(query, ["prefix"] + query + ["suffix"]) == 1.0


def test_edit_evidence_keeps_original_scores_and_restores_function():
    from provtrail.pipeline.detection.verification import edit_distance as ed
    original = ed.fuzzy_substring_similarity
    candidate = "if (size >= maximum) reject(); return buffer.read();"
    lines = [{"kind": "removed", "text": "if (length > limit) reject();"},
             {"kind": "added", "text": "if (length >= limit) reject();"}]
    old_evidence = ed.score_edit_distance(candidate, lines)
    with fast.exact_backend():
        assert ed.fuzzy_substring_similarity is fast.fuzzy_substring_similarity
        assert asdict(ed.score_edit_distance(candidate, lines)) == asdict(old_evidence)
    assert ed.fuzzy_substring_similarity is original
