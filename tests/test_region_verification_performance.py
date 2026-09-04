import difflib

from pipeline.controller import region_verification


def test_ratio_preserves_sequence_matcher_result_for_small_sequences():
    left = ["a", "b", "x", "c", "d"]
    right = ["a", "b", "y", "c", "d"]

    expected = difflib.SequenceMatcher(a=left, b=right, autojunk=False).ratio()

    assert region_verification._ratio(left, right) == expected


def test_ratio_only_sends_changed_core_to_sequence_matcher(monkeypatch):
    left = ["same"] * 50_000 + ["vulnerable"] + ["tail"] * 50_000
    right = ["same"] * 50_000 + ["patched"] + ["tail"] * 50_000
    observed = {}
    real_matcher = difflib.SequenceMatcher

    def recording_matcher(*, a, b, autojunk):
        observed.update(left_core=len(a), right_core=len(b), autojunk=autojunk)
        return real_matcher(a=a, b=b, autojunk=autojunk)

    monkeypatch.setattr(region_verification.difflib, "SequenceMatcher", recording_matcher)

    ratio = region_verification._ratio(left, right)

    assert observed == {"left_core": 1, "right_core": 1, "autojunk": False}
    assert ratio == 100_000 / 100_001
