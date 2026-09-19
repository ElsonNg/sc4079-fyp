"""Fixture-selection checks for the 100-positive clone benchmark."""

from collections import Counter

from scripts.compare_clone_100 import origin_key, samples_100
from scripts.run_jscpd_clone_30 import samples as pilot_samples


def test_selection_is_balanced_and_retains_pilot() -> None:
    chosen = samples_100()
    assert len(chosen) == 100
    assert len({origin_key(row["fixture_record"]) for row in chosen}) == 100
    assert Counter((row["clone_type"], row["language"]) for row in chosen) == {
        (clone_type, language): count
        for clone_type in ("type_1", "type_2", "type_3", "type_4")
        for language, count in (("javascript", 12), ("typescript", 13))
    }
    assert [row["sample_id"] for row in chosen[:30]] == [
        row["sample_id"] for row in pilot_samples()
    ]


def test_new_exact_and_renamed_cases() -> None:
    new_cases = samples_100()[30:]
    assert all(
        row["candidate"] == row["reference"]
        for row in new_cases if row["clone_type"] == "type_1"
    )
    assert all(
        row["candidate"] != row["reference"] and "__clone_" in row["candidate"]
        for row in new_cases if row["clone_type"] == "type_2"
    )
