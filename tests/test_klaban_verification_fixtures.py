from provtrail.corpus.models.corpus import CorpusEntry
from scripts.generate_klaban_verification_subset import generate_fixtures


def _entry(index: int) -> CorpusEntry:
    return CorpusEntry(
        ghsa_id=f"KLABAN-CASE-{index}",
        package_name=f"package-{index}",
        ecosystem="npm",
        repo=f"acme/repo-{index}",
        fix_commit_sha=f"commit-{index}",
        file_path=f"src/file-{index}.js",
        function_name=f"case{index}",
        vulnerable_function=f"function case{index}(value) {{ return sink(value); }}",
        patched_function=f"function case{index}(value) {{ return safe(value); }}",
    )


def test_generate_klaban_verification_fixtures():
    entries = [_entry(index) for index in range(1, 6)]
    entries.append(
        _entry(99).model_copy(update={'advisory': _entry(99).advisory.model_copy(update={'ghsa_id': "GHSA-NOT-KLABAN"})})
    )

    positives, negatives = generate_fixtures(entries, count=2)

    assert len(positives) == 2
    assert len(negatives) == 4
    assert all(row["corpus_entry"]["ghsa_id"].startswith("KLABAN-") for row in positives + negatives)
    assert all(row["expected_status"] == "flagged" for row in positives)
    assert {row["negative_category"] for row in negatives} == {"patched", "benign_similar"}
    assert sum(row["negative_category"] == "patched" for row in negatives) == 2
    assert all(row["candidate_source"] != row["vulnerable_function"] for row in positives)
