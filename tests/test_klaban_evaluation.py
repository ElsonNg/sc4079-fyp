from pipeline.models.retrieval import RetrievalMatch
from scripts.evaluate_klaban_retrieval import evaluate_recall
from tests.test_windowed_retrieval import _entry


def test_recall_evaluator_scores_vulnerable_and_patched_queries():
    entry = _entry("function demo() { danger(); }", "function demo() { safe(); }")
    correct = RetrievalMatch(
        ghsa_id=entry.advisory.ghsa_id,
        fix_commit_sha=entry.origin.fix_commit_sha,
        file_path=entry.origin.file_path,
        function_name=entry.origin.function_name,
        repo=entry.origin.repo,
    )

    result = evaluate_recall(
        [entry],
        object(),
        k=5,
        query_fn=lambda source, _index, **_kwargs: [correct] if "danger" in source else [],
    )

    assert result["vulnerable_recall_at_k"] == 1.0
    assert result["patched_recall_at_k"] == 0.0


def test_recall_evaluator_reports_progress_after_each_query():
    entry = _entry("function demo() { danger(); }", "function demo() { safe(); }")
    updates = []

    evaluate_recall(
        [entry],
        object(),
        query_fn=lambda *_args, **_kwargs: [],
        progress_callback=updates.append,
    )

    assert [update["completed"] for update in updates] == [1, 2]
    assert all(update["total"] == 2 for update in updates)
    assert [update["phase"] for update in updates] == ["vulnerable", "patched"]
