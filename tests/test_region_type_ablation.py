from contextlib import contextmanager
import json
from types import SimpleNamespace

import faiss
import numpy as np
import pytest

from eval.ablation.common import digest, seal, write_json
from eval.ablation import run_region_types as runner
from eval.ablation.region_types import ARMS, TYPES, EligibleHNSW, region_mode
from provtrail.corpus.models.corpus import CorpusEntry
from provtrail.pipeline.controller import region_detection as controller
from provtrail.pipeline.controller.hashing import HashIndex
from provtrail.pipeline.controller.region_extraction import enumerate_candidate_regions, extract_corpus_region_pairs
from provtrail.pipeline.controller.region_retrieval import RegionRetrievalIndex, query_regions
from provtrail.pipeline.integrations import embedding


def source():
    body = "\n".join(f"  service.accept(value + {i});" for i in range(30))
    return f"function checkValue(value) {{\n{body}\n  return service.result;\n}}"


def fixture():
    entry = CorpusEntry(
        ghsa_id="GHSA-region-test", package_name="test-package", ecosystem="npm",
        repo="test/repo", fix_commit_sha="abcdef", file_path="lib/test.js",
        function_name="checkValue", vulnerable_function=source(),
        patched_function=source().replace("service.accept", "service.reject"),
        diagnostic_lines=[{"kind": "removed", "vulnerable_line": 1, "text": "service.accept(value);"}],
    )
    pairs = extract_corpus_region_pairs([entry])
    vectors = np.asarray([[1., .0], [.98, .02], [.8, .2], [.5, .5]], dtype=np.float32)
    index = faiss.IndexHNSWFlat(2, 4, faiss.METRIC_INNER_PRODUCT)
    index.hnsw.efSearch = 128
    index.add(vectors)
    region_index = RegionRetrievalIndex("test", index, pairs,
                                        [p.pair_id for p in pairs], ["vulnerable"]*4)
    detector = SimpleNamespace(entry=entry, region_index=region_index, pairs={p.pair_id: p for p in pairs},
        boundary_function_pairs={p.fix_boundary_id: p for p in pairs if p.vulnerable_region.granularity == "function"})
    return detector


def test_selector_excludes_best_neighbors_before_top_k():
    detector = fixture()
    index = detector.region_index.index
    _, unfiltered = index.search(np.asarray([[1., 0.]], dtype=np.float32), 1)
    assert unfiltered.tolist() == [[0]]
    selected = EligibleHNSW(index, [2, 3])
    _, ids = selected.search(np.asarray([[1., 0.]], dtype=np.float32), 1)
    assert ids.tolist() == [[2]]


def test_reference_eligibility_reaches_real_retrieval_and_retains_function_pairs(monkeypatch):
    detector = fixture()
    functions = detector.boundary_function_pairs.copy()
    original = detector.region_index
    candidates = enumerate_candidate_regions(source(), max_regions=1)
    monkeypatch.setattr(embedding, "encode", lambda _model, texts: np.tile(np.asarray([[1., 0.]], dtype=np.float32), (len(texts), 1)))
    with region_mode(detector, ARMS["no_changed"]):
        results = query_regions(candidates, detector.region_index, top_k=1)
        assert len(results) == 1
        assert results[0].corpus_granularity == "block"
        assert detector.region_index.pairs is original.pairs
        assert detector.boundary_function_pairs == functions
    assert detector.region_index is original


@pytest.mark.parametrize("arm", list(ARMS))
def test_candidate_eligibility_is_applied_before_cap_and_restored(arm):
    detector = fixture()
    original = controller.enumerate_candidate_regions
    with region_mode(detector, ARMS[arm]):
        regions = controller.enumerate_candidate_regions(source(), max_regions=8)
        assert all(r.region.granularity in ARMS[arm] for r in regions)
        assert len(regions) == (1 if arm == "function_only" else 8)
        if arm == "all_types":
            assert [r.model_dump() for r in regions] == [r.model_dump() for r in original(source(), max_regions=8)]
    assert controller.enumerate_candidate_regions is original


def test_no_function_keeps_function_source_for_patch_verification_on_error():
    detector = fixture()
    original = detector.region_index
    functions = detector.boundary_function_pairs.copy()
    with pytest.raises(RuntimeError):
        with region_mode(detector, ARMS["no_function"]):
            assert detector.boundary_function_pairs == functions
            assert any(p.vulnerable_region.granularity == "function" for p in detector.region_index.pairs)
            raise RuntimeError("interrupted")
    assert detector.region_index is original


def test_real_detector_runs_without_function_retrieval_and_keeps_edit_diagnostics(monkeypatch):
    fixture_detector = fixture()
    detector = controller.RegionDetector([fixture_detector.entry], fixture_detector.region_index, HashIndex(),
                                          runner.detector_config("test"))
    monkeypatch.setattr(embedding, "encode", lambda _model, texts: np.tile(np.asarray([[1., 0.]], dtype=np.float32), (len(texts), 1)))
    monkeypatch.setattr(runner, "synchronize", lambda: None)
    record = dict(candidate_id="end-to-end", candidate_source=source(), source_language="javascript",
                  tier="tier2", split="evaluation", package_name="test-package", expected_status="flagged",
                  corpus_entry=fixture_detector.entry.model_dump(mode="json"))
    with region_mode(detector, ARMS["no_function"]):
        row = runner.run_case(detector, record, False)
    assert row["candidate_region_count"] > 0
    assert "function" not in row["candidate_type_counts"]
    assert "function" not in row["reference_type_counts"]
    assert row["boundaries"]
    assert detector.boundary_diagnostics


@pytest.fixture
def study_fixture(monkeypatch):
    records = [dict(candidate_id=f"case-{i}", candidate_source="service.accept(value);",
                    candidate_source_sha256=digest("service.accept(value);"),
                    tier="tier1" if i < 2 else "tier2", source_language="javascript",
                    expected_status="flagged" if i % 2 == 0 else "cleared",
                    split="tuning" if i % 2 == 0 else "evaluation", package_name="test") for i in range(4)]
    study = dict(repetitions=2, seed=4079, hash_routes={r["candidate_id"]: r["tier"] == "tier1" for r in records},
                 code={"runner": "a"}, searchable_vector_counts={arm: 10 for arm in ARMS})
    detector = SimpleNamespace(boundary_diagnostics={}, allowed=TYPES, detect=lambda *args, **kwargs: None)
    calls = []

    @contextmanager
    def mode(detector, allowed):
        detector.allowed = allowed
        yield

    def case(detector, record, fixed_hash):
        calls.append(record["candidate_id"])
        auto = record["expected_status"] == "flagged"
        return dict(candidate_id=record["candidate_id"], tier=record["tier"], split=record["split"],
                    expected_status=record["expected_status"], priority="automatic_vulnerability" if auto else "none",
                    hash_path=fixed_hash, expected_hash_types=["exact"] if fixed_hash else [],
                    expected_raw_rank=None if fixed_hash else 1, expected_aggregate_rank=1,
                    correct_origin_automatic=auto, wrong_origin_automatic=False,
                    patched_false_positive=False, abstained=False, candidate_region_count=0 if fixed_hash else 1,
                    candidate_type_counts={} if fixed_hash else {detector.allowed[0]: 1},
                    reference_type_counts={} if fixed_hash else {detector.allowed[0]: 1},
                    boundaries=[["boundary", "vulnerable" if auto else "patched", None]], lineages=[],
                    elapsed_seconds=1., result={"priority": "automatic_vulnerability" if auto else "none"})

    monkeypatch.setattr(runner, "synchronize", lambda: None)
    monkeypatch.setattr(runner, "region_mode", mode)
    monkeypatch.setattr(runner, "run_case", case)
    return SimpleNamespace(study=study, records=records, detector=detector, calls=calls, case=case)


def test_resume_reuses_checkpoints_and_preserves_quality_denominators(tmp_path, study_fixture):
    f = study_fixture
    runner.execute_pass(tmp_path, f.study, "all_types", 1, f.records, f.detector, "session-1", 30)
    assert len(f.calls) == 4
    # Re-entering the same pass should not scan saved cases again.
    runner.execute_pass(tmp_path, f.study, "all_types", 1, f.records, f.detector, "session-2", 30)
    assert len(f.calls) == 4
    for arm in ARMS:
        for repeat in (1, 2):
            if arm == "all_types" and repeat == 1:
                continue
            runner.execute_pass(tmp_path, f.study, arm, repeat, f.records, f.detector, "session-2", 30)
    runner.collect(tmp_path, f.study, f.records)
    summary = json.loads((tmp_path / "combined/summary.json").read_text())
    scopes = [s for s in summary["summaries"] if (s["tier"], s["split"], s["route"]) == ("tier2", "all", "non_hash")]
    assert len(scopes) == 6
    assert all(s["metrics"]["cases"] == 2 and s["metrics"]["automatic_recall"]["denominator"] == 1 for s in scopes)
    assert all(s["completed_repeats"] == [1, 2] and s["median_detector_seconds"] == 2 for s in scopes)
    assert runner.complete_pass(tmp_path, f.study, "all_types", 2, f.records)


def test_resume_rejects_changed_case_and_missing_complete_checkpoint(tmp_path, study_fixture):
    f = study_fixture
    runner.execute_pass(tmp_path, f.study, "all_types", 1, f.records, f.detector, "session", 30)
    changed = dict(f.records[0], candidate_source="changed")
    with pytest.raises(ValueError, match="another study/candidate"):
        runner.read_checkpoint(tmp_path, f.study, "all_types", 1, changed)
    runner.checkpoint_path(tmp_path, "all_types", 1, f.records[0]["candidate_id"]).unlink()
    with pytest.raises(ValueError, match="missing a checkpoint"):
        runner.complete_pass(tmp_path, f.study, "all_types", 1, f.records)


def test_checkpoint_tampering_is_rejected(tmp_path, study_fixture):
    f = study_fixture
    runner.execute_pass(tmp_path, f.study, "all_types", 1, f.records, f.detector, "session", 30)
    path = runner.checkpoint_path(tmp_path, "all_types", 1, f.records[0]["candidate_id"])
    data = json.loads(path.read_text())
    data["row"]["priority"] = "none"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="seal mismatch"):
        runner.read_checkpoint(tmp_path, f.study, "all_types", 1, f.records[0])


def test_repeat_guard_rejects_changed_decision(tmp_path, study_fixture, monkeypatch):
    f = study_fixture
    runner.execute_pass(tmp_path, f.study, "all_types", 1, f.records, f.detector, "session", 30)

    def drift(*args):
        return dict(f.case(*args), priority="manual_review", abstained=True)

    monkeypatch.setattr(runner, "run_case", drift)
    with pytest.raises(ValueError, match="between repeats"):
        runner.execute_pass(tmp_path, f.study, "all_types", 2, f.records, f.detector, "session", 30)


def test_metrics_include_reviews_in_positive_and_patched_denominators():
    rows = [dict(expected_status=label, priority="manual_review", correct_origin_automatic=False,
                 wrong_origin_automatic=False, abstained=True, expected_aggregate_rank=None,
                 expected_hash_types=[], expected_raw_rank=None, candidate_region_count=1, elapsed_seconds=1.)
            for label in ("flagged", "cleared")]
    metrics = runner.metrics(rows)
    assert metrics["automatic_recall"] == runner.fraction(0, 1)
    assert metrics["patched_false_alert_rate"] == runner.fraction(0, 1)
    assert metrics["review_rate"] == runner.fraction(2, 2)


def test_plan_is_read_only_and_rejects_changed_source_lock(tmp_path, study_fixture, monkeypatch):
    f = study_fixture
    monkeypatch.setattr(runner, "prepare", lambda args: (f.study, f.records, None))
    monkeypatch.setattr(runner, "load_detector", lambda *args: pytest.fail("Plan loaded a model"))
    output = tmp_path / "output"
    assert runner.main(["--plan", "--output", str(output)]) == 0
    assert not output.exists()
    write_json(output / "study-lock.json", seal(dict(f.study, code={"runner": "changed"})))
    with pytest.raises(ValueError, match="settings/source/inputs changed"):
        runner.main(["--plan", "--output", str(output)])


def test_concurrent_writer_is_rejected_and_lock_is_released(tmp_path):
    output = tmp_path / "output"
    with runner.study_writer(output):
        with pytest.raises(ValueError, match="Another process"):
            with runner.study_writer(output):
                pytest.fail("Two writers acquired the same output lock")
    with runner.study_writer(output):
        pass
