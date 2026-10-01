import json
from types import SimpleNamespace

import numpy as np
import pytest

from eval.ablation import run_block_function as followup
from eval.ablation import run_region_types as runner
from eval.ablation.common import digest, seal, write_json
from eval.ablation.region_types import ARMS, region_mode
from provtrail.pipeline.controller import region_detection as controller
from provtrail.pipeline.controller.region_retrieval import query_regions
from provtrail.pipeline.integrations import embedding
from tests.test_region_type_ablation import fixture, source, study_fixture


def test_only_block_function_candidates_and_references_survive(monkeypatch):
    detector = fixture()
    monkeypatch.setattr(embedding, "encode", lambda _model, texts: np.tile(np.asarray([[1., 0.]], dtype=np.float32), (len(texts), 1)))
    with region_mode(detector, followup.REGIONS):
        candidates = controller.enumerate_candidate_regions(source(), max_regions=96)
        assert {c.region.granularity for c in candidates} == {"block", "function"}
        matches = query_regions(candidates, detector.region_index, top_k=4)
        assert {m.corpus_granularity for m in matches} == {"block", "function"}
        assert detector.boundary_function_pairs


@pytest.fixture
def archived_reference(tmp_path, study_fixture):
    f = study_fixture
    study = dict(f.study, parent_manifest="parent", inputs={}, model={}, dependencies={},
                 detector={}, execution={}, smoke_limit=None,
                 candidate_ids=[r["candidate_id"] for r in f.records], code={"core.py": "same"})
    archive = dict(study, schema="region_type_ablation_gpu_v1", arms={k: list(v) for k, v in ARMS.items()})
    directory = tmp_path / "archive"
    write_json(directory/"study-lock.json", seal(archive))
    write_json(directory/"runtime.json", seal({"gpu": "fake"}))
    write_json(directory/"combined/summary.json", {"study": digest(archive), "summaries": []})
    for arm in followup.REFERENCES:
        for repeat in (1, 2):
            write_json(runner.pass_dir(directory, arm, repeat)/"complete.json", seal({
                "study": digest(archive), "arm": arm, "repeat": repeat,
                "candidate_ids": sorted(study["candidate_ids"])}))
        for record in f.records:
            row = dict(f.case(f.detector, record, study["hash_routes"][record["candidate_id"]]), arm=arm, repetition=1)
            write_json(runner.checkpoint_path(directory, arm, 1, record["candidate_id"]),
                       seal({"identity": digest([digest(archive), arm, 1, record]), "row": row}))
    return SimpleNamespace(directory=directory, study=study, records=f.records)


def test_reuses_verified_reference_without_model_loading(archived_reference):
    f = archived_reference
    provenance, cache, summary = followup.load_reference(f.directory, f.study, f.records)
    assert set(cache) == set(followup.REFERENCES)
    assert all(len(rows) == 4 for rows in cache.values())
    assert all("result" not in row for rows in cache.values() for row in rows.values())
    assert provenance["selected_checkpoint_set_sha256"]
    assert provenance["runtime"] == {"gpu": "fake"}


def test_changed_original_code_is_rejected(archived_reference):
    f = archived_reference
    with pytest.raises(ValueError, match="code changed"):
        followup.load_reference(f.directory, dict(f.study, code={"core.py": "different"}), f.records)


def test_tampered_control_checkpoint_is_rejected(archived_reference):
    f = archived_reference
    path = runner.checkpoint_path(f.directory, "all_types", 1, f.records[0]["candidate_id"])
    value = json.loads(path.read_text())
    value["row"]["priority"] = "manual_review"
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="seal mismatch"):
        followup.load_reference(f.directory, f.study, f.records)


def test_single_arm_execution_reuses_controls_and_restores_original_runner(tmp_path, study_fixture, monkeypatch):
    f = study_fixture
    f.study.update(smoke_limit=None, candidate_ids=[r["candidate_id"] for r in f.records])
    controls = {arm: {r["candidate_id"]: f.case(f.detector, r, f.study["hash_routes"][r["candidate_id"]])
                      for r in f.records} for arm in followup.REFERENCES}
    f.calls.clear()
    monkeypatch.setattr(runner, "prepare", lambda args: (f.study.copy(), f.records, f.detector))
    monkeypatch.setattr(followup, "load_reference", lambda *args: ({"runtime": {"gpu": "fake"}}, controls, {"summaries": []}))
    original_arms = runner.ARMS
    original_read = runner.read_checkpoint
    output = tmp_path / "new"

    def execute(argv):
        assert runner.ARMS == {"block_function": ("block", "function")}
        study, records, detector = runner.prepare(SimpleNamespace())
        for repeat in (1, 2):
            runner.execute_pass(output, study, "block_function", repeat, records, detector, "session", 30)
        runner.collect(output, study, records)
        assert len(f.calls) == 8  # Four cases twice; no control scans.
        assert [p.name for p in (output/"runs").iterdir()] == ["block_function"]
        summary = json.loads((output/"combined/summary.json").read_text())
        assert {s["arm"] for s in summary["summaries"]} == {"block_function"}
        assert (output/"combined/reference-case-changes.json").exists()
        return 0

    monkeypatch.setattr(runner, "main", execute)
    assert followup.main([]) == 0
    assert runner.ARMS is original_arms
    assert runner.read_checkpoint is original_read
