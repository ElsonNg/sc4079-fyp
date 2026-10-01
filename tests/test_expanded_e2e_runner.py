"""Resume, repeat stability, independent outputs and explicit verifier settings."""
import json
import pytest

from eval.ablation import run_expanded_e2e as e2e
from eval.ablation import run_region_types as runner
from eval.ablation.common import seal, write_json
from tests.test_region_type_ablation import study_fixture


def test_selected_settings_match_frozen_shortlist():
    config = e2e.selected_config("fixture")
    assert config.retrieval_top_k == 5 and config.max_verification_candidates == 10
    assert config.include_expanded_correspondence_fallback is True
    assert config.include_local_correspondence_fallback is False
    assert config.verifier.minimum_edit_side_score == .90
    assert config.verifier.minimum_edit_margin == .10


def test_single_arm_resume_without_archived_controls(tmp_path, study_fixture):
    f = study_fixture
    f.study["detector"] = {}
    # No all_types/control files exist; every selected case is freshly run.
    e2e.execute_pass(tmp_path, f.study, e2e.ARM, 1, f.records, f.detector, "session-1", 30)
    assert len(f.calls) == 4
    e2e.execute_pass(tmp_path, f.study, e2e.ARM, 1, f.records, f.detector, "session-2", 30)
    assert len(f.calls) == 4
    e2e.collect(tmp_path, f.study, f.records)
    partial = json.loads((tmp_path / "combined/summary.json").read_text())
    assert all(not s["complete"] for s in partial["summaries"])
    e2e.execute_pass(tmp_path, f.study, e2e.ARM, 2, f.records, f.detector, "session-2", 30)
    assert len(f.calls) == 8
    e2e.collect(tmp_path, f.study, f.records)
    summary = json.loads((tmp_path / "combined/summary.json").read_text())
    scopes = [s for s in summary["summaries"] if (s["tier"], s["split"], s["route"]) == ("tier2", "all", "non_hash")]
    assert len(scopes) == 1
    assert scopes[0]["metrics"]["cases"] == 2
    assert scopes[0]["metrics"]["correct_origin_recall"]["denominator"] == 1
    assert scopes[0]["completed_repeats"] == [1, 2]
    assert scopes[0]["median_detector_seconds"] == 2.
    assert [p.name for p in (tmp_path / "runs").iterdir()] == [e2e.ARM]


def test_changed_repeat_decision_is_rejected(tmp_path, study_fixture, monkeypatch):
    f = study_fixture
    e2e.execute_pass(tmp_path, f.study, e2e.ARM, 1, f.records, f.detector, "session", 30)
    monkeypatch.setattr(runner, "run_case", lambda *args: dict(f.case(*args), priority="manual_review", abstained=True))
    with pytest.raises(ValueError, match="between repeats"):
        e2e.execute_pass(tmp_path, f.study, e2e.ARM, 2, f.records, f.detector, "session", 30)


def test_interrupted_pass_resumes_only_unfinished_cases(tmp_path, study_fixture, monkeypatch):
    f = study_fixture
    completed = []

    def interrupted(detector, record, fixed_hash):
        if len(completed) == 2:
            raise KeyboardInterrupt
        completed.append(record["candidate_id"])
        return f.case(detector, record, fixed_hash)

    monkeypatch.setattr(runner, "run_case", interrupted)
    with pytest.raises(KeyboardInterrupt):
        e2e.execute_pass(tmp_path, f.study, e2e.ARM, 1, f.records, f.detector, "session-1", 30)
    assert not runner.complete_pass(tmp_path, f.study, e2e.ARM, 1, f.records)
    assert len(f.calls) == 2
    monkeypatch.setattr(runner, "run_case", f.case)
    e2e.execute_pass(tmp_path, f.study, e2e.ARM, 1, f.records, f.detector, "session-2", 30)
    assert len(f.calls) == 4 and len(set(f.calls)) == 4
    marker = json.loads((runner.pass_dir(tmp_path, e2e.ARM, 1) / "complete.json").read_text())
    assert marker["interrupted"] is True
    assert marker["sessions"] == ["session-1", "session-2"]


def test_plan_is_read_only_and_restores_adapter(tmp_path, study_fixture, monkeypatch):
    f = study_fixture
    original_arms = runner.ARMS
    monkeypatch.setattr(runner, "prepare", lambda args: (dict(f.study, detector={}), f.records, None))
    monkeypatch.setattr(runner, "load_detector", lambda *args: pytest.fail("Plan loaded a model"))
    output = tmp_path / "planned"
    assert e2e.main(["--plan", "--output", str(output), "--count", "1"]) == 0
    assert not output.exists()
    assert runner.ARMS is original_arms
    write_json(output / "study-lock.json", seal(dict(f.study, code={"runner": "changed"})))
    with pytest.raises(ValueError, match="settings/source/inputs changed"):
        e2e.main(["--plan", "--output", str(output), "--count", "1"])
