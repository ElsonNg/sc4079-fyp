import json

from pipeline.controller.incremental import (
    MerkleSnapshot,
    build_merkle_snapshot,
    changed_paths,
    load_scan_state,
    save_scan_state,
)
from pipeline.controller.scanning import ScanConfig, scan_directory
from pipeline.controller.region_detection import RegionDetector
from pipeline.models.regions import RegionDetectionResult


class _FakeDetector:
    def __init__(self):
        self.calls = []

    def detect(
        self,
        candidate_source: str,
        candidate_id: str | None = None,
        language: str | None = None,
    ):
        self.calls.append((candidate_source, candidate_id))
        return RegionDetectionResult(
            priority="manual_review",
            candidate_id=candidate_id,
            candidate_region_count=1,
            retrieval_match_count=1,
            message="fake detector",
        )


class _FakeBatchRegionDetector(RegionDetector):
    def __init__(self):
        self.single_calls = []
        self.batch_calls = []

    @staticmethod
    def _result(candidate_id):
        return RegionDetectionResult(
            priority="manual_review",
            candidate_id=candidate_id,
            candidate_region_count=1,
            retrieval_match_count=1,
            message="equivalent fake result",
        )

    def detect(self, candidate_source, candidate_id=None, language=None,
               candidate_function_name=None, **kwargs):
        self.single_calls.append((candidate_id, language, candidate_function_name))
        return self._result(candidate_id)

    def detect_batch(self, candidates):
        self.batch_calls.append(candidates)
        return [self._result(candidate[0]) for candidate in candidates]


def test_merkle_snapshot_is_deterministic_and_reports_file_changes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.js").write_text("const a = 1;\n", encoding="utf-8")
    (tmp_path / "src" / "b.js").write_text("const b = 2;\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "ignored").write_text("ignored", encoding="utf-8")

    first = build_merkle_snapshot(tmp_path)
    second = build_merkle_snapshot(tmp_path)

    assert first.root_hash == second.root_hash
    assert set(first.files) == {"src/a.js", "src/b.js"}

    (tmp_path / "src" / "a.js").write_text("const a = 3;\n", encoding="utf-8")
    (tmp_path / "src" / "b.js").unlink()
    (tmp_path / "src" / "c.js").write_text("const c = 4;\n", encoding="utf-8")
    current = build_merkle_snapshot(tmp_path)
    changed, deleted = changed_paths(first, current)

    assert changed == {"src/a.js", "src/c.js"}
    assert deleted == {"src/b.js"}
    assert current.root_hash != first.root_hash


def test_scan_reuses_unchanged_functions_and_rescans_changed_functions(tmp_path):
    source_path = tmp_path / "src.js"
    source_path.write_text("function first(value) { return value + 1; }\n", encoding="utf-8")
    state_path = tmp_path / ".provtrail" / "scan-state.json"
    fake = _FakeDetector()
    config = ScanConfig(corpus_version="corpus-v1", state_path=state_path)

    first = scan_directory(tmp_path, detector=fake, config=config)
    assert first.total_functions == 1
    assert first.scanned_functions == 1
    assert first.reused_functions == 0
    assert len(fake.calls) == 1

    second = scan_directory(tmp_path, detector=fake, config=config)
    assert second.scanned_functions == 0
    assert second.reused_functions == 1
    assert len(fake.calls) == 1

    (tmp_path / "README.md").write_text("non-JavaScript change", encoding="utf-8")
    third = scan_directory(tmp_path, detector=fake, config=config)
    assert third.scanned_functions == 0
    assert third.reused_functions == 1
    assert len(fake.calls) == 1

    source_path.write_text("function first(value) { return value + 2; }\n", encoding="utf-8")
    fourth = scan_directory(tmp_path, detector=fake, config=config)
    assert fourth.scanned_functions == 1
    assert fourth.reused_functions == 0
    assert len(fake.calls) == 2

    state = load_scan_state(state_path)
    assert state is not None
    assert state.snapshot.root_hash == fourth.root_hash
    assert state.functions


def test_scan_reuses_result_by_function_content_hash_after_location_changes(tmp_path):
    source_path = tmp_path / "src.js"
    source_path.write_text("function first(value) { return value + 1; }\n", encoding="utf-8")
    fake = _FakeDetector()
    config = ScanConfig(corpus_version="corpus-v1", state_path=tmp_path / "state.json")

    scan_directory(tmp_path, detector=fake, config=config)
    source_path.write_text("\n\nfunction first(value) { return value + 1; }\n", encoding="utf-8")
    result = scan_directory(tmp_path, detector=fake, config=config)

    assert result.scanned_functions == 0
    assert result.reused_functions == 1
    assert len(fake.calls) == 1


def test_scan_context_change_forces_safe_reverification(tmp_path):
    (tmp_path / "src.js").write_text("function first(value) { return value + 1; }\n", encoding="utf-8")
    fake = _FakeDetector()
    state_path = tmp_path / "state.json"

    scan_directory(tmp_path, detector=fake, config=ScanConfig(corpus_version="corpus-v1", state_path=state_path))
    result = scan_directory(tmp_path, detector=fake, config=ScanConfig(corpus_version="corpus-v2", state_path=state_path))

    assert result.scanned_functions == 1
    assert result.reused_functions == 0
    assert len(fake.calls) == 2


def test_scan_state_is_valid_json(tmp_path):
    (tmp_path / "src.js").write_text("function first() { return 1; }\n", encoding="utf-8")
    state_path = tmp_path / "state.json"
    scan_directory(tmp_path, detector=_FakeDetector(), config=ScanConfig(state_path=state_path))

    parsed = json.loads(state_path.read_text(encoding="utf-8"))
    assert parsed["schema_version"] == 1
    assert parsed["snapshot"]["root_hash"]


def test_scan_reports_intermediate_progress(tmp_path):
    (tmp_path / "src.js").write_text(
        "function first() { return 1; }\nfunction second() { return 2; }\n",
        encoding="utf-8",
    )
    events = []

    result = scan_directory(
        tmp_path,
        detector=_FakeDetector(),
        config=ScanConfig(state_path=tmp_path / "state.json"),
        progress_callback=events.append,
    )

    assert result.total_functions == 2
    assert [event["phase"] for event in events] == [
        "snapshot_start",
        "snapshot_complete",
        "file_start",
        "function_start",
        "function_complete",
        "function_start",
        "function_complete",
        "file_complete",
        "scan_complete",
    ]
    function_events = [event for event in events if event["phase"] == "function_complete"]
    # Project-evidence assessment derives the final priority; a detector result
    # without attributable lineages is intentionally reduced to no lineage.
    assert [event["status"] for event in function_events] == ["none", "none"]
    assert all(event["source"] == "scanned" for event in function_events)


def test_scan_reports_detector_initialization_when_factory_is_lazy(tmp_path):
    (tmp_path / "src.js").write_text("function first() { return 1; }\n", encoding="utf-8")
    events = []

    scan_directory(
        tmp_path,
        detector_factory=_FakeDetector,
        config=ScanConfig(state_path=tmp_path / "state.json"),
        progress_callback=events.append,
    )

    phases = [event["phase"] for event in events]
    assert phases.index("detector_start") < phases.index("detector_ready")
    assert phases.index("detector_ready") < phases.index("function_complete")


def test_batched_and_sequential_directory_scans_are_equivalent(tmp_path):
    source = (
        "function first(value) { return value + 1; }\n"
        "const second = (value: number) => value * 2;\n"
    )
    sequential_root = tmp_path / "sequential"
    batched_root = tmp_path / "batched"
    sequential_root.mkdir()
    batched_root.mkdir()
    (sequential_root / "source.ts").write_text(source, encoding="utf-8")
    (batched_root / "source.ts").write_text(source, encoding="utf-8")
    sequential_detector = _FakeBatchRegionDetector()
    batched_detector = _FakeBatchRegionDetector()

    sequential = scan_directory(
        sequential_root, detector=sequential_detector,
        config=ScanConfig(state_path=sequential_root / "state.json", batch_size=1),
    )
    batched = scan_directory(
        batched_root, detector=batched_detector,
        config=ScanConfig(state_path=batched_root / "state.json", batch_size=32),
    )

    assert sequential.priority_counts == batched.priority_counts
    assert [item["result"] for item in sequential.findings] == [
        item["result"] for item in batched.findings
    ]
    assert len(sequential_detector.single_calls) == 2
    assert len(batched_detector.batch_calls) == 1
    assert all(candidate[2] == "typescript" for candidate in batched_detector.batch_calls[0])
