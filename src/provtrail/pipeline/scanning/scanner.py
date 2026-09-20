"""Coordinate directory scanning, detection, and result assessment."""

from __future__ import annotations

import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from provtrail.corpus.models.corpus import CorpusEntry
from provtrail.pipeline.controller.parsing import SUPPORTED_SOURCE_EXTENSIONS
from provtrail.pipeline.controller.region_detection import RegionDetector, RegionDetectorConfig, build_region_detector
from provtrail.pipeline.models.result import RegionDetectionResult
from provtrail.pipeline.scanning.cache import (
    DEFAULT_STATE_FILENAME, RESULT_CACHE_SCHEMA_VERSION, ScanCache,
    build_merkle_snapshot, corpus_fingerprint, _result_from_record,
    prepare_scan_cache,
)
from provtrail.pipeline.scanning.discovery import _extract_file_functions, _js_files
from provtrail.pipeline.scanning.project_context import ProjectEvidenceIndex, build_project_evidence

JS_EXTENSIONS = SUPPORTED_SOURCE_EXTENSIONS
DEFAULT_CORPUS_VERSION = "unknown"


class Detector(Protocol):
    def detect(
        self, candidate_source: str, candidate_id: str | None = None, language: str | None = None
    ) -> RegionDetectionResult:
        ...


@dataclass(frozen=True)
class ScanConfig:
    detector: RegionDetectorConfig = field(default_factory=RegionDetectorConfig)
    corpus_version: str = DEFAULT_CORPUS_VERSION
    state_path: Path | None = None
    extensions: tuple[str, ...] = JS_EXTENSIONS
    batch_size: int = 32


@dataclass
class ScanSummary:
    target_root: str
    root_hash: str
    previous_root_hash: str | None
    changed_files: list[str]
    deleted_files: list[str]
    scanned_files: list[str]
    total_files: int
    total_functions: int
    scanned_functions: int
    reused_functions: int
    priority_counts: dict[str, int]
    findings: list[dict[str, Any]]
    state_path: str
    explanation_run: dict[str, Any] = field(
        default_factory=lambda: {
            "enabled": False,
            "provider": "ollama",
            "model": None,
            "generated": 0,
            "reused": 0,
            "unavailable": 0,
        }
    )

    def to_dict(self) -> dict[str, Any]:
        public_findings = [
            {key: value for key, value in finding.items() if key != "source"}
            for finding in self.findings
        ]
        return {
            "schema": "provtrail_scan_v5",
            "target_root": self.target_root,
            "root_hash": self.root_hash,
            "previous_root_hash": self.previous_root_hash,
            "changed_files": self.changed_files,
            "deleted_files": self.deleted_files,
            "scanned_files": self.scanned_files,
            "total_files": self.total_files,
            "total_functions": self.total_functions,
            "scanned_functions": self.scanned_functions,
            "reused_functions": self.reused_functions,
            "priority_counts": self.priority_counts,
            "findings": public_findings,
            "state_path": self.state_path,
            "explanation_run": self.explanation_run,
        }


class _ScanRun:
    """Process source files using one cache and lazily initialized detector."""

    def __init__(
        self, root: Path, files: list[str], cache: ScanCache,
        project: ProjectEvidenceIndex, config: ScanConfig,
        detector: Detector | None, detector_factory: Callable[[], Detector] | None,
        progress: Callable[..., None],
    ) -> None:
        self.root = root
        self.files = files
        self.cache = cache
        self.project = project
        self.config = config
        self.detector = detector
        self.detector_factory = detector_factory
        self.progress = progress
        self.records: dict[str, dict[str, Any]] = {}
        self.scanned = 0
        self.reused = 0

    # File processing calls this only when cached results cannot cover a function.
    def _get_detector(self) -> Detector:
        if self.detector is None:
            if self.detector_factory is None:
                raise ValueError("A detector or detector_factory is required for uncached functions")
            self.progress("detector_start")
            self.detector = self.detector_factory()
            self.progress("detector_ready")
        return self.detector

    # Both scan paths call this after detection or reuse to refresh project context.
    def _record_result(
        self, record: dict[str, Any], raw: RegionDetectionResult,
        function_index: int, function_count: int, source: str,
    ) -> None:
        # Project evidence is refreshed even when the raw detector result came from cache.
        result = self.project.assess(raw, record["path"])
        record["result"] = result.model_dump(mode="json")
        self.records[record["function_id"]] = record
        self.progress(
            "function_complete",
            path=record["path"], function_index=function_index,
            function_count=function_count, name=record["name"],
            status=result.priority, source=source,
        )

    def _finish_file(
        self, file_index: int, path: str, function_count: int,
        scanned: int, reused: int,
    ) -> None:
        self.progress(
            "file_complete", completed_files=file_index,
            total_files=len(self.files), path=path,
            function_count=function_count, scanned_count=scanned,
            reused_count=reused,
        )

    # Scan_file uses saved records here when the whole source file is unchanged.
    def _reuse_file(self, file_index: int, path: str, records: list[dict[str, Any]]) -> None:
        for record in records:
            cached_result = _result_from_record(record, record["function_id"])
            record["result"] = self.project.assess(cached_result, path).model_dump(mode="json")
            self.records[record["function_id"]] = record
            self.reused += 1
        self._finish_file(file_index, path, len(records), 0, len(records))

    # The default RegionDetector shares retrieval work for uncached functions.
    def _scan_batch(
        self, path: str, records: list[dict[str, Any]],
        uncached: list[dict[str, Any]], detector: RegionDetector,
    ) -> tuple[int, int]:
        raw_results: dict[str, RegionDetectionResult] = {}
        result_sources: dict[str, str] = {}
        reused = 0
        scanned = 0

        for index, record in enumerate(records, start=1):
            self.progress(
                "function_start", path=path, function_index=index,
                function_count=len(records), name=record["name"],
                source_chars=len(record["source"]),
            )
            cached = self.cache.result_for(record)
            if cached is not None:
                raw_results[record["function_id"]] = cached
                result_sources[record["function_id"]] = "reused"
                reused += 1

        # Only uncached functions enter the shared retrieval batch.
        for offset in range(0, len(uncached), self.config.batch_size):
            chunk = uncached[offset: offset + self.config.batch_size]
            self.progress(
                "batch_start", path=path,
                batch_index=offset // self.config.batch_size + 1,
                batch_count=(len(uncached) + self.config.batch_size - 1) // self.config.batch_size,
                function_count=len(chunk),
            )
            batch_results = detector.detect_batch([
                (
                    record["function_id"], record["source"],
                    record.get("source_language"), record.get("name"),
                )
                for record in chunk
            ])
            if len(batch_results) != len(chunk):
                raise ValueError("detector batch result count does not match input count")
            for record, raw in zip(chunk, batch_results):
                raw_results[record["function_id"]] = raw
                result_sources[record["function_id"]] = "scanned"
                self.cache.remember(record, raw)
                scanned += 1
            self.progress(
                "batch_complete", path=path,
                batch_index=offset // self.config.batch_size + 1,
                function_count=len(chunk),
            )

        for index, record in enumerate(records, start=1):
            self._record_result(
                record, raw_results[record["function_id"]], index,
                len(records), result_sources[record["function_id"]],
            )
        return scanned, reused

    # Custom detectors and batch_size=1 use this path for each function.
    def _scan_sequential(self, path: str, records: list[dict[str, Any]]) -> tuple[int, int]:
        scanned = 0
        reused = 0
        for index, record in enumerate(records, start=1):
            self.progress(
                "function_start", path=path, function_index=index,
                function_count=len(records), name=record["name"],
                source_chars=len(record["source"]),
            )
            cached = self.cache.result_for(record)
            if cached is not None:
                raw = cached
                reused += 1
                source = "reused"
            else:
                detector = self._get_detector()
                if isinstance(detector, RegionDetector):
                    raw = detector.detect(
                        record["source"], candidate_id=record["function_id"],
                        language=record.get("source_language"),
                        candidate_function_name=record.get("name"),
                    )
                else:
                    raw = detector.detect(
                        record["source"], candidate_id=record["function_id"],
                        language=record.get("source_language"),
                    )
                self.cache.remember(record, raw)
                scanned += 1
                source = "scanned"
            self._record_result(record, raw, index, len(records), source)
        return scanned, reused

    # Scan_directory delegates each discovered file here for reuse or detection.
    def scan_file(self, file_index: int, path: str) -> None:
        cached_file = self.cache.unchanged_file(path)
        if cached_file is not None:
            self._reuse_file(file_index, path, cached_file)
            return

        records = _extract_file_functions(self.root, path)
        self.progress(
            "file_start", completed_files=file_index - 1,
            total_files=len(self.files), path=path, function_count=len(records),
        )
        uncached = [
            record for record in records
            if self.cache.results.get(record["function_hash"]) is None
        ]
        detector = self._get_detector() if uncached else self.detector
        if isinstance(detector, RegionDetector) and self.config.batch_size > 1:
            scanned, reused = self._scan_batch(path, records, uncached, detector)
        else:
            scanned, reused = self._scan_sequential(path, records)
        self.scanned += scanned
        self.reused += reused
        self._finish_file(file_index, path, len(records), scanned, reused)


# Called after all files to prepare findings for CLI and HTML reporting.
def _findings(records: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    findings = []
    for record in sorted(records.values(), key=lambda item: (item["path"], item["start_byte"])):
        result = _result_from_record(record, record["function_id"])
        finding = {
            "function_id": record["function_id"],
            "path": record["path"],
            "name": record["name"],
            "node_type": record["node_type"],
            "start_line": record["start_line"],
            "end_line": record["end_line"],
            "function_hash": record["function_hash"],
            "source_language": record.get("source_language", "javascript"),
            # HTML uses the in-memory source. ScanSummary.to_dict omits it from JSON.
            "source": record["source"],
            "result": result.model_dump(mode="json"),
        }
        findings.append(finding)
    return findings


# Called by the scan CLI and Tier 1 evaluator to coordinate the full directory scan.
def scan_directory(
    root: Path | str,
    *,
    detector: Detector | None = None,
    detector_factory: Callable[[], Detector] | None = None,
    entries: list[CorpusEntry] | None = None,
    config: ScanConfig | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> ScanSummary:
    """Scan JavaScript and TypeScript functions, reusing safe cached results."""

    config = config or ScanConfig()
    if config.batch_size < 1:
        raise ValueError("batch_size must be at least 1")
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)

    def progress(phase: str, **details: Any) -> None:
        if progress_callback is not None:
            progress_callback({"phase": phase, **details})

    # Discover files, then load a cache valid for this root, corpus and detector.
    state_path = config.state_path or root / ".provtrail" / DEFAULT_STATE_FILENAME
    progress("snapshot_start", root=str(root))
    snapshot = build_merkle_snapshot(root)
    files = _js_files(snapshot, config.extensions)
    project = build_project_evidence(root, files)
    progress("snapshot_complete", total_files=len(files))
    cache = prepare_scan_cache(root, state_path, config.corpus_version, config.detector, snapshot)

    # Reuse unchanged files or process functions from each changed file.
    run = _ScanRun(root, files, cache, project, config, detector, detector_factory, progress)
    for index, path in enumerate(files, start=1):
        run.scan_file(index, path)

    # Persist raw detector results and return assessed findings to the CLI.
    findings = _findings(run.records)
    cache.save(root, config.corpus_version, snapshot, run.records, state_path)
    priorities = Counter(finding["result"]["priority"] for finding in findings)
    progress(
        "scan_complete", total_files=len(files), total_functions=len(findings),
        scanned_functions=run.scanned, reused_functions=run.reused,
    )
    return ScanSummary(
        target_root=str(root),
        root_hash=snapshot.root_hash,
        previous_root_hash=cache.previous_root_hash,
        changed_files=sorted(cache.changed),
        deleted_files=sorted(cache.deleted),
        scanned_files=files,
        total_files=len(files),
        total_functions=len(findings),
        scanned_functions=run.scanned,
        reused_functions=run.reused,
        priority_counts=dict(sorted(priorities.items())),
        findings=findings,
        state_path=str(state_path),
    )


# The scan CLI passes this factory so model loading happens only when detection runs.
def build_default_detector_factory(
    entries: list[CorpusEntry],
    config: RegionDetectorConfig,
) -> Callable[[], RegionDetector]:
    return lambda: build_region_detector(entries, config=config, progress_callback=_index_progress)


def _index_progress(done: int, total: int) -> None:
    print(f"indexed corpus regions: {done}/{total}", file=sys.stderr, flush=True)
