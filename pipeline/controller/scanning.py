"""Target-directory scan orchestration with incremental result reuse."""

from __future__ import annotations

import hashlib
import json
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Protocol

from corpus.models.corpus import CorpusEntry
from pipeline.controller.incremental import (
    DEFAULT_STATE_FILENAME,
    MerkleSnapshot,
    ScanState,
    build_merkle_snapshot,
    changed_paths,
    fingerprint_config,
    load_scan_state,
    save_scan_state,
)
from pipeline.controller.parsing import extract_function_units
from pipeline.controller.region_detection import RegionDetector, RegionDetectorConfig, build_region_detector
from pipeline.models.regions import RegionDetectionResult

JS_EXTENSIONS = (".js", ".jsx", ".mjs", ".cjs")
DEFAULT_CORPUS_VERSION = "unknown"
# Bump this whenever the persisted RegionDetectionResult shape or its serialized
# metadata contract changes. This prevents old cache entries from being treated as
# complete results after adding fields such as CVE/version provenance.
RESULT_CACHE_SCHEMA_VERSION = 3


class Detector(Protocol):
    def detect(self, candidate_source: str, candidate_id: str | None = None) -> RegionDetectionResult:
        ...


@dataclass(frozen=True)
class ScanConfig:
    detector: RegionDetectorConfig = field(default_factory=RegionDetectorConfig)
    corpus_version: str = DEFAULT_CORPUS_VERSION
    state_path: Path | None = None
    extensions: tuple[str, ...] = JS_EXTENSIONS


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
    status_counts: dict[str, int]
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
            "schema": "provtrail_scan_v3",
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
            "status_counts": self.status_counts,
            "findings": public_findings,
            "state_path": self.state_path,
            "explanation_run": self.explanation_run,
        }


def corpus_fingerprint(entries: list[CorpusEntry]) -> str:
    values = []
    for entry in entries:
        values.append(
            {
                "identity": [entry.ghsa_id, entry.fix_commit_sha, entry.file_path, entry.function_name],
                "vulnerable": entry.vulnerable_function,
                "patched": entry.patched_function,
                "advisory": {
                    "title": entry.advisory_title,
                    "description": entry.advisory_description,
                    "url": entry.advisory_url,
                    "references": entry.advisory_references,
                    "severity": entry.severity,
                    "affected_versions": entry.affected_versions,
                    "fixed_versions": entry.fixed_versions,
                },
            }
        )
    encoded = json.dumps(
        sorted(values, key=lambda value: json.dumps(value["identity"])),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _function_hash(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _function_id(relative_path: str, start_byte: int, end_byte: int) -> str:
    return f"{relative_path}::{start_byte}:{end_byte}"


def _rebind_result(result: RegionDetectionResult, candidate_id: str) -> RegionDetectionResult:
    """Update cached candidate identifiers when a function is found at a new path/span."""

    old_id = result.candidate_id
    if not old_id or old_id == candidate_id:
        return result.model_copy(update={"candidate_id": candidate_id})

    def rebind_region_id(value: str) -> str:
        prefix = f"candidate:{old_id}:"
        return f"candidate:{candidate_id}:" + value[len(prefix):] if value.startswith(prefix) else value

    aggregates = []
    for aggregate in result.aggregates:
        top_matches = [
            match.model_copy(update={"candidate_region_id": rebind_region_id(match.candidate_region_id)})
            for match in aggregate.top_matches
        ]
        aggregates.append(aggregate.model_copy(update={"top_matches": top_matches}))
    evidence = [
        item.model_copy(update={"candidate_region_id": rebind_region_id(item.candidate_region_id)})
        for item in result.evidence
    ]
    return result.model_copy(update={"candidate_id": candidate_id, "aggregates": aggregates, "evidence": evidence})


def _result_from_record(record: dict[str, Any], candidate_id: str) -> RegionDetectionResult:
    return _rebind_result(RegionDetectionResult.model_validate(record["result"]), candidate_id)


def _js_files(snapshot: MerkleSnapshot, extensions: tuple[str, ...]) -> list[str]:
    normalized = tuple(extension.lower() for extension in extensions)
    return sorted(path for path in snapshot.files if path.lower().endswith(normalized))


def _extract_file_functions(root: Path, relative_path: str) -> list[dict[str, Any]]:
    source = (root / relative_path).read_text(encoding="utf-8")
    records = []
    for unit in extract_function_units(source):
        function_id = _function_id(relative_path, unit.start_byte, unit.end_byte)
        records.append(
            {
                "function_id": function_id,
                "path": relative_path,
                "name": unit.name,
                "node_type": unit.node_type,
                "start_line": unit.start_line,
                "end_line": unit.end_line,
                "start_byte": unit.start_byte,
                "end_byte": unit.end_byte,
                "function_hash": _function_hash(unit.source),
                "source": unit.source,
            }
        )
    return records


def scan_directory(
    root: Path | str,
    *,
    detector: Detector | None = None,
    detector_factory: Callable[[], Detector] | None = None,
    entries: list[CorpusEntry] | None = None,
    config: ScanConfig | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> ScanSummary:
    """Scan JavaScript functions, reusing safe cached results where possible."""

    config = config or ScanConfig()
    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)

    def progress(phase: str, **details: Any) -> None:
        if progress_callback is not None:
            progress_callback({"phase": phase, **details})

    state_path = config.state_path or root / ".provtrail" / DEFAULT_STATE_FILENAME
    progress("snapshot_start", root=str(root))
    previous = load_scan_state(state_path)
    snapshot = build_merkle_snapshot(root)
    js_files = _js_files(snapshot, config.extensions)
    progress("snapshot_complete", total_files=len(js_files))
    config_fingerprint = fingerprint_config(
        {
            "detector": asdict(config.detector),
            "result_cache_schema": RESULT_CACHE_SCHEMA_VERSION,
        }
    )
    context_matches = bool(
        previous
        and previous.target_root == str(root)
        and previous.corpus_version == config.corpus_version
        and previous.detector_config_fingerprint == config_fingerprint
    )
    changed, deleted = changed_paths(previous.snapshot if previous else None, snapshot)
    previous_root_hash = previous.snapshot.root_hash if previous else None

    previous_functions = previous.functions if context_matches and previous else {}
    previous_by_path: dict[str, list[dict[str, Any]]] = {}
    for record in previous_functions.values():
        previous_by_path.setdefault(str(record["path"]), []).append(record)

    result_cache = dict(previous.result_cache) if context_matches and previous else {}
    current_records: dict[str, dict[str, Any]] = {}
    scanned_functions = 0
    reused_functions = 0
    lazy_detector = detector

    def get_detector() -> Detector:
        nonlocal lazy_detector
        if lazy_detector is None:
            if detector_factory is None:
                raise ValueError("A detector or detector_factory is required for uncached functions")
            progress("detector_start")
            lazy_detector = detector_factory()
            progress("detector_ready")
        return lazy_detector

    for file_index, relative_path in enumerate(js_files, start=1):
        file_unchanged = context_matches and relative_path not in changed
        if file_unchanged and relative_path in previous_by_path:
            records = [dict(record) for record in previous_by_path[relative_path]]
            for record in records:
                current_records[record["function_id"]] = record
                reused_functions += 1
            progress(
                "file_complete",
                completed_files=file_index,
                total_files=len(js_files),
                path=relative_path,
                function_count=len(records),
                scanned_count=0,
                reused_count=len(records),
            )
            continue

        records = _extract_file_functions(root, relative_path)
        file_scanned = 0
        file_reused = 0
        progress(
            "file_start",
            completed_files=file_index - 1,
            total_files=len(js_files),
            path=relative_path,
            function_count=len(records),
        )
        for function_index, record in enumerate(records, start=1):
            progress(
                "function_start",
                path=relative_path,
                function_index=function_index,
                function_count=len(records),
                name=record["name"],
            )
            function_hash = record["function_hash"]
            cached = result_cache.get(function_hash)
            if cached is not None:
                result = _result_from_record(cached, record["function_id"])
                reused_functions += 1
                file_reused += 1
                source = "reused"
            else:
                result = get_detector().detect(record["source"], candidate_id=record["function_id"])
                scanned_functions += 1
                file_scanned += 1
                source = "scanned"
                result_cache[function_hash] = {
                    "function_hash": function_hash,
                    "result": result.model_dump(mode="json"),
                }
            record["result"] = result.model_dump(mode="json")
            current_records[record["function_id"]] = record
            progress(
                "function_complete",
                path=relative_path,
                function_index=function_index,
                function_count=len(records),
                name=record["name"],
                status=result.status,
                source=source,
            )
        progress(
            "file_complete",
            completed_files=file_index,
            total_files=len(js_files),
            path=relative_path,
            function_count=len(records),
            scanned_count=file_scanned,
            reused_count=file_reused,
        )

    findings = []
    for record in sorted(current_records.values(), key=lambda item: (item["path"], item["start_byte"])):
        result = _result_from_record(record, record["function_id"])
        finding = {
            "function_id": record["function_id"],
            "path": record["path"],
            "name": record["name"],
            "node_type": record["node_type"],
            "start_line": record["start_line"],
            "end_line": record["end_line"],
            "function_hash": record["function_hash"],
            # Kept on the in-memory summary for HTML rendering. ``to_dict``
            # deliberately removes source so the established JSON artifact remains
            # safe to share and compact.
            "source": record["source"],
            "result": result.model_dump(mode="json"),
        }
        findings.append(finding)

    state = ScanState(
        target_root=str(root),
        corpus_version=config.corpus_version,
        detector_config_fingerprint=config_fingerprint,
        snapshot=snapshot,
        functions=current_records,
        result_cache=result_cache,
    )
    save_scan_state(state, state_path)
    statuses = Counter(finding["result"]["status"] for finding in findings)
    progress(
        "scan_complete",
        total_files=len(js_files),
        total_functions=len(findings),
        scanned_functions=scanned_functions,
        reused_functions=reused_functions,
    )
    return ScanSummary(
        target_root=str(root),
        root_hash=snapshot.root_hash,
        previous_root_hash=previous_root_hash,
        changed_files=sorted(changed),
        deleted_files=sorted(deleted),
        scanned_files=js_files,
        total_files=len(js_files),
        total_functions=len(findings),
        scanned_functions=scanned_functions,
        reused_functions=reused_functions,
        status_counts=dict(sorted(statuses.items())),
        findings=findings,
        state_path=str(state_path),
    )


def build_default_detector_factory(
    entries: list[CorpusEntry],
    config: RegionDetectorConfig,
) -> Callable[[], RegionDetector]:
    return lambda: build_region_detector(entries, config=config, progress_callback=_index_progress)


def _index_progress(done: int, total: int) -> None:
    print(f"indexed corpus regions: {done}/{total}", file=sys.stderr, flush=True)
