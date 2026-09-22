"""Merkle snapshots and persisted state for incremental target scans.

The snapshot records which files changed. The scan controller decides which
functions need parsing and verification. Generated state belongs under
``.provtrail``.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from provtrail.corpus.models.corpus import CorpusEntry
from provtrail.pipeline.detection.config import RegionDetectorConfig
from provtrail.pipeline.models.result import RegionDetectionResult

STATE_SCHEMA_VERSION = 1
DEFAULT_STATE_FILENAME = "scan-state.json"
# Increment when the saved detector result contract changes.
RESULT_CACHE_SCHEMA_VERSION = 25
DEFAULT_EXCLUDED_DIRS = frozenset(
    {".git", ".provtrail", "node_modules", ".venv", "__pycache__"}
)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class MerkleSnapshot:
    """Content-addressed snapshot of a directory tree.

    ``files`` uses POSIX relative paths so state is portable across platforms.  The
    directory hashes are retained both for diagnostics and to make the tree shape
    explicit, even though the flat file map is sufficient to calculate changed paths.
    """

    root_hash: str
    files: dict[str, str] = field(default_factory=dict)
    directories: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_hash": self.root_hash,
            "files": dict(sorted(self.files.items())),
            "directories": dict(sorted(self.directories.items())),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "MerkleSnapshot":
        return cls(
            root_hash=str(value.get("root_hash", "")),
            files={str(k): str(v) for k, v in value.get("files", {}).items()},
            directories={str(k): str(v) for k, v in value.get("directories", {}).items()},
        )


def _iter_tree_files(root: Path, excluded_dirs: frozenset[str]) -> list[Path]:
    files: list[Path] = []
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name not in excluded_dirs)
        for filename in sorted(filenames):
            path = Path(current) / filename
            if path.is_file() and not path.is_symlink():
                files.append(path)
    return files


# Scan_directory calls this once before deciding which source files need work.
def build_merkle_snapshot(
    root: Path | str,
    excluded_dirs: frozenset[str] = DEFAULT_EXCLUDED_DIRS,
) -> MerkleSnapshot:
    """Build a deterministic file-and-directory Merkle snapshot for ``root``."""

    root = Path(root).resolve()
    if not root.is_dir():
        raise NotADirectoryError(root)

    files: dict[str, str] = {}
    children: dict[str, list[tuple[str, str, str]]] = {}
    children.setdefault("", [])
    for path in _iter_tree_files(root, excluded_dirs):
        relative = path.relative_to(root).as_posix()
        digest = _sha256(path.read_bytes())
        files[relative] = digest

        parts = relative.split("/")
        filename = parts[-1]
        parent = "" if len(parts) == 1 else "/".join(parts[:-1])
        children.setdefault(parent, []).append(("file", filename, digest))
        for index in range(1, len(parts)):
            directory = "/".join(parts[:index])
            parent_directory = "/".join(parts[: index - 1])
            children.setdefault(directory, [])
            entry = ("dir", parts[index - 1], directory)
            if entry not in children[parent_directory]:
                children[parent_directory].append(entry)

    directories: dict[str, str] = {}
    for directory in sorted(
        children,
        key=lambda item: item.count("/") + (1 if item else 0),
        reverse=True,
    ):
        entries = []
        for kind, name, value in sorted(children[directory]):
            child_hash = directories[value] if kind == "dir" else value
            entries.append(f"{kind}\0{name}\0{child_hash}")
        directories[directory] = _sha256("\n".join(entries).encode("utf-8"))

    return MerkleSnapshot(
        root_hash=directories.get("", _sha256(b"")),
        files=files,
        directories=directories,
    )


def changed_paths(
    previous: MerkleSnapshot | None,
    current: MerkleSnapshot,
) -> tuple[set[str], set[str]]:
    """Return ``(changed_or_added, deleted)`` relative file paths."""

    if previous is None:
        return set(current.files), set()
    changed = {
        path
        for path, digest in current.files.items()
        if previous.files.get(path) != digest
    }
    deleted = set(previous.files) - set(current.files)
    return changed, deleted


@dataclass
class ScanState:
    """Persisted state for one target root and one detector configuration."""

    target_root: str
    corpus_version: str
    detector_config_fingerprint: str
    snapshot: MerkleSnapshot
    functions: dict[str, dict[str, Any]] = field(default_factory=dict)
    result_cache: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": STATE_SCHEMA_VERSION,
            "target_root": self.target_root,
            "corpus_version": self.corpus_version,
            "detector_config_fingerprint": self.detector_config_fingerprint,
            "snapshot": self.snapshot.to_dict(),
            "functions": self.functions,
            "result_cache": self.result_cache,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ScanState":
        if int(value.get("schema_version", 0)) != STATE_SCHEMA_VERSION:
            raise ValueError("Unsupported scan-state schema version")
        return cls(
            target_root=str(value["target_root"]),
            corpus_version=str(value["corpus_version"]),
            detector_config_fingerprint=str(value["detector_config_fingerprint"]),
            snapshot=MerkleSnapshot.from_dict(value["snapshot"]),
            functions={str(k): dict(v) for k, v in value.get("functions", {}).items()},
            result_cache={str(k): dict(v) for k, v in value.get("result_cache", {}).items()},
        )


# Cache preparation loads prior state here and treats invalid state as a fresh scan.
def load_scan_state(path: Path | str) -> ScanState | None:
    path = Path(path)
    if not path.exists():
        return None
    try:
        return ScanState.from_dict(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError):
        # Corrupt or old state must result in a safe full scan, not a failed security
        # scan and not silently reused verdicts.
        return None


def save_scan_state(state: ScanState, path: Path | str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(json.dumps(state.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(path)


def fingerprint_config(value: Any) -> str:
    """Stable fingerprint for detector settings included in cache validity."""

    if hasattr(value, "__dataclass_fields__"):
        from dataclasses import asdict

        value = asdict(value)
    return _sha256(_canonical_json(value).encode("utf-8"))


# The CLI and Tier 1 runner use this to invalidate results when corpus data changes.
def corpus_fingerprint(entries: list[CorpusEntry]) -> str:
    values = []
    for entry in entries:
        values.append(
            {
                "identity": [entry.advisory.ghsa_id, entry.origin.fix_commit_sha, entry.origin.file_path, entry.origin.function_name],
                "vulnerable": entry.vulnerable_function,
                "patched": entry.patched_function,
                "advisory": {
                    "title": entry.advisory.advisory_title,
                    "description": entry.advisory.advisory_description,
                    "url": entry.advisory.advisory_url,
                    "references": entry.advisory.advisory_references,
                    "severity": entry.advisory.severity,
                    "affected_versions": entry.advisory.affected_versions,
                    "fixed_versions": entry.advisory.fixed_versions,
                },
            }
        )
    encoded = json.dumps(
        sorted(values, key=lambda value: json.dumps(value["identity"])),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


# Cached function content may move, so result_for updates its candidate and region IDs.
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
        item.model_copy(update={"candidate": item.candidate.model_copy(
            update={"region_id": rebind_region_id(item.candidate.region_id)}
        )})
        for item in result.evidence
    ]
    return result.model_copy(update={"candidate_id": candidate_id, "aggregates": aggregates, "evidence": evidence})


def _result_from_record(record: dict[str, Any], candidate_id: str) -> RegionDetectionResult:
    return _rebind_result(RegionDetectionResult.model_validate(record["result"]), candidate_id)


@dataclass
class ScanCache:
    """Cache identity and reusable results for one directory scan."""

    config_fingerprint: str
    previous_root_hash: str | None
    changed: set[str]
    deleted: set[str]
    previous_by_path: dict[str, list[dict[str, Any]]]
    results: dict[str, dict[str, Any]]
    context_matches: bool

    def unchanged_file(self, path: str) -> list[dict[str, Any]] | None:
        if self.context_matches and path not in self.changed and path in self.previous_by_path:
            return [dict(record) for record in self.previous_by_path[path]]
        return None

    def result_for(self, record: dict[str, Any]) -> RegionDetectionResult | None:
        cached = self.results.get(record["function_hash"])
        return _result_from_record(cached, record["function_id"]) if cached is not None else None

    def remember(self, record: dict[str, Any], result: RegionDetectionResult) -> None:
        self.results[record["function_hash"]] = {
            "function_hash": record["function_hash"],
            "result": result.model_dump(mode="json"),
        }

    def save(
        self, root: Path, corpus_version: str, snapshot: MerkleSnapshot,
        functions: dict[str, dict[str, Any]], state_path: Path,
    ) -> None:
        save_scan_state(ScanState(
            target_root=str(root),
            corpus_version=corpus_version,
            detector_config_fingerprint=self.config_fingerprint,
            snapshot=snapshot,
            functions=functions,
            result_cache=self.results,
        ), state_path)


# Scan_directory calls this after discovery to check prior state against this scan.
def prepare_scan_cache(
    root: Path, state_path: Path, corpus_version: str,
    detector: RegionDetectorConfig, snapshot: MerkleSnapshot,
) -> ScanCache:
    previous = load_scan_state(state_path)
    config_fingerprint = fingerprint_config({
        "detector": asdict(detector),
        "result_cache_schema": RESULT_CACHE_SCHEMA_VERSION,
    })
    context_matches = bool(
        previous
        and previous.target_root == str(root)
        and previous.corpus_version == corpus_version
        and previous.detector_config_fingerprint == config_fingerprint
    )
    changed, deleted = changed_paths(previous.snapshot if previous else None, snapshot)
    previous_functions = previous.functions if context_matches and previous else {}
    previous_by_path: dict[str, list[dict[str, Any]]] = {}
    for record in previous_functions.values():
        previous_by_path.setdefault(str(record["path"]), []).append(record)

    return ScanCache(
        config_fingerprint=config_fingerprint,
        previous_root_hash=previous.snapshot.root_hash if previous else None,
        changed=changed,
        deleted=deleted,
        previous_by_path=previous_by_path,
        results=dict(previous.result_cache) if context_matches and previous else {},
        context_matches=context_matches,
    )
