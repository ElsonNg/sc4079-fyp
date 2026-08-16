"""Merkle snapshots and persisted state for incremental target scans.

The snapshot is deliberately independent of the vulnerability detector.  It answers
which files changed; the scan controller decides which functions need to be parsed and
verified.  Generated state belongs under ``.provtrail`` and is never part of the
corpus or detector's correctness contract.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

STATE_SCHEMA_VERSION = 1
DEFAULT_STATE_FILENAME = "scan-state.json"
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
