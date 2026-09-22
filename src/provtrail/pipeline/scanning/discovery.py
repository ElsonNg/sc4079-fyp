"""Find source files and extract function records for scanning."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from provtrail.pipeline.controller.parsing import extract_function_units
from provtrail.pipeline.scanning.cache import MerkleSnapshot


def _function_hash(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


def _function_id(relative_path: str, start_byte: int, end_byte: int) -> str:
    return f"{relative_path}::{start_byte}:{end_byte}"


# Called after the Merkle snapshot so scanning only visits supported source files.
def _js_files(snapshot: MerkleSnapshot, extensions: tuple[str, ...]) -> list[str]:
    normalized = tuple(extension.lower() for extension in extensions)
    return sorted(path for path in snapshot.files if path.lower().endswith(normalized))


# Called for changed files to produce the records checked against the function cache.
def _extract_file_functions(root: Path, relative_path: str) -> list[dict[str, Any]]:
    source = (root / relative_path).read_text(encoding="utf-8")
    records = []
    for unit in extract_function_units(source, filename=relative_path):
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
                "source_language": unit.language,
            }
        )
    return records
