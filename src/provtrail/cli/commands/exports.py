"""Validate and write optional scan exports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from provtrail.cli import PROVTRAIL_VERSION
from provtrail.pipeline.controller.finding_exports import build_sarif, format_ai


def validate_paths(
    *, sarif_path: Path | None, ai_path: Path | None,
    reserved: tuple[Path, ...], json_stdout: bool,
) -> None:
    if sarif_path == Path("-"):
        raise ValueError("--sarif-output requires a file path")
    if ai_path == Path("-") and json_stdout:
        raise ValueError("--ai-output - cannot be combined with --json")
    paths = [path for path in (sarif_path, ai_path, *reserved) if path is not None and path != Path("-")]
    resolved = [path.resolve() for path in paths]
    if len(resolved) != len(set(resolved)):
        raise ValueError("output paths must be distinct from each other and from report files")


def write_text_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def write_exports(report: dict[str, Any], *, sarif_path: Path | None, ai_path: Path | None) -> str | None:
    if sarif_path is not None:
        write_text_atomic(sarif_path, json.dumps(build_sarif(report, tool_version=PROVTRAIL_VERSION), indent=2) + "\n")
    if ai_path is None:
        return None
    content = format_ai(report)
    if ai_path == Path("-"):
        return content
    write_text_atomic(ai_path, content)
    return None
