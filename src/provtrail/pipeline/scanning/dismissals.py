"""Project-local human review decisions, independent of detector caches."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from provtrail.pipeline.controller.report_evidence import decision_boundaries, report_boundaries, supports_decision
from provtrail.pipeline.models.result import RegionDetectionResult

DISMISSAL_SCHEMA = "provtrail_dismissals_v1"
ACTIVE_PRIORITIES = {"automatic_vulnerability", "manual_review"}


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def finding_signature(finding: dict[str, Any]) -> str:
    """Bind a review to its decisions, reference evidence and dependency context.

    Unrelated corpus entries and optional model opinions do not invalidate reviews.
    A new supporting boundary or changed dependency assessment does.
    """
    result = finding.get("result") or {}
    relevant = [boundary for boundary in report_boundaries(result)
                if supports_decision(boundary, result.get("priority", "none"))
                or supports_decision(boundary, "manual_review")]
    boundaries = [
        {
            "state": boundary.state,
            "advisories": sorted(boundary.advisories, key=_digest),
            "lineage": {
                key: boundary.lineage.get(key)
                for key in ("lineage_id", "confidence", "repo", "file_path", "reference_function")
            },
            "hash_matches": sorted(boundary.hash_matches, key=_digest),
        }
        for boundary in (relevant or decision_boundaries(result))
    ]
    return _digest({
        "priority": result.get("priority"),
        "decision_policy": result.get("decision_policy"),
        "boundaries": sorted(boundaries, key=_digest),
        "package_applicabilities": sorted(result.get("package_applicabilities") or [], key=_digest),
    })


def finding_id(finding: dict[str, Any]) -> str | None:
    if not all(finding.get(key) for key in ("path", "function_id", "file_hash", "function_hash")):
        return None
    return _digest({
        key: finding.get(key)
        for key in ("path", "function_id", "file_hash", "function_hash", "source_language", "node_type")
    } | {"signature": finding_signature(finding)})


def is_dismissed(finding: dict[str, Any]) -> bool:
    return (finding.get("dismissal") or {}).get("status") == "dismissed"


def active_priority_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    return {priority: sum((item.get("result") or {}).get("priority") == priority and not is_dismissed(item)
                         for item in findings) for priority in sorted(ACTIVE_PRIORITIES)}


def dismissal_path(root: Path | str) -> Path:
    return Path(root) / ".provtrail" / "dismissals.json"


def load_dismissals(root: Path | str) -> list[dict[str, Any]]:
    path = dismissal_path(root)
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema") != DISMISSAL_SCHEMA:
            raise ValueError("unsupported dismissal schema")
        records = payload["dismissals"]
        if not isinstance(records, list):
            raise ValueError("dismissals must be a list")
        ids = set()
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("finding"), dict):
                raise ValueError("invalid dismissal record")
            finding = record["finding"]
            if not all(isinstance(finding.get(key), str) and finding[key]
                       for key in ("path", "function_id", "file_hash", "function_hash")):
                raise ValueError("invalid file/function identity")
            if not all(re.fullmatch(r"[0-9a-f]{64}", finding[key]) for key in ("file_hash", "function_hash")):
                raise ValueError("invalid source hash")
            if not isinstance(finding.get("result"), dict):
                raise ValueError("invalid finding evidence")
            RegionDetectionResult.model_validate(finding["result"])
            if record.get("html_finding") is not None and not isinstance(record["html_finding"], dict):
                raise ValueError("invalid saved HTML evidence")
            identity = finding_id(record["finding"])
            if not identity or identity != record.get("id") or identity in ids:
                raise ValueError("invalid or duplicate dismissal fingerprint")
            if not isinstance(record.get("reason"), str) or not isinstance(record.get("dismissed_at"), str):
                raise ValueError("invalid dismissal metadata")
            datetime.fromisoformat(record["dismissed_at"])
            ids.add(identity)
        return records
    except (OSError, UnicodeError, ValueError, KeyError, TypeError) as exc:
        raise ValueError(f"Unable to read {path}: {exc}") from exc


def save_dismissals(root: Path | str, records: list[dict[str, Any]]) -> None:
    path = dismissal_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    # A unique temporary file avoids collisions with concurrent readers/writers.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            json.dump({"schema": DISMISSAL_SCHEMA, "dismissals": records}, handle, indent=2)
            handle.write("\n")
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def dismissal_lock(root: Path | str) -> Iterator[None]:
    path = dismissal_path(root).with_suffix(".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError as exc:
        raise ValueError(f"Another review command is writing {path}; retry after it finishes") from exc
    try:
        os.close(descriptor)
        yield
    finally:
        path.unlink(missing_ok=True)


def make_dismissal(finding: dict[str, Any], reason: str, html_finding: dict | None = None) -> dict[str, Any]:
    identity = finding_id(finding)
    if not identity:
        raise ValueError("This report has no file/function fingerprints; rescan with the current scanner")
    saved = {key: value for key, value in finding.items() if key not in {"source", "dismissal"}}
    return {
        "id": identity,
        "dismissed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "reason": reason.strip(),
        "finding": saved,
        "html_finding": html_finding,
    }


STATUS_LABELS = {
    "dismissed": "Still applies",
    "file_changed": "File changed",
    "function_changed": "Function changed",
    "finding_changed": "Finding or dependency context changed",
    "file_missing": "File no longer present",
    "no_longer_present": "Finding no longer present",
    "scan_unavailable": "Rescan to verify (scan report unavailable)",
}


def apply_dismissals(
    report: dict[str, Any], records: list[dict[str, Any]], *,
    file_hashes: dict[str, str] | None = None,
    context_signatures: dict[str, str] | None = None,
    scan_available: bool = True,
) -> None:
    """Annotate findings and review history without changing detector verdicts."""
    findings = report.get("findings", [])
    by_function = {(item.get("path"), item.get("function_id")): item for item in findings}
    if file_hashes is None:
        file_hashes = {item["path"]: item.get("file_hash", "") for item in findings}
    for item in findings:
        item.pop("dismissal", None)
        item["finding_id"] = finding_id(item)

    history = []
    for record in records:
        saved = record["finding"]
        current = by_function.get((saved["path"], saved["function_id"]))
        if saved["path"] not in file_hashes:
            status = "file_missing"
        elif file_hashes[saved["path"]] != saved["file_hash"]:
            status = "file_changed"
        elif not scan_available:
            status = "scan_unavailable"
        elif current is None or (current.get("result") or {}).get("priority") not in ACTIVE_PRIORITIES:
            status = "no_longer_present"
        elif current.get("function_hash") != saved["function_hash"]:
            status = "function_changed"
        elif current.get("finding_id") != record["id"] or (
            context_signatures is not None
            and context_signatures.get(current["function_id"]) != finding_signature(saved)
        ):
            status = "finding_changed"
        else:
            status = "dismissed"
        row = {
            "id": record["id"], "status": status, "status_label": STATUS_LABELS[status],
            "reason": record["reason"], "dismissed_at": record["dismissed_at"],
            **{key: saved.get(key) for key in (
                "path", "name", "node_type", "function_id", "start_line", "end_line",
                "source_language", "file_hash", "function_hash",
            )},
            "priority": (saved.get("result") or {}).get("priority"),
            "advisories": [alias for boundary in decision_boundaries(saved.get("result") or {}) for alias in boundary.advisories],
            # Only the HTML artifact receives this saved code/evidence snapshot.
            "html_finding": record.get("html_finding"),
        }
        history.append(row)
        if status == "dismissed":
            current["dismissal"] = {key: row[key] for key in ("id", "status", "reason", "dismissed_at")}

    # Preserve the last review reason for code whose dismissal is outdated.
    for item in findings:
        if is_dismissed(item) or (item.get("result") or {}).get("priority") not in ACTIVE_PRIORITIES:
            continue
        previous = [row for row in history if row["status"] != "dismissed" and row["path"] == item["path"]
                    and (row["function_id"] == item["function_id"] or (
                        row["name"] == item.get("name") and row["node_type"] == item.get("node_type")
                    ))]
        if previous:
            latest = max(previous, key=lambda row: row["dismissed_at"])
            item["dismissal"] = {
                key: latest[key] for key in ("id", "reason", "dismissed_at", "status_label")
            } | {"status": "reopened"}
    report["dismissal_history"] = history
    report["active_priority_counts"] = active_priority_counts(findings)
    report["dismissed_functions"] = sum(is_dismissed(item) for item in findings)


def public_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: value for key, value in row.items() if key != "html_finding"} for row in history]
