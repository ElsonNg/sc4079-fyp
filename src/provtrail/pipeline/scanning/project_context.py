"""Conservative npm project evidence used to assess advisory applicability."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from provtrail.pipeline.detection.priority import derive_priority
from provtrail.pipeline.models.evidence import ApplicabilityEvidence, PackageApplicability
from provtrail.pipeline.models.result import RegionDetectionResult

_IMPORT_RE = re.compile(
    r"(?:\bfrom\s*|\bimport\s*\(?\s*|\brequire\s*\(\s*)['\"]([^'\"]+)['\"]"
)
_DEPENDENCY_SECTIONS = (
    "dependencies", "devDependencies", "peerDependencies", "optionalDependencies"
)


def _package_from_specifier(value: str) -> str | None:
    if not value or value.startswith((".", "/", "node:", "#")):
        return None
    parts = value.split("/")
    return "/".join(parts[:2]) if value.startswith("@") and len(parts) > 1 else parts[0]


@dataclass
class ManifestEvidence:
    path: str
    name: str | None = None
    version: str | None = None
    declarations: dict[str, str] = field(default_factory=dict)


@dataclass
class ProjectEvidenceIndex:
    root: Path
    manifests: list[ManifestEvidence] = field(default_factory=list)
    imports: dict[str, set[str]] = field(default_factory=dict)
    locked: dict[str, str | None] = field(default_factory=dict)

    def _owner(self, relative_path: str) -> ManifestEvidence | None:
        path = Path(relative_path)
        candidates = []
        for manifest in self.manifests:
            parent = Path(manifest.path).parent
            try:
                path.relative_to(parent)
            except ValueError:
                continue
            candidates.append((len(parent.parts), manifest))
        return max(candidates, default=(0, None), key=lambda item: item[0])[1]

    # Scanner calls this for cached and fresh results before exposing a finding.
    def assess(self, result: RegionDetectionResult, relative_path: str) -> RegionDetectionResult:
        owner = self._owner(relative_path)
        parts = Path(relative_path).parts
        imported = set().union(*self.imports.values()) if self.imports else set()
        applications = []
        for value in result.package_applicabilities:
            evidence: list[ApplicabilityEvidence] = []
            status = "unknown"
            package = value.package
            if "node_modules" in parts:
                index = len(parts) - 1 - list(reversed(parts)).index("node_modules")
                tail = parts[index + 1 :]
                actual = "/".join(tail[:2]) if tail and tail[0].startswith("@") else (tail[0] if tail else "")
                status = "confirmed" if actual == package else "conflicting"
                evidence.append(ApplicabilityEvidence(
                    kind="package_ownership", source=relative_path, package=actual or None,
                    detail="candidate file is owned by an installed package",
                ))
            elif owner and owner.name == package:
                status = "confirmed"
                evidence.append(ApplicabilityEvidence(
                    kind="package_ownership", source=owner.path, package=owner.name,
                    version=owner.version,
                ))
            elif any(segment in {"vendor", "vendored"} for segment in parts):
                normalized = package.replace("/", "-")
                if package in parts or normalized in parts:
                    status = "confirmed"
                    evidence.append(ApplicabilityEvidence(
                        kind="vendored_path", source=relative_path, package=package,
                    ))
            declarations = [
                manifest for manifest in self.manifests if package in manifest.declarations
            ]
            if status == "unknown" and declarations and (package in imported or package in self.locked):
                status = "confirmed"
                manifest = declarations[0]
                evidence.append(ApplicabilityEvidence(
                    kind="resolved_dependency", source=manifest.path, package=package,
                    version=self.locked.get(package) or manifest.declarations.get(package),
                    detail="declared package is imported or present in a lockfile",
                ))
            elif status == "unknown" and declarations:
                evidence.append(ApplicabilityEvidence(
                    kind="manifest_declaration", source=declarations[0].path,
                    package=package, version=declarations[0].declarations.get(package),
                    detail="declaration alone does not prove candidate ownership",
                ))
            applications.append(value.model_copy(update={"status": status, "evidence": evidence}))
        priority = derive_priority(result.lineages, result.vulnerability_states, applications)
        return result.model_copy(update={
            "package_applicabilities": applications,
            "priority": priority,
        })


def _read_manifest(root: Path, path: Path) -> ManifestEvidence | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return None
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None
    declarations = {}
    for section in _DEPENDENCY_SECTIONS:
        values = value.get(section)
        if isinstance(values, dict):
            declarations.update({str(name): str(version) for name, version in values.items()})
    return ManifestEvidence(
        path=str(path.relative_to(root)),
        name=str(value.get("name") or "").strip() or None,
        version=str(value.get("version") or "").strip() or None,
        declarations=declarations,
    )


# Scan_directory builds this once to assess all functions against current project files.
def build_project_evidence(root: Path, js_files: list[str]) -> ProjectEvidenceIndex:
    manifests = []
    for path in root.rglob("package.json"):
        relative = path.relative_to(root)
        if any(part in {".git", ".provtrail"} for part in relative.parts):
            continue
        manifest = _read_manifest(root, path)
        if manifest:
            manifests.append(manifest)
    imports = {}
    for relative in js_files:
        try:
            source = (root / relative).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        values = {
            package for specifier in _IMPORT_RE.findall(source)
            if (package := _package_from_specifier(specifier))
        }
        if values:
            imports[relative] = values
    locked: dict[str, str | None] = {}
    package_lock = root / "package-lock.json"
    try:
        payload = json.loads(package_lock.read_text(encoding="utf-8"))
        for key, value in (payload.get("packages") or {}).items():
            if not key.startswith("node_modules/") or not isinstance(value, dict):
                continue
            name = key.removeprefix("node_modules/")
            locked[name] = str(value.get("version") or "").strip() or None
    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
        pass
    for filename in ("yarn.lock", "pnpm-lock.yaml"):
        path = root / filename
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for manifest in manifests:
            for package in manifest.declarations:
                if package in source:
                    locked.setdefault(package, None)
    return ProjectEvidenceIndex(root=root, manifests=manifests, imports=imports, locked=locked)
