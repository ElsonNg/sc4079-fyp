"""Download and safely unpack npm release tarballs for static-only evaluation.

This module exists for the Tier-1 self-check benchmark, which scans the real npm
releases the corpus points at. Nothing here executes package code: it downloads a
tarball, verifies its sha256 against the corpus-recorded digest, and extracts it
with an explicit path-traversal / link / size guard. The extracted tree is only
ever read (tree-sitter parsed) by the scanner, never installed or run.

The stdlib ``tarfile`` PEP-706 ``filter=`` argument is deliberately NOT relied on:
it is absent on Python < 3.11.4 (the evaluation venv is 3.11.3), so every member is
validated explicitly instead.
"""

from __future__ import annotations

import hashlib
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path

import requests

# Guard limits: a legitimate npm package is far smaller than these. They exist to
# stop a hostile tarball from filling the disk (tar bomb) during extraction.
MAX_MEMBER_COUNT = 50_000
MAX_TOTAL_UNCOMPRESSED_BYTES = 512 * 1024 * 1024  # 512 MiB across the whole archive
DEFAULT_DOWNLOAD_TIMEOUT = 120.0


class SandboxFetchError(RuntimeError):
    def __init__(self, reason_code: str, detail: str = "") -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)


@dataclass(frozen=True)
class ExtractionReport:
    dest: Path
    files_written: int
    total_bytes: int
    skipped_members: list[str]


def download_release(
    url: str,
    expected_sha256: str,
    *,
    session: requests.Session | None = None,
    timeout: float = DEFAULT_DOWNLOAD_TIMEOUT,
) -> bytes:
    """Download tarball bytes and verify them against the corpus-recorded digest.

    Raises SandboxFetchError on any network failure or hash mismatch. The digest
    check happens before the bytes are ever handed to an extractor, so a tampered
    or wrong artifact is rejected without being unpacked.
    """
    if not expected_sha256:
        raise SandboxFetchError("missing_expected_sha256", url)
    client = session or requests.Session()
    try:
        response = client.get(url, timeout=timeout)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise SandboxFetchError("download_failed", f"{url}: {exc}") from exc
    data = response.content
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256:
        raise SandboxFetchError(
            "sha256_mismatch",
            f"{url}: expected {expected_sha256}, got {actual}",
        )
    return data


# Built-output directory names dropped when a package also ships authoring source
# (src/ or lib/). These hold bundled/duplicated/minified copies that make an
# in-distribution self-check slow and off-target (minification is Tier 3's job).
_BUILT_DIR_NAMES = {
    "dist", "build", "umd", "amd", "esm", "es", "_esm5", "_esm2015",
    "bundles", "_bundles", "module", "lib-esm",
}
_SOURCE_DIR_NAMES = {"src", "lib"}
# Directories that are never the shipped library surface. Dropped unconditionally so
# a Tier-1 self-check scans the package's own source rather than its tests, examples,
# generated bundles or docs. A vulnerability whose fix lives only in one of these is
# separately marked tier1_applicable=false at label time (see build_tier1_targets).
_NON_LIBRARY_DIR_NAMES = {
    "test", "tests", "spec", "specs", "__tests__", "__test__", "e2e",
    "example", "examples", "demo", "demos", "sample", "samples",
    "integration", "integration-testing", "benchmark", "benchmarks", "bench",
    "fixture", "fixtures", "coverage", "docs", "doc", "website", "scripts",
    # Third-party code bundled into a release: never the package's own vuln surface.
    "vendor", "vendored", "third_party", "third-party",
}
# A .js/.ts line longer than this is almost certainly bundled/minified, not authored.
_BUNDLE_LINE_THRESHOLD = 2000


@dataclass(frozen=True)
class PruneReport:
    removed_dirs: list[str]
    removed_files: list[str]


def _looks_bundled(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            return any(len(line) > _BUNDLE_LINE_THRESHOLD for line in handle)
    except OSError:
        return False


def prune_built_artifacts(dest_dir: Path) -> PruneReport:
    """Reduce an extracted package tree to its authoring library source for a Tier-1
    self-check scan. Removes: non-library dirs (tests/examples/docs/bundles) always;
    built-output dirs (dist/build/...) when the package root also ships src/ or lib/;
    ``*.min.*`` and ``*.d.ts`` files; and any surviving bundled/minified-looking file
    (a very long line). Purely deletes files on an already-sandboxed tree — runs
    nothing.
    """
    import shutil

    dest_dir = Path(dest_dir)
    removed_dirs: list[str] = []
    removed_files: list[str] = []

    # Non-library directories, anywhere in the tree.
    for directory in sorted(dest_dir.rglob("*"), key=lambda p: len(p.parts), reverse=True):
        if directory.is_dir() and directory.name.lower() in _NON_LIBRARY_DIR_NAMES:
            shutil.rmtree(directory, ignore_errors=True)
            removed_dirs.append(str(directory.relative_to(dest_dir)))

    # Built-output dirs next to real source, per package root (has package.json).
    for manifest in dest_dir.rglob("package.json"):
        root = manifest.parent
        if not root.exists():
            continue
        children = {child.name for child in root.iterdir() if child.is_dir()}
        if not (children & _SOURCE_DIR_NAMES):
            continue
        for built in _BUILT_DIR_NAMES & children:
            target = root / built
            if target.is_dir():
                shutil.rmtree(target, ignore_errors=True)
                removed_dirs.append(str(target.relative_to(dest_dir)))

    # Minified / declaration / bundled files anywhere that survived.
    for path in list(dest_dir.rglob("*")):
        if not path.is_file():
            continue
        name = path.name.lower()
        if name.endswith((".min.js", ".min.mjs", ".min.cjs", ".d.ts")):
            path.unlink(missing_ok=True)
            removed_files.append(str(path.relative_to(dest_dir)))
        elif name.endswith((".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts")) and _looks_bundled(path):
            path.unlink(missing_ok=True)
            removed_files.append(str(path.relative_to(dest_dir)))

    return PruneReport(removed_dirs=removed_dirs, removed_files=removed_files)


def _is_safe_member(member: tarfile.TarInfo, dest_root: Path) -> tuple[bool, str]:
    """Return (ok, reason). A member is safe only if it is a regular file or dir
    that resolves strictly under dest_root. Symlinks, hardlinks and device/fifo
    nodes are always rejected."""
    if member.issym() or member.islnk():
        return False, "link_member"
    if not (member.isfile() or member.isdir()):
        return False, "special_member"
    name = member.name.replace("\\", "/")
    if name.startswith("/") or Path(name).is_absolute():
        return False, "absolute_path"
    # Resolve the target without touching the filesystem and confirm containment.
    resolved = (dest_root / name).resolve()
    try:
        resolved.relative_to(dest_root.resolve())
    except ValueError:
        return False, "path_escape"
    return True, ""


def safe_extract_tarball(data: bytes, dest_dir: Path) -> ExtractionReport:
    """Extract a gzip tarball into dest_dir with an explicit safety guard.

    Rejects path traversal (``..`` / absolute paths escaping dest_dir), symlink and
    hardlink members, device/fifo nodes, and enforces file-count and total-size
    caps. Directories are created; regular files are written from their read
    stream. Never calls TarInfo.extract/extractall (which would honour unsafe
    members); writes bytes manually instead.
    """
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest_root = dest_dir.resolve()

    files_written = 0
    total_bytes = 0
    skipped: list[str] = []

    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:gz")
    except tarfile.TarError as exc:
        raise SandboxFetchError("tarball_invalid", str(exc)) from exc

    with archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBER_COUNT:
            raise SandboxFetchError("too_many_members", str(len(members)))
        for member in members:
            ok, reason = _is_safe_member(member, dest_root)
            if not ok:
                skipped.append(f"{reason}:{member.name}")
                continue
            target = (dest_root / member.name.replace("\\", "/")).resolve()
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            total_bytes += max(member.size, 0)
            if total_bytes > MAX_TOTAL_UNCOMPRESSED_BYTES:
                raise SandboxFetchError("archive_too_large", str(total_bytes))
            stream = archive.extractfile(member)
            if stream is None:
                skipped.append(f"unreadable:{member.name}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("wb") as handle:
                handle.write(stream.read())
            files_written += 1

    return ExtractionReport(
        dest=dest_dir,
        files_written=files_written,
        total_bytes=total_bytes,
        skipped_members=skipped,
    )
