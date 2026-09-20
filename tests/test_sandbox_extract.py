import hashlib
import io
import tarfile

import pytest

from provtrail.corpus.integrations.sandbox_fetch import (
    SandboxFetchError,
    download_release,
    prune_built_artifacts,
    safe_extract_tarball,
)


def _tar_gz(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for info, payload in members:
            if payload is None:
                archive.addfile(info)
            else:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def test_extracts_normal_member_and_rejects_traversal_and_symlink(tmp_path):
    good = tarfile.TarInfo("package/index.js")
    escape = tarfile.TarInfo("../escape.js")
    absolute = tarfile.TarInfo("/etc/evil.js")
    link = tarfile.TarInfo("package/link.js")
    link.type = tarfile.SYMTYPE
    link.linkname = "../../../../etc/passwd"

    data = _tar_gz(
        [
            (good, b"export const x = 1;\n"),
            (escape, b"malicious\n"),
            (absolute, b"malicious\n"),
            (link, None),
        ]
    )

    report = safe_extract_tarball(data, tmp_path / "out")

    assert (tmp_path / "out" / "package" / "index.js").read_text() == "export const x = 1;\n"
    assert not (tmp_path / "escape.js").exists()
    assert report.files_written == 1
    reasons = {entry.split(":", 1)[0] for entry in report.skipped_members}
    assert "path_escape" in reasons
    assert "absolute_path" in reasons
    assert "link_member" in reasons


def test_download_release_rejects_sha256_mismatch():
    payload = b"tarball-bytes"

    class _Resp:
        status_code = 200
        content = payload

        def raise_for_status(self):
            return None

    class _Session:
        def get(self, url, timeout=None):
            return _Resp()

    correct = hashlib.sha256(payload).hexdigest()
    # Correct hash returns bytes unchanged.
    assert download_release("http://x/y.tgz", correct, session=_Session()) == payload
    # Wrong hash is rejected before any extraction.
    with pytest.raises(SandboxFetchError) as excinfo:
        download_release("http://x/y.tgz", "0" * 64, session=_Session())
    assert excinfo.value.reason_code == "sha256_mismatch"


def test_prune_drops_built_dirs_and_minified_but_keeps_source(tmp_path):
    root = tmp_path / "package"
    (root / "lib").mkdir(parents=True)
    (root / "dist").mkdir(parents=True)
    (root / "package.json").write_text('{"name":"demo"}')
    (root / "lib" / "index.js").write_text("function real() { return 1; }")
    (root / "dist" / "bundle.js").write_text("built")
    (root / "dist" / "bundle.min.js").write_text("min")
    (root / "index.d.ts").write_text("export declare const x: number;")

    report = prune_built_artifacts(tmp_path)

    assert (root / "lib" / "index.js").exists()
    assert not (root / "dist").exists()
    assert not (root / "index.d.ts").exists()
    assert any("dist" in name for name in report.removed_dirs)


def test_prune_keeps_dist_when_no_source_dir(tmp_path):
    root = tmp_path / "package"
    (root / "dist").mkdir(parents=True)
    (root / "package.json").write_text('{"name":"demo"}')
    (root / "dist" / "index.js").write_text("function only() {}")
    (root / "dist" / "index.min.js").write_text("min")

    prune_built_artifacts(tmp_path)

    # No src/lib, so dist is the only source form and must be kept...
    assert (root / "dist" / "index.js").exists()
    # ...but the minified copy is always dropped.
    assert not (root / "dist" / "index.min.js").exists()


def test_extract_round_trips_a_realistic_package(tmp_path):
    files = {
        "package/package.json": b'{"name":"demo","version":"1.0.0"}',
        "package/lib/http.js": b"function setProxy(){ return 1; }\n",
        "package/README.md": b"# demo\n",
    }
    members = [(tarfile.TarInfo(name), body) for name, body in files.items()]
    report = safe_extract_tarball(_tar_gz(members), tmp_path / "pkg")
    assert report.files_written == 3
    assert (tmp_path / "pkg" / "package" / "lib" / "http.js").exists()
