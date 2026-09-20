import base64
import runpy
import threading
from pathlib import Path

import pytest

from corpus.integrations import github
from corpus.integrations.github import fetch_file_content, fetch_source_tree


@pytest.mark.parametrize("environment_token", [None, "environment-token"])
def test_github_loads_project_dotenv_without_overriding_environment(tmp_path, monkeypatch, environment_token):
    project = tmp_path / "project"
    client = project / "corpus" / "controller" / "github.py"
    client.parent.mkdir(parents=True)
    client.write_text(Path(github.__file__).read_text(encoding="utf-8"), encoding="utf-8")
    (project / ".env").write_text("GITHUB_TOKEN=dotenv-token\n", encoding="utf-8")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    if environment_token:
        monkeypatch.setenv("GITHUB_TOKEN", environment_token)
    monkeypatch.chdir(tmp_path)

    module = runpy.run_path(str(client))

    assert module["_github_headers"]()["Authorization"] == f"Bearer {environment_token or 'dotenv-token'}"


class FakeResponse:
    def __init__(self, payload, status_code=200, headers=None):
        self._payload = payload
        self.status_code = status_code
        self.headers = headers or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    @property
    def content(self):
        return self._payload if isinstance(self._payload, bytes) else b""


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self.responses.pop(0)


def _blob(content: str) -> dict:
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    return {"encoding": "base64", "content": encoded}


def test_fetch_file_content_falls_back_to_git_blob_for_large_file():
    session = FakeSession([
        FakeResponse({"encoding": "none", "content": "", "sha": "blob123"}),
        FakeResponse(_blob("export const large = true;\n")),
    ])

    content = fetch_file_content("acme", "widget", "dist/large.js", "commit1", session)

    assert content == "export const large = true;\n"
    assert session.calls[1][0].endswith("/repos/acme/widget/git/blobs/blob123")


def test_fetch_source_tree_reads_raw_files_without_contents_api():
    session = FakeSession([
        FakeResponse({
            "truncated": False,
            "tree": [
                {"path": "src/index.js", "type": "blob", "sha": "source123"},
                {"path": "tests/index.js", "type": "blob", "sha": "test123"},
                {"path": "README.md", "type": "blob", "sha": "readme123"},
            ],
        }),
        FakeResponse(b"export function run() {}\n"),
    ])

    sources = fetch_source_tree("acme", "widget", "commit1", session=session)

    assert sources == {"src/index.js": "export function run() {}\n"}
    assert len(session.calls) == 2
    assert session.calls[1][0].endswith("/acme/widget/commit1/src/index.js")


def test_fetch_source_tree_parallelizes_and_skips_only_large_background(monkeypatch):
    session = FakeSession([FakeResponse({
        "truncated": False,
        "tree": [
            {"path": "src/target.js", "type": "blob", "sha": "target", "size": 2_000_000},
            {"path": "src/small.js", "type": "blob", "sha": "small", "size": 100},
            {"path": "src/large.js", "type": "blob", "sha": "large", "size": 2_000_000},
        ],
    })])
    barrier = threading.Barrier(2)
    worker_threads = set()

    def fake_fetch_raw(_owner, _repo, path, _ref, **_kwargs):
        worker_threads.add(threading.get_ident())
        barrier.wait(timeout=2)
        return f"// {path}\n"

    monkeypatch.setattr(github, "fetch_raw_file_content", fake_fetch_raw)

    sources = fetch_source_tree(
        "acme",
        "widget",
        "commit1",
        required_paths={"src/target.js"},
        max_background_blob_bytes=1_000_000,
        max_workers=2,
        session=session,
    )

    assert sources == {
        "src/target.js": "// src/target.js\n",
        "src/small.js": "// src/small.js\n",
    }
    assert len(worker_threads) == 2


def test_fetch_source_tree_file_cap_always_reserves_required_paths(monkeypatch):
    session = FakeSession([FakeResponse({
        "truncated": False,
        "tree": [
            {"path": "src/a.js", "type": "blob", "sha": "a", "size": 10},
            {"path": "src/b.js", "type": "blob", "sha": "b", "size": 10},
            {"path": "src/required.js", "type": "blob", "sha": "required", "size": 10},
        ],
    })])
    monkeypatch.setattr(
        github, "fetch_raw_file_content",
        lambda _owner, _repo, path, _ref, **_kwargs: f"// {path}\n",
    )

    sources = fetch_source_tree(
        "acme", "widget", "commit1", required_paths={"src/required.js"},
        max_files=1, session=session,
    )

    assert sources == {"src/required.js": "// src/required.js\n"}


def test_secondary_rate_limit_uses_retry_after_header():
    response = FakeResponse(
        {"message": "You have exceeded a secondary rate limit."},
        status_code=403,
        headers={"Retry-After": "12"},
    )

    assert github._rate_limit_delay(response, attempt=0) == 13.0
