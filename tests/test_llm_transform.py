import json

import pytest

from eval.tier2.transform import (
    LlmTransformError,
    OllamaCodeTransformer,
    TransformConfig,
)


class _Resp:
    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")

    def json(self):
        return self._payload


class _FakeSession:
    def __init__(self, tags_models, chat_content):
        self.tags_models = tags_models
        self.chat_content = chat_content
        self.posted = []

    def get(self, url, timeout=None):
        return _Resp(payload={"models": [{"name": name} for name in self.tags_models]})

    def post(self, url, json=None, timeout=None):
        self.posted.append({"url": url, "json": json})
        return _Resp(payload={"message": {"content": self.chat_content}})


def test_transform_builds_chat_payload_and_parses_code():
    session = _FakeSession(
        tags_models=["gemma4:e4b", "qwen3:8b"],
        chat_content=json.dumps({"code": "function f(x) { return x + 1; }"}),
    )
    transformer = OllamaCodeTransformer(TransformConfig(model="gemma4:e4b"), session=session)
    transformer.ensure_model_available()

    code = transformer.transform(
        "function g(y){return y+1;}", clone_type="type_3", side="vulnerable", language="javascript"
    )
    assert code == "function f(x) { return x + 1; }"

    posted = session.posted[0]["json"]
    assert posted["model"] == "gemma4:e4b"
    assert posted["stream"] is False
    assert posted["format"]["required"] == ["code"]
    assert posted["messages"][0]["role"] == "system"
    assert "Type-3" in posted["messages"][1]["content"]


def test_type4_and_patched_prompt_flags():
    session = _FakeSession(["gemma4:e4b"], json.dumps({"code": "x"}))
    transformer = OllamaCodeTransformer(TransformConfig(), session=session)
    transformer.transform("code", clone_type="type_4", side="patched", language="typescript")
    user_prompt = session.posted[0]["json"]["messages"][1]["content"]
    assert "Type-4" in user_prompt
    assert "PATCHED" in user_prompt
    assert "Language: typescript" in user_prompt


def test_missing_model_raises():
    session = _FakeSession(["qwen3:8b"], json.dumps({"code": "x"}))
    transformer = OllamaCodeTransformer(TransformConfig(model="gemma4:e4b"), session=session)
    with pytest.raises(LlmTransformError) as excinfo:
        transformer.ensure_model_available()
    assert excinfo.value.reason_code == "model_missing"


def test_extract_code_tolerates_fenced_block():
    session = _FakeSession(["gemma4:e4b"], "```js\nfunction f(){}\n```")
    transformer = OllamaCodeTransformer(TransformConfig(), session=session)
    code = transformer.transform("code", clone_type="type_3", side="vulnerable")
    assert code == "function f(){}"
