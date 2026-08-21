import json

import requests

from pipeline.controller.review_explanation import (
    MAX_SNIPPET_CHARACTERS,
    OllamaExplanationConfig,
    OllamaExplanationError,
    OllamaReviewExplainer,
    _complete_project_function,
    _explanation_input,
    _snippet_payload,
    enrich_manual_review_findings,
)
from pipeline.controller.scanning import ScanConfig, ScanSummary


BRIEF = {
    "relevance_tier": 2,
    "verdict_rationale": "A request sink is present, but redirect validation is outside the region.",
    "security_mechanism": "Caller-controlled redirect destinations must be validated before requests.",
}


class FakeResponse:
    def __init__(self, payload, *, status_code=200, text=""):
        self.payload = payload
        self.status_code = status_code
        self.text = text

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


class FakeSession:
    def __init__(self, *, posts=None, models=None, get_error=None):
        self.posts = list(posts or [])
        self.models = models if models is not None else [{"name": "qwen3:8b"}]
        self.get_error = get_error
        self.get_calls = []
        self.post_calls = []

    def get(self, url, *, timeout):
        self.get_calls.append((url, timeout))
        if self.get_error:
            raise self.get_error
        return FakeResponse({"models": self.models})

    def post(self, url, *, json, timeout):
        self.post_calls.append((url, json, timeout))
        response = self.posts.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _summary():
    return ScanSummary(
        target_root="/tmp/demo",
        root_hash="root",
        previous_root_hash=None,
        changed_files=["src/request.js"],
        deleted_files=[],
        scanned_files=["src/request.js"],
        total_files=1,
        total_functions=1,
        scanned_functions=1,
        reused_functions=0,
        priority_counts={"manual_review": 1},
        findings=[
            {
                "function_id": "src/request.js::0:42",
                "path": "src/request.js",
                "name": "request",
                "start_line": 0,
                "end_line": 2,
                "source": "function request(url) { return fetch(url); }",
                "result": {"priority": "manual_review"},
            }
        ],
        state_path="/tmp/demo/.provtrail/scan-state.json",
    )


def _normalized_finding():
    return {
        "id": "src/request.js::0:42",
        "priority": "manual_review",
        "path": "src/request.js",
        "name": "request",
        "start_line": 1,
        "end_line": 3,
        "message": "Conflicting vulnerable and patched signals",
        "confidence": "ambiguous",
        "parser_supported": True,
        "severity": "high",
        "primary": {
            "identifier": "CVE-2026-1234",
            "title": "Redirect validation can be bypassed",
            "cwes": ["CWE-918"],
            "package_name": "demo-http",
            "affected_versions": ["< 2.0.0"],
            "fixed_versions": ["2.0.0"],
            "patch_changes": {"removed": ["fetch(url)"], "added": ["validate(url)"]},
        },
        "evidence": {
            "retrieval_similarity": 0.87,
            "vulnerable_score": 0.82,
            "patched_score": 0.78,
            "vulnerable_minus_patched": 0.04,
        },
        "reference": {
            "candidate": {
                "lines": [{"number": 1, "text": "return fetch(url);", "marker": "detected"}],
                "truncated": False,
            },
            "vulnerable": None,
            "patched": None,
        },
    }


def test_ollama_request_uses_structured_non_streaming_chat():
    session = FakeSession(
        posts=[FakeResponse({"message": {"content": json.dumps(BRIEF)}})]
    )
    explainer = OllamaReviewExplainer(
        OllamaExplanationConfig(host="localhost:11434", timeout=12), session=session
    )

    brief = explainer.explain({"source_evidence": {"project": "untrusted code"}})

    assert brief.verdict_rationale == BRIEF["verdict_rationale"]
    url, body, timeout = session.post_calls[0]
    assert url == "http://localhost:11434/api/chat"
    assert timeout == 12
    assert body["model"] == "qwen3:8b"
    assert body["stream"] is False
    assert body["think"] is False
    assert body["options"]["temperature"] == 0
    assert body["format"]["required"]
    assert "untrusted code" in body["messages"][1]["content"]


def test_invalid_ollama_response_is_retried_once():
    session = FakeSession(
        posts=[
            FakeResponse({"message": {"content": "not json"}}),
            FakeResponse({"message": {"content": json.dumps(BRIEF)}}),
        ]
    )

    brief = OllamaReviewExplainer(OllamaExplanationConfig(), session=session).explain({})

    assert brief.relevance_tier == 2
    assert len(session.post_calls) == 2


def test_timeout_after_retry_has_stable_error_code():
    session = FakeSession(posts=[requests.Timeout("slow"), requests.Timeout("slow")])

    try:
        OllamaReviewExplainer(OllamaExplanationConfig(), session=session).explain({})
    except OllamaExplanationError as exc:
        assert exc.code == "timeout"
    else:
        raise AssertionError("expected OllamaExplanationError")


def test_explanations_are_attached_and_reused_from_content_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "pipeline.controller.review_explanation.build_html_report_data",
        lambda *_args, **_kwargs: {"findings": [_normalized_finding()]},
    )
    cache_path = tmp_path / "review-explanations.json"
    first_summary = _summary()
    first_session = FakeSession(
        posts=[FakeResponse({"message": {"content": json.dumps(BRIEF)}})]
    )

    first = enrich_manual_review_findings(
        first_summary,
        entries=[],
        scan_config=ScanConfig(),
        ollama_config=OllamaExplanationConfig(),
        cache_path=cache_path,
        session=first_session,
    )

    assert first.generated == 1
    assert first_summary.findings[0]["review_explanation"]["status"] == "generated"
    assert first_summary.findings[0]["review_explanation"]["llm_verdict"] == "needs_review"
    assert cache_path.exists()

    second_summary = _summary()
    second_session = FakeSession()
    second = enrich_manual_review_findings(
        second_summary,
        entries=[],
        scan_config=ScanConfig(),
        ollama_config=OllamaExplanationConfig(),
        cache_path=cache_path,
        session=second_session,
    )

    assert second.reused == 1
    assert second.generated == 0
    assert second_session.get_calls == []
    assert second_session.post_calls == []


def test_unavailable_ollama_does_not_fail_scan_or_poison_cache(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "pipeline.controller.review_explanation.build_html_report_data",
        lambda *_args, **_kwargs: {"findings": [_normalized_finding()]},
    )
    summary = _summary()
    warnings = []
    cache_path = tmp_path / "review-explanations.json"

    stats = enrich_manual_review_findings(
        summary,
        entries=[],
        scan_config=ScanConfig(),
        ollama_config=OllamaExplanationConfig(),
        cache_path=cache_path,
        session=FakeSession(get_error=requests.ConnectionError("offline")),
        warning_callback=warnings.append,
    )

    assert stats.unavailable == 1
    assert summary.findings[0]["result"]["priority"] == "manual_review"
    assert summary.findings[0]["review_explanation"]["error_code"] == "ollama_unavailable"
    assert warnings == ["offline"]
    assert not cache_path.exists()


def test_prompt_snippets_have_a_hard_character_bound():
    payload = _snippet_payload(
        {
            "lines": [
                {"number": 1, "text": "a" * MAX_SNIPPET_CHARACTERS, "marker": "detected"},
                {"number": 2, "text": "more", "marker": None},
            ],
            "truncated": False,
        }
    )

    assert sum(len(line["text"]) for line in payload["lines"]) == MAX_SNIPPET_CHARACTERS
    assert payload["truncated"] is True
    assert payload["scope"] == "function_truncated_at_safety_limit"
    assert payload["lines"][0]["in_detected_region"] is True
    assert payload["detected_region_lines"] == [1]


def test_complete_project_function_marks_region_without_dropping_context():
    source = "function request(url) {\n  const target = normalize(url);\n  return fetch(target);\n}"
    raw = {
        "function_id": "src/request.js::0:80",
        "start_line": 9,
        "source": source,
    }
    normalized = {
        "evidence": {"candidate_region_id": "missing-region"},
        "reference": {"candidate": None},
    }

    payload = _snippet_payload(_complete_project_function(raw, normalized))

    assert payload["scope"] == "complete_function"
    assert [line["text"] for line in payload["lines"]] == source.splitlines()
    assert payload["detected_region_lines"] == [10, 11, 12, 13]
    assert all(line["in_detected_region"] for line in payload["lines"])


def test_project_function_input_is_not_truncated_by_reference_snippet_limit():
    finding = _normalized_finding()
    project_function = {
        "lines": [
            {"number": 1, "text": "x" * (MAX_SNIPPET_CHARACTERS + 1), "marker": "detected"}
        ],
        "truncated": False,
    }

    payload = _explanation_input(finding, project_function=project_function)

    project = payload["source_evidence"]["project_function"]
    assert len(project["lines"][0]["text"]) == MAX_SNIPPET_CHARACTERS + 1
    assert project["scope"] == "complete_function"


def test_prompt_is_an_independent_three_tier_security_review():
    session = FakeSession(
        posts=[FakeResponse({"message": {"content": json.dumps(BRIEF)}})]
    )
    OllamaReviewExplainer(OllamaExplanationConfig(), session=session).explain(
        {"source_evidence": {"project": "generic helper"}}
    )

    prompt = "\n".join(message["content"] for message in session.post_calls[0][1]["messages"])
    assert "1 — Totally irrelevant" in prompt
    assert "2 — Potentially relevant" in prompt
    assert "3 — Definitely relevant" in prompt
    assert "independent second opinion" in prompt
    assert "complete project function block" in prompt
    assert "in_detected_region=true" in prompt
    assert "__proto__" in prompt
    assert "Do not discuss, infer, justify, or repeat detector scores" in prompt


def test_second_opinion_input_excludes_detector_scores_and_status():
    finding = _normalized_finding()
    finding["evidence"] = {
        "retrieval_similarity": 0.99,
        "vulnerable_score": 0.98,
        "patched_score": 0.02,
        "vulnerable_minus_patched": 0.96,
    }

    payload = _explanation_input(finding)
    encoded = json.dumps(payload)

    assert "deterministic_evidence" not in payload
    assert "deterministic_status" not in encoded
    assert "retrieval_similarity" not in encoded
    assert "vulnerable_score" not in encoded
    assert "severity" not in encoded
    assert payload["advisory"]["identifier"] == "CVE-2026-1234"


def test_flagged_findings_do_not_invoke_second_opinion(monkeypatch, tmp_path):
    normalized = _normalized_finding()
    normalized["priority"] = "automatic_vulnerability"
    monkeypatch.setattr(
        "pipeline.controller.review_explanation.build_html_report_data",
        lambda *_args, **_kwargs: {"findings": [normalized]},
    )
    summary = _summary()
    summary.findings[0]["result"]["priority"] = "automatic_vulnerability"
    session = FakeSession()

    stats = enrich_manual_review_findings(
        summary,
        entries=[],
        scan_config=ScanConfig(),
        ollama_config=OllamaExplanationConfig(),
        cache_path=tmp_path / "review-explanations.json",
        session=session,
    )

    assert stats.generated == 0
    assert stats.reused == 0
    assert stats.unavailable == 0
    assert summary.findings[0]["result"]["priority"] == "automatic_vulnerability"
    assert "review_explanation" not in summary.findings[0]
    assert session.get_calls == []
    assert session.post_calls == []
