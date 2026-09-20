"""Ollama transport for optional review explanations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

import requests
from pydantic import ValidationError

from pipeline.models.explanations import ReviewBrief

DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"
DEFAULT_OLLAMA_MODEL = "qwen3:8b"
DEFAULT_OLLAMA_TIMEOUT = 180.0

class OllamaExplanationError(RuntimeError):
    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class OllamaExplanationConfig:
    model: str = DEFAULT_OLLAMA_MODEL
    host: str = DEFAULT_OLLAMA_HOST
    timeout: float = DEFAULT_OLLAMA_TIMEOUT


def _endpoint(host: str, path: str) -> str:
    if "://" not in host:
        host = f"http://{host}"
    return urljoin(host.rstrip("/") + "/", path.lstrip("/"))


class OllamaClient:
    """Own HTTP calls and provider response handling for review briefs."""

    def __init__(self, config: OllamaExplanationConfig, session: requests.Session | None = None) -> None:
        self.config = config
        self.session = session or requests.Session()

    def available_models(self) -> set[str]:
        try:
            response = self.session.get(
                _endpoint(self.config.host, "/api/tags"), timeout=self.config.timeout,
            )
            response.raise_for_status()
            models = response.json().get("models", [])
        except (requests.RequestException, ValueError, AttributeError) as exc:
            raise OllamaExplanationError("ollama_unavailable", str(exc)) from exc
        return {
            str(model.get("name") or model.get("model") or "")
            for model in models if isinstance(model, dict)
        }

    def review(self, request_body: dict[str, Any]) -> ReviewBrief:
        last_error: OllamaExplanationError | None = None
        for _attempt in range(2):
            try:
                response = self.session.post(
                    _endpoint(self.config.host, "/api/chat"),
                    json=request_body, timeout=self.config.timeout,
                )
                if response.status_code == 404:
                    raise OllamaExplanationError("model_missing", response.text)
                response.raise_for_status()
                content = response.json()["message"]["content"]
                return ReviewBrief.model_validate_json(content)
            except OllamaExplanationError as exc:
                last_error = exc
            except requests.Timeout as exc:
                last_error = OllamaExplanationError("timeout", str(exc))
            except requests.RequestException as exc:
                last_error = OllamaExplanationError("ollama_unavailable", str(exc))
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                last_error = OllamaExplanationError("invalid_response", str(exc))
        assert last_error is not None
        raise last_error
