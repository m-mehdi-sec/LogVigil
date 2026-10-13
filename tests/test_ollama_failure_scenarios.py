"""Test Ollama failure handling without network access."""

import io
import json
from urllib.error import URLError

import pytest

from soc_assistant.ollama_client import (
    OllamaClientError,
    analyze_with_ollama,
)


AI_REQUEST = {
    "system": "Analyze defensive security telemetry.",
    "user": '{"events":[]}',
    "response_format": "json",
}


class FakeResponse:
    """Simulate an HTTP response from Ollama."""

    def __init__(self, body, status=200):
        self.body = io.BytesIO(body)
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.body.close()

    def getcode(self):
        return self.status

    def read(self, size=-1):
        return self.body.read(size)


def test_connection_failure(monkeypatch):
    def fake_urlopen(request, timeout):
        raise URLError("Connection refused")

    monkeypatch.setattr(
        "soc_assistant.ollama_client.urlopen",
        fake_urlopen,
    )

    with pytest.raises(
        OllamaClientError,
        match="Unable to connect to local Ollama",
    ):
        analyze_with_ollama(AI_REQUEST)


def test_timeout_failure(monkeypatch):
    def fake_urlopen(request, timeout):
        raise TimeoutError("Connection timed out")

    monkeypatch.setattr(
        "soc_assistant.ollama_client.urlopen",
        fake_urlopen,
    )

    with pytest.raises(
        OllamaClientError,
        match="Unable to connect to local Ollama",
    ):
        analyze_with_ollama(AI_REQUEST)


def test_invalid_json_response(monkeypatch):
    def fake_urlopen(request, timeout):
        return FakeResponse(b"not valid JSON")

    monkeypatch.setattr(
        "soc_assistant.ollama_client.urlopen",
        fake_urlopen,
    )

    with pytest.raises(
        OllamaClientError,
        match="Invalid Ollama response",
    ):
        analyze_with_ollama(AI_REQUEST)


def test_http_error(monkeypatch):
    from urllib.error import HTTPError

    def fake_urlopen(request, timeout):
        raise HTTPError(
            request.full_url, 404, "Not Found", {}, None
        )

    monkeypatch.setattr(
        "soc_assistant.ollama_client.urlopen",
        fake_urlopen,
    )

    with pytest.raises(
        OllamaClientError,
        match="Ollama HTTP error: 404",
    ):
        analyze_with_ollama(AI_REQUEST)


def test_incomplete_response(monkeypatch):
    response = {
        "done": False,
        "message": {"content": "{}"},
    }

    def fake_urlopen(request, timeout):
        return FakeResponse(json.dumps(response).encode())

    monkeypatch.setattr(
        "soc_assistant.ollama_client.urlopen",
        fake_urlopen,
    )

    with pytest.raises(
        OllamaClientError,
        match="Invalid Ollama response",
    ):
        analyze_with_ollama(AI_REQUEST)


def test_oversized_response(monkeypatch):
    from soc_assistant.ollama_client import MAX_HTTP_RESPONSE_BYTES

    def fake_urlopen(request, timeout):
        return FakeResponse(b"x" * (MAX_HTTP_RESPONSE_BYTES + 1))

    monkeypatch.setattr(
        "soc_assistant.ollama_client.urlopen",
        fake_urlopen,
    )

    with pytest.raises(
        OllamaClientError,
        match="Ollama response exceeds size limit",
    ):
        analyze_with_ollama(AI_REQUEST)
