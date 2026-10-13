"""Tests for the local-only Ollama client."""

import json
from io import BytesIO
from unittest.mock import patch
from urllib.error import URLError

import pytest

from soc_assistant.ollama_client import (
    OllamaClientError,
    analyze_with_ollama,
)


AI_REQUEST = {
    "system": "Analyze defensive security telemetry.",
    "user": "Analyze this JSON data.",
    "response_format": "json",
}

AI_RESPONSE = {
    "risk_level": "high",
    "observations": ["Multiple failed logins"],
    "hypotheses": ["Possible brute-force activity"],
    "recommended_actions": ["Review authentication logs"],
}


class FakeResponse:
    def __init__(self, payload):
        self.stream = BytesIO(payload)

    def getcode(self):
        return 200

    def read(self, size=-1):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def mock_ollama_response(content):
    payload = {
        "done": True,
        "message": {
            "content": content,
        }
    }
    return FakeResponse(json.dumps(payload).encode("utf-8"))


def test_valid_ollama_response():
    fake = mock_ollama_response(json.dumps(AI_RESPONSE))

    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=fake,
    ):
        result = analyze_with_ollama(AI_REQUEST)

    assert result == AI_RESPONSE


def test_request_uses_localhost():
    fake = mock_ollama_response(json.dumps(AI_RESPONSE))

    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=fake,
    ) as mocked:
        analyze_with_ollama(AI_REQUEST)

    request = mocked.call_args.args[0]

    assert request.full_url == (
        "http://127.0.0.1:11434/api/chat"
    )


def test_request_disables_streaming():
    fake = mock_ollama_response(json.dumps(AI_RESPONSE))

    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=fake,
    ) as mocked:
        analyze_with_ollama(AI_REQUEST)

    payload = json.loads(mocked.call_args.args[0].data)

    assert payload["stream"] is False
    assert payload["format"] == "json"


def test_request_uses_separate_roles():
    fake = mock_ollama_response(json.dumps(AI_RESPONSE))

    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=fake,
    ) as mocked:
        analyze_with_ollama(AI_REQUEST)

    payload = json.loads(mocked.call_args.args[0].data)

    assert payload["messages"][0]["role"] == "system"
    assert payload["messages"][1]["role"] == "user"


def test_connection_failure():
    with patch(
        "soc_assistant.ollama_client.urlopen",
        side_effect=URLError("Connection refused"),
    ):
        with pytest.raises(
            OllamaClientError,
            match="Unable to connect",
        ):
            analyze_with_ollama(AI_REQUEST)


def test_invalid_json_response():
    fake = FakeResponse(b"not valid JSON")

    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=fake,
    ):
        with pytest.raises(
            OllamaClientError,
            match="Invalid Ollama response",
        ):
            analyze_with_ollama(AI_REQUEST)


def test_invalid_ai_content():
    fake = mock_ollama_response(
        json.dumps({"risk_level": "high"})
    )

    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=fake,
    ):
        with pytest.raises(OllamaClientError):
            analyze_with_ollama(AI_REQUEST)


def test_response_size_limit():
    fake = FakeResponse(b"x" * 65537)

    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=fake,
    ):
        with pytest.raises(
            OllamaClientError,
            match="size limit",
        ):
            analyze_with_ollama(AI_REQUEST)


def test_invalid_model_rejected():
    with pytest.raises(ValueError):
        analyze_with_ollama(AI_REQUEST, model="")


def test_invalid_timeout_rejected():
    for timeout in (0, -1, 121, True):
        with pytest.raises(ValueError):
            analyze_with_ollama(AI_REQUEST, timeout=timeout)
