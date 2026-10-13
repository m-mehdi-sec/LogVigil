"""Security and robustness tests for the local Ollama client."""

import json
from unittest.mock import patch

import pytest

from soc_assistant.ollama_client import (
    MAX_REQUEST_BYTES,
    OllamaClientError,
    analyze_with_ollama,
)


@pytest.fixture
def request_data():
    return {
        "system": "Analyze defensive SOC evidence.",
        "user": "One authentication finding.",
        "response_format": "json",
    }


def test_rejects_oversized_request(request_data):
    request_data["user"] = "X" * (MAX_REQUEST_BYTES + 1)

    with patch("soc_assistant.ollama_client.urlopen") as mocked:
        with pytest.raises(ValueError, match="size limit"):
            analyze_with_ollama(request_data)

    mocked.assert_not_called()


def test_rejects_model_with_spaces(request_data):
    with patch("soc_assistant.ollama_client.urlopen") as mocked:
        with pytest.raises(ValueError):
            analyze_with_ollama(request_data, model="bad model")

    mocked.assert_not_called()


def test_rejects_model_with_shell_characters(request_data):
    with patch("soc_assistant.ollama_client.urlopen") as mocked:
        with pytest.raises(ValueError):
            analyze_with_ollama(request_data, model="qwen;echo test")

    mocked.assert_not_called()


def test_rejects_empty_model(request_data):
    with pytest.raises(ValueError):
        analyze_with_ollama(request_data, model="")


def test_rejects_infinite_timeout(request_data):
    with pytest.raises(ValueError):
        analyze_with_ollama(request_data, timeout=float("inf"))


def test_rejects_nan_timeout(request_data):
    with pytest.raises(ValueError):
        analyze_with_ollama(request_data, timeout=float("nan"))


def test_rejects_negative_timeout(request_data):
    with pytest.raises(ValueError):
        analyze_with_ollama(request_data, timeout=-1)


def test_rejects_timeout_above_limit(request_data):
    with pytest.raises(ValueError):
        analyze_with_ollama(request_data, timeout=121)


def test_rejects_non_json_response_format(request_data):
    request_data["response_format"] = "text"

    with patch("soc_assistant.ollama_client.urlopen") as mocked:
        with pytest.raises(ValueError):
            analyze_with_ollama(request_data)

    mocked.assert_not_called()


def test_rejects_non_text_user_content(request_data):
    request_data["user"] = {"raw": "unexpected object"}

    with patch("soc_assistant.ollama_client.urlopen") as mocked:
        with pytest.raises(ValueError):
            analyze_with_ollama(request_data)

    mocked.assert_not_called()
