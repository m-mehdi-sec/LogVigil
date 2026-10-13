"""HTTP robustness tests for local Ollama communication."""

import io
import json
from urllib.error import HTTPError, URLError
from unittest.mock import patch

import pytest

from soc_assistant.ollama_client import (
    MAX_HTTP_RESPONSE_BYTES,
    OllamaClientError,
    analyze_with_ollama,
)


class FakeResponse:
    def __init__(self, content):
        self.stream = io.BytesIO(content)

    def getcode(self):
        return 200

    def read(self, size=-1):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.stream.close()


@pytest.fixture
def request_data():
    return {
        "system": "Analyze defensive SOC evidence.",
        "user": "Synthetic authentication events.",
        "response_format": "json",
    }


def run_with_response(request_data, content):
    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=FakeResponse(content),
    ):
        return analyze_with_ollama(request_data)


def test_http_401_is_handled(request_data):
    error = HTTPError(
        "http://127.0.0.1:11434/api/chat",
        401,
        "Unauthorized",
        {},
        None,
    )

    with patch(
        "soc_assistant.ollama_client.urlopen",
        side_effect=error,
    ):
        with pytest.raises(
            OllamaClientError, match="Ollama HTTP error: 401"
        ):
            analyze_with_ollama(request_data)


def test_http_503_is_handled(request_data):
    error = HTTPError(
        "http://127.0.0.1:11434/api/chat",
        503,
        "Service Unavailable",
        {},
        None,
    )

    with patch(
        "soc_assistant.ollama_client.urlopen",
        side_effect=error,
    ):
        with pytest.raises(
            OllamaClientError, match="Ollama HTTP error: 503"
        ):
            analyze_with_ollama(request_data)


def test_connection_refused_is_handled(request_data):
    with patch(
        "soc_assistant.ollama_client.urlopen",
        side_effect=URLError("Connection refused"),
    ):
        with pytest.raises(
            OllamaClientError, match="Unable to connect"
        ):
            analyze_with_ollama(request_data)


def test_timeout_is_handled(request_data):
    with patch(
        "soc_assistant.ollama_client.urlopen",
        side_effect=TimeoutError("Timed out"),
    ):
        with pytest.raises(
            OllamaClientError, match="Unable to connect"
        ):
            analyze_with_ollama(request_data)


def test_empty_http_body_is_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_with_response(request_data, b"")


def test_invalid_json_is_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_with_response(request_data, b"{invalid json")


def test_invalid_utf8_is_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_with_response(request_data, b"\\xff\\xfe".decode("unicode_escape").encode("latin1"))


def test_missing_message_is_rejected(request_data):
    body = json.dumps({"done": True}).encode()

    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_with_response(request_data, body)


def test_oversized_response_is_rejected(request_data):
    body = b"X" * (MAX_HTTP_RESPONSE_BYTES + 1)

    with pytest.raises(
        OllamaClientError, match="size limit"
    ):
        run_with_response(request_data, body)


def test_connection_error_does_not_expose_log_data(request_data):
    secret = "SYNTHETIC-SECRET-123"
    request_data["user"] = secret

    with patch(
        "soc_assistant.ollama_client.urlopen",
        side_effect=URLError(secret),
    ):
        with pytest.raises(OllamaClientError) as error:
            analyze_with_ollama(request_data)

    assert secret not in str(error.value)
