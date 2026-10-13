"""Additional Ollama HTTP response security tests."""

import io
import json
from unittest.mock import patch
from urllib.error import HTTPError

import pytest

from soc_assistant.ollama_client import (
    NoRedirectHandler,
    OllamaClientError,
    analyze_with_ollama,
)


class FakeResponse:
    def __init__(self, body, status=200):
        self.body = io.BytesIO(body)
        self.status = status

    def read(self, size=-1):
        return self.body.read(size)

    def getcode(self):
        return self.status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.body.close()


@pytest.fixture
def request_data():
    return {
        "system": "Defensive SOC analysis.",
        "user": "Synthetic event evidence.",
        "response_format": "json",
    }


def run_response(request_data, payload, status=200):
    body = json.dumps(payload).encode("utf-8")
    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=FakeResponse(body, status),
    ):
        return analyze_with_ollama(request_data)


def test_redirect_handler_blocks_redirect():
    handler = NoRedirectHandler()
    result = handler.redirect_request(
        None, None, 302, "Found", {},
        "https://external.example/collect",
    )
    assert result is None


def test_http_302_is_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Unexpected Ollama HTTP status"
    ):
        run_response(request_data, {}, status=302)


def test_http_500_is_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Unexpected Ollama HTTP status"
    ):
        run_response(request_data, {}, status=500)


def test_json_array_is_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_response(request_data, [])


def test_json_null_is_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_response(request_data, None)


def test_incomplete_response_is_rejected(request_data):
    payload = {
        "done": False,
        "message": {"content": "{}"},
    }
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_response(request_data, payload)


def test_missing_message_is_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_response(request_data, {"done": True})


def test_message_array_is_rejected(request_data):
    payload = {"message": []}
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_response(request_data, payload)


def test_non_text_content_is_rejected(request_data):
    payload = {"message": {"content": {"unexpected": True}}}
    with pytest.raises(
        OllamaClientError, match="Invalid Ollama response"
    ):
        run_response(request_data, payload)


def test_redirect_http_error_is_handled(request_data):
    error = HTTPError(
        "http://127.0.0.1:11434/api/chat",
        307,
        "Temporary Redirect",
        {"Location": "https://external.example"},
        None,
    )
    with patch(
        "soc_assistant.ollama_client.urlopen",
        side_effect=error,
    ):
        with pytest.raises(
            OllamaClientError, match="Ollama HTTP error: 307"
        ):
            analyze_with_ollama(request_data)
