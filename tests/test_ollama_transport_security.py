"""Transport security tests for local Ollama communication."""

import io
import json
from unittest.mock import patch
from urllib.request import Request

import pytest

from soc_assistant.ollama_client import (
    OLLAMA_URL,
    OllamaClientError,
    NoRedirectHandler,
    analyze_with_ollama,
)


class FakeResponse:
    def __init__(self, payload, status=200):
        self.body = io.BytesIO(json.dumps(payload).encode())
        self.status = status

    def getcode(self):
        return self.status

    def read(self, size=-1):
        return self.body.read(size)

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


def check_status(request_data, status):
    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=FakeResponse({}, status),
    ):
        return analyze_with_ollama(request_data)


@pytest.mark.parametrize(
    "status",
    [201, 204, 301, 302, 307, 308],
)
def test_unexpected_http_status_rejected(request_data, status):
    with pytest.raises(
        OllamaClientError, match="Unexpected Ollama HTTP status"
    ):
        check_status(request_data, status)


def test_missing_http_status_rejected(request_data):
    with pytest.raises(
        OllamaClientError, match="Unexpected Ollama HTTP status"
    ):
        check_status(request_data, None)


def test_ollama_url_is_loopback():
    assert OLLAMA_URL == "http://127.0.0.1:11434/api/chat"


def test_redirect_handler_blocks_external_destination():
    handler = NoRedirectHandler()
    request = Request(OLLAMA_URL)

    assert handler.redirect_request(
        request,
        None,
        307,
        "Temporary Redirect",
        {},
        "https://example.com/collect",
    ) is None


def test_valid_request_targets_loopback(request_data):
    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=FakeResponse(
            {
                "done": True,
                "message": {
                    "content": json.dumps({
                        "risk_level": "low",
                        "observations": [],
                        "hypotheses": [],
                        "recommended_actions": [],
                    })
                },
            }
        ),
    ) as mocked:
        analyze_with_ollama(request_data)

    request = mocked.call_args.args[0]
    assert request.full_url == OLLAMA_URL
    assert request.get_method() == "POST"
