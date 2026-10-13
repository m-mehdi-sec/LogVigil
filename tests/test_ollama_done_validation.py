"""Validate Ollama completion status strictly."""

import io
import json
from unittest.mock import patch

import pytest

from soc_assistant.ollama_client import (
    OllamaClientError,
    analyze_with_ollama,
)


class FakeResponse:
    def __init__(self, payload):
        self.body = io.BytesIO(json.dumps(payload).encode())

    def getcode(self):
        return 200

    def read(self, size=-1):
        return self.body.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.body.close()


REQUEST = {
    "system": "Defensive SOC analysis.",
    "user": "Synthetic authentication events.",
    "response_format": "json",
}

VALID_ANALYSIS = {
    "risk_level": "low",
    "observations": [],
    "hypotheses": [],
    "recommended_actions": [],
}


def run_response(done_marker):
    payload = {
        "message": {"content": json.dumps(VALID_ANALYSIS)}
    }

    if done_marker != "MISSING":
        payload["done"] = done_marker

    with patch(
        "soc_assistant.ollama_client.urlopen",
        return_value=FakeResponse(payload),
    ):
        return analyze_with_ollama(REQUEST)


def test_done_true_accepted():
    result = run_response(True)
    assert result["risk_level"] == "low"


def test_done_false_rejected():
    with pytest.raises(OllamaClientError):
        run_response(False)


def test_done_missing_rejected():
    with pytest.raises(OllamaClientError):
        run_response("MISSING")


def test_done_null_rejected():
    with pytest.raises(OllamaClientError):
        run_response(None)


def test_done_numeric_one_rejected():
    with pytest.raises(OllamaClientError):
        run_response(1)
