
"""Local-only Ollama chat client for defensive SOC analysis."""

import json
import math
import re
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler

from soc_assistant.ai_analyzer import parse_ai_response


OLLAMA_URL = "http://127.0.0.1:11434/api/chat"
DEFAULT_TIMEOUT = 30
MAX_HTTP_RESPONSE_BYTES = 65536
MAX_REQUEST_BYTES = 65536

SOC_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "risk_level": {
            "type": "string",
            "enum": [
                "critical",
                "high",
                "medium",
                "low",
                "informational",
            ],
        },
        "observations": {
            "type": "array",
            "items": {"type": "string"},
        },
        "hypotheses": {
            "type": "array",
            "items": {"type": "string"},
        },
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "risk_level",
        "observations",
        "hypotheses",
        "recommended_actions",
    ],
    "additionalProperties": False,
}


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent Ollama requests from following redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def urlopen(request, timeout):
    """Open a local request without following HTTP redirects."""
    opener = build_opener(ProxyHandler({}), NoRedirectHandler())
    return opener.open(request, timeout=timeout)


class OllamaClientError(Exception):
    """Raised when local Ollama communication fails."""


def analyze_with_ollama(
    ai_request,
    model="qwen3:4b",
    timeout=DEFAULT_TIMEOUT,
):
    """Send a bounded SOC request to a local Ollama model."""
    if not isinstance(ai_request, dict):
        raise ValueError("AI request must be an object")

    if not isinstance(model, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}", model
    ):
        raise ValueError("Model name must be a non-empty string")

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or not 0 < timeout <= 120
    ):
        raise ValueError("Timeout must be between 0 and 120 seconds")

    for field in ("system", "user"):
        if not isinstance(ai_request.get(field), str):
            raise ValueError(f"AI request {field} must be text")

    if ai_request.get("response_format") != "json":
        raise ValueError("AI request must use JSON response format")

    payload = {
        "model": model,
        "stream": False,
        "think": False,
        "format": SOC_RESPONSE_SCHEMA,
        "messages": [
            {"role": "system", "content": ai_request["system"]},
            {"role": "user", "content": ai_request["user"]},
        ],
        "options": {
            "temperature": 0,
            "num_predict": 1024,
        },
    }

    encoded = json.dumps(
        payload, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")

    if len(encoded) > MAX_REQUEST_BYTES:
        raise ValueError("AI request exceeds size limit")

    request = Request(
        OLLAMA_URL,
        data=encoded,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout) as response:
            status = response.getcode()
            if status != 200:
                raise OllamaClientError("Unexpected Ollama HTTP status")
            raw = response.read(MAX_HTTP_RESPONSE_BYTES + 1)
    except HTTPError as error:
        raise OllamaClientError(
            f"Ollama HTTP error: {error.code}"
        ) from error
    except (URLError, TimeoutError, OSError) as error:
        if isinstance(error, TimeoutError) or isinstance(
            getattr(error, "reason", None), TimeoutError
        ):
            raise OllamaClientError(
                "Local Ollama request timed out"
            ) from error
        raise OllamaClientError(
            "Unable to connect to local Ollama"
        ) from error

    if len(raw) > MAX_HTTP_RESPONSE_BYTES:
        raise OllamaClientError("Ollama response exceeds size limit")

    try:
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise ValueError("Unexpected Ollama response type")
        if result.get("done") is not True:
            raise ValueError("Incomplete Ollama response")
        message = result["message"]
        if not isinstance(message, dict):
            raise ValueError("Invalid Ollama message")
        content = message["content"]
        if not isinstance(content, str):
            raise ValueError("Invalid Ollama message content")
        return parse_ai_response(content)
    except (
        UnicodeError,
        json.JSONDecodeError,
        KeyError,
        TypeError,
        ValueError,
    ) as error:
        raise OllamaClientError(
            "Invalid Ollama response"
        ) from error
