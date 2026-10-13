"""Verify local Ollama transport does not use configured proxies."""

from unittest.mock import MagicMock, patch
from urllib.request import ProxyHandler, Request

from soc_assistant.ollama_client import (
    NoRedirectHandler,
    OLLAMA_URL,
    urlopen,
)


def test_proxy_handler_disables_all_proxies():
    with patch("soc_assistant.ollama_client.build_opener") as mocked:
        mocked.return_value = MagicMock()
        urlopen(Request(OLLAMA_URL), timeout=5)

    handlers = mocked.call_args.args
    proxies = [h for h in handlers if isinstance(h, ProxyHandler)]

    assert len(proxies) == 1
    assert proxies[0].proxies == {}


def test_redirect_handler_is_preserved():
    with patch("soc_assistant.ollama_client.build_opener") as mocked:
        urlopen(Request(OLLAMA_URL), timeout=5)

    assert any(
        isinstance(h, NoRedirectHandler)
        for h in mocked.call_args.args
    )


def test_timeout_is_forwarded():
    with patch("soc_assistant.ollama_client.build_opener") as mocked:
        urlopen(Request(OLLAMA_URL), timeout=7)

    assert mocked.return_value.open.call_args.kwargs["timeout"] == 7


def test_request_is_forwarded_unchanged():
    request = Request(OLLAMA_URL)

    with patch("soc_assistant.ollama_client.build_opener") as mocked:
        urlopen(request, timeout=5)

    assert mocked.return_value.open.call_args.args[0] is request
