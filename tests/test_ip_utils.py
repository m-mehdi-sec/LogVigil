"""Tests for source IP validation."""

import pytest

from soc_assistant.ip_utils import is_usable_source_ip


@pytest.mark.parametrize(
    "value",
    [
        "192.0.2.10",
        "192.168.10.20",
        "10.10.10.2",
        "2001:db8::10",
    ],
)
def test_usable_source_ips(value):
    assert is_usable_source_ip(value)


@pytest.mark.parametrize(
    "value",
    [
        None,
        "",
        "-",
        "invalid",
        "0.0.0.0",
        "::",
        "127.0.0.1",
        "::1",
    ],
)
def test_unusable_source_ips(value):
    assert not is_usable_source_ip(value)
