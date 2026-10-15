"""Regression tests for source IP classification."""

import pytest

from soc_assistant.ip_utils import classify_source_ip


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("192.168.10.20", "private"),
        ("10.10.10.2", "private"),
        ("8.8.8.8", "public"),
        ("192.0.2.50", "documentation"),
        ("198.51.100.10", "documentation"),
        ("203.0.113.10", "documentation"),
        ("2001:db8::10", "documentation"),
        ("127.0.0.1", "loopback"),
        ("::1", "loopback"),
        ("0.0.0.0", "unspecified"),
        ("::", "unspecified"),
        ("169.254.1.10", "link_local"),
        ("224.0.0.1", "multicast"),
        ("::ffff:192.0.2.50", "documentation"),
        ("invalid", "invalid"),
        ("", "invalid"),
        (None, "invalid"),
    ],
)
def test_classify_source_ip(address, expected):
    assert classify_source_ip(address) == expected
