"""Tests for logon-type-aware data-quality validation."""

import pytest

from soc_assistant.validator import validate_events


def login_event(logon_type, source_ip=None):
    return {
        "event_id": 4625,
        "timestamp": "2026-10-13T12:00:00+00:00",
        "computer": "WIN11-LAB",
        "username": "testuser",
        "source_ip": source_ip,
        "logon_type": logon_type,
    }


def test_interactive_login_without_ip_has_no_warning():
    assert validate_events([login_event("2")]) == []


@pytest.mark.parametrize("logon_type", ["3", "10", None])
def test_other_login_types_without_ip_generate_warning(logon_type):
    warnings = validate_events([login_event(logon_type)])

    assert len(warnings) == 1
    assert warnings[0]["missing_fields"] == ["source_ip"]


def test_network_login_with_ip_has_no_warning():
    events = [login_event("3", "192.0.2.10")]

    assert validate_events(events) == []
