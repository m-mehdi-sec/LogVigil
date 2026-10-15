"""Tests for security event data-quality validation."""

from soc_assistant.validator import validate_events


def test_valid_login_event_has_no_warnings():
    events = [{
        "event_id": 4625,
        "timestamp": "2026-10-13T12:00:00+00:00",
        "computer": "WIN11-LAB",
        "username": "testuser",
        "source_ip": "192.0.2.10",
    }]

    assert validate_events(events) == []


def test_missing_computer_generates_warning():
    events = [{
        "event_id": 4625,
        "timestamp": "2026-10-13T12:00:00+00:00",
        "computer": None,
        "username": "testuser",
        "source_ip": "192.0.2.10",
    }]

    warnings = validate_events(events)

    assert len(warnings) == 1
    assert warnings[0]["event_id"] == 4625
    assert warnings[0]["missing_fields"] == ["computer"]


def test_unrelated_event_is_not_flagged():
    events = [{"event_id": 4740}]

    assert validate_events(events) == []


def test_validation_does_not_modify_events():
    events = [{"event_id": 4625, "username": "testuser"}]
    original = [event.copy() for event in events]

    validate_events(events)

    assert events == original


import pytest


@pytest.mark.parametrize("logon_type", ["2", "5", "7", "11"])
def test_local_logon_types_allow_missing_source_ip(logon_type):
    event = {
        "event_id": 4624,
        "timestamp": "2026-10-14T12:00:00Z",
        "computer": "TestHost",
        "username": "test-user",
        "source_ip": None,
        "logon_type": logon_type,
    }

    assert validate_events([event]) == []


@pytest.mark.parametrize(
    "event_id,logon_type",
    [(4624, "3"), (4625, "10")],
)
def test_remote_logon_types_warn_on_missing_source_ip(event_id, logon_type):
    event = {
        "event_id": event_id,
        "timestamp": "2026-10-14T12:00:00Z",
        "computer": "TestHost",
        "username": "test-user",
        "source_ip": None,
        "logon_type": logon_type,
    }

    warnings = validate_events([event])

    assert len(warnings) == 1
    assert warnings[0]["missing_fields"] == ["source_ip"]
