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
