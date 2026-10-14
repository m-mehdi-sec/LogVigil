"""Regression tests for unusable authentication source addresses."""

from datetime import datetime, timedelta, timezone

import pytest

from soc_assistant.detector import (
    detect_account_enumeration,
    detect_brute_force,
    detect_success_after_failures,
)


def make_events(ip, different_users=False, include_success=False):
    start = datetime(2026, 10, 14, 12, 0, tzinfo=timezone.utc)
    events = []

    for index in range(5):
        events.append({
            "event_id": 4625,
            "timestamp": (start + timedelta(seconds=30 * index)).isoformat(),
            "computer": "LAB-TEST",
            "username": f"user-{index}" if different_users else "test-user",
            "source_ip": ip,
            "record_id": str(index + 1),
        })

    if include_success:
        events.append({
            "event_id": 4624,
            "timestamp": (start + timedelta(minutes=3)).isoformat(),
            "computer": "LAB-TEST",
            "username": "test-user",
            "source_ip": ip,
            "record_id": "6",
        })

    return events


@pytest.mark.parametrize("ip", ["0.0.0.0", "::", "127.0.0.1", "::1", "-"])
def test_unusable_ip_does_not_trigger_brute_force(ip):
    assert detect_brute_force(make_events(ip)) == []


@pytest.mark.parametrize("ip", ["0.0.0.0", "::", "127.0.0.1", "::1", "-"])
def test_unusable_ip_does_not_trigger_account_enumeration(ip):
    assert detect_account_enumeration(
        make_events(ip, different_users=True)
    ) == []


def test_unusable_ip_does_not_trigger_success_after_failures():
    events = make_events("127.0.0.1", include_success=True)
    assert detect_success_after_failures(events) == []


def test_valid_ip_still_triggers_brute_force():
    findings = detect_brute_force(make_events("192.0.2.10"))
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-001"


def test_valid_ip_still_triggers_account_enumeration():
    events = make_events("192.0.2.10", different_users=True)
    findings = detect_account_enumeration(events)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-003"


def test_valid_ip_still_triggers_success_after_failures():
    events = make_events("192.0.2.10", include_success=True)
    findings = detect_success_after_failures(events)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-002"
