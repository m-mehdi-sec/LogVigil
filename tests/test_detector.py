from soc_assistant.detector import detect_brute_force


def test_five_failed_logins_trigger_detection():
    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
        }
        for i in range(5)
    ]

    findings = detect_brute_force(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-001"


def test_four_failed_logins_do_not_trigger_detection():
    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
        }
        for i in range(4)
    ]

    findings = detect_brute_force(events)

    assert findings == []


def test_five_failed_logins_outside_time_window():
    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:{i * 2:02d}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
        }
        for i in range(5)
    ]

    findings = detect_brute_force(events)

    assert findings == []


def test_duplicate_record_ids_do_not_trigger_detection():
    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
        }
        for i in range(4)
    ]

    events.append(events[0].copy())

    findings = detect_brute_force(events)

    assert findings == []


def test_exactly_five_minutes_triggers_detection():
    minutes = [0, 1, 2, 3, 5]
    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:{minute:02d}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
        }
        for i, minute in enumerate(minutes)
    ]

    findings = detect_brute_force(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-001"


def test_different_source_ips_do_not_trigger_detection():
    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": (
                "192.168.10.50" if i < 3 else "192.168.10.60"
            ),
        }
        for i in range(5)
    ]

    findings = detect_brute_force(events)

    assert findings == []


def test_different_users_do_not_trigger_detection():
    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": "alice" if i < 3 else "bob",
            "source_ip": "192.168.10.50",
        }
        for i in range(5)
    ]

    findings = detect_brute_force(events)

    assert findings == []


def test_out_of_order_events_trigger_detection():
    minutes = [4, 1, 3, 0, 2]

    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:{minute:02d}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
        }
        for i, minute in enumerate(minutes)
    ]

    findings = detect_brute_force(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-001"


def test_missing_source_ip_does_not_trigger_detection():
    events = [
        {
            "event_id": 4625,
            "record_id": i,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": None,
        }
        for i in range(5)
    ]

    findings = detect_brute_force(events)

    assert findings == []


def test_invalid_timestamp_raises_value_error():
    events = [
        {
            "event_id": 4625,
            "record_id": 1,
            "timestamp": "invalid-timestamp",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
        }
    ]

    import pytest

    with pytest.raises(ValueError):
        detect_brute_force(events)


def test_evidence_record_ids_follow_timestamp_order():
    events = [
        {
            "event_id": 4625,
            "timestamp": f"2026-10-12T10:0{minute}:00+02:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
            "record_id": 101 + minute,
        }
        for minute in [4, 1, 3, 0, 2]
    ]

    findings = detect_brute_force(events)

    assert len(findings) == 1
    assert findings[0]["evidence_record_ids"] == [
        101, 102, 103, 104, 105
    ]
    assert findings[0]["first_seen"] == "2026-10-12T10:00:00+02:00"
    assert findings[0]["last_seen"] == "2026-10-12T10:04:00+02:00"


def test_detection_with_mixed_timezone_offsets():
    timestamps = [
        "2026-10-12T10:00:00+02:00",
        "2026-10-12T08:01:00+00:00",
        "2026-10-12T10:02:00+02:00",
        "2026-10-12T08:03:00+00:00",
        "2026-10-12T10:04:00+02:00",
    ]

    events = [
        {
            "event_id": 4625,
            "timestamp": timestamp,
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
            "record_id": 101 + index,
        }
        for index, timestamp in enumerate(timestamps)
    ]

    findings = detect_brute_force(events)

    assert len(findings) == 1
    assert findings[0]["event_count"] == 5
    assert findings[0]["evidence_record_ids"] == [
        101, 102, 103, 104, 105
    ]


def test_rejects_timestamp_without_timezone():
    events = [
        {
            "event_id": 4625,
            "timestamp": "2026-10-12T10:00:00",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
        }
    ]

    try:
        detect_brute_force(events)
    except ValueError as error:
        assert "timezone" in str(error).lower()
    else:
        raise AssertionError("Expected timezone validation error")


def test_det002_ignores_different_source_ip():
    from soc_assistant.parser import parse_jsonl
    from soc_assistant.detector import detect_success_after_failures

    events = parse_jsonl("data/samples/failed_logins.jsonl")
    events.append({
        "event_id": 4624,
        "timestamp": "2026-10-12T10:05:00+02:00",
        "computer": "WIN11",
        "username": "testuser",
        "source_ip": "192.168.10.99",
        "record_id": 106,
    })

    assert detect_success_after_failures(events) == []


def test_det002_ignores_late_success():
    from soc_assistant.parser import parse_jsonl
    from soc_assistant.detector import detect_success_after_failures

    events = parse_jsonl("data/samples/failed_logins.jsonl")
    events.append({
        "event_id": 4624,
        "timestamp": "2026-10-12T10:11:00+02:00",
        "computer": "WIN11",
        "username": "testuser",
        "source_ip": "192.168.10.50",
        "record_id": 106,
    })

    assert detect_success_after_failures(events) == []


def test_det002_ignores_success_before_fifth_failure():
    from soc_assistant.parser import parse_jsonl
    from soc_assistant.detector import detect_success_after_failures

    events = parse_jsonl("data/samples/failed_logins.jsonl")
    events.append({
        "event_id": 4624,
        "timestamp": "2026-10-12T10:03:30+02:00",
        "computer": "WIN11",
        "username": "testuser",
        "source_ip": "192.168.10.50",
        "record_id": 106,
    })

    assert detect_success_after_failures(events) == []



def test_det003_requires_five_distinct_usernames():
    from soc_assistant.detector import detect_account_enumeration

    events = [
        {
            "event_id": 4625,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": f"user{i % 4}",
            "source_ip": "192.168.10.50",
            "record_id": 201 + i,
        }
        for i in range(5)
    ]

    assert detect_account_enumeration(events) == []


def test_det003_separates_source_ips():
    from soc_assistant.detector import detect_account_enumeration

    events = [
        {
            "event_id": 4625,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": f"user{i}",
            "source_ip": f"192.168.10.{50 + i}",
            "record_id": 201 + i,
        }
        for i in range(5)
    ]

    assert detect_account_enumeration(events) == []


def test_det003_respects_five_minute_window():
    from soc_assistant.detector import detect_account_enumeration

    events = [
        {
            "event_id": 4625,
            "timestamp": f"2026-10-12T10:{i * 3:02d}:00+02:00",
            "computer": "WIN11",
            "username": f"user{i}",
            "source_ip": "192.168.10.50",
            "record_id": 201 + i,
        }
        for i in range(5)
    ]

    assert detect_account_enumeration(events) == []



def test_det003_ignores_duplicate_records():
    from soc_assistant.detector import detect_account_enumeration

    events = [
        {
            "event_id": 4625,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": f"user{i}",
            "source_ip": "192.168.10.50",
            "record_id": 201 + i,
        }
        for i in range(4)
    ]

    duplicate = {**events[0], "username": "user4"}
    events.append(duplicate)

    assert detect_account_enumeration(events) == []


def test_det003_keeps_records_from_different_computers():
    from soc_assistant.detector import detect_account_enumeration

    events = [
        {
            "event_id": 4625,
            "timestamp": f"2026-10-12T10:0{i}:00+02:00",
            "computer": "WIN11",
            "username": f"user{i}",
            "source_ip": "192.168.10.50",
            "record_id": 201 + i,
        }
        for i in range(4)
    ]

    events.append({
        **events[0],
        "computer": "WIN-SRV2025",
        "username": "user4",
    })

    assert detect_account_enumeration(events) == []
