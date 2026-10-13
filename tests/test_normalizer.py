from soc_assistant.detector import detect_brute_force
from soc_assistant.normalizer import normalize_event, normalize_events


def make_wazuh_event(index, source_ip="192.168.10.50"):
    return {
        "timestamp": f"2026-10-13T12:{index * 10:02d}:00+02:00",
        "data": {
            "win": {
                "system": {
                    "eventID": "4625",
                    "computer": "WIN11",
                    "eventRecordID": str(501 + index),
                    "systemTime": f"2026-10-13T08:0{index}:00Z",
                },
                "eventdata": {
                    "targetUserName": "testuser",
                    "ipAddress": source_ip,
                },
            }
        },
    }


def test_windows_event_time_drives_detection():
    events = normalize_events([
        make_wazuh_event(index) for index in range(5)
    ])

    findings = detect_brute_force(events)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-001"
    assert findings[0]["first_seen"] == "2026-10-13T08:00:00+00:00"


def test_missing_wazuh_source_ip_prevents_false_alerts():
    events = normalize_events([
        make_wazuh_event(index, "-") for index in range(5)
    ])

    assert all(event["source_ip"] is None for event in events)
    assert detect_brute_force(events) == []


def test_existing_logvigil_format_is_preserved():
    event = {
        "event_id": 4740,
        "timestamp": "2026-10-13T10:00:00+02:00",
        "computer": "WIN-SRV2025",
        "username": "testuser",
        "record_id": 801,
    }

    assert normalize_event(event) == event



def test_mixed_ipv4_formats_detect_same_source():
    events = normalize_events([
        make_wazuh_event(
            index,
            "192.168.10.50" if index % 2 == 0
            else "::ffff:192.168.10.50",
        )
        for index in range(5)
    ])

    assert all(
        event["source_ip"] == "192.168.10.50"
        for event in events
    )
    assert len(detect_brute_force(events)) == 1


def test_invalid_source_ip_prevents_false_alert():
    events = normalize_events([
        make_wazuh_event(index, "not-an-ip")
        for index in range(5)
    ])

    assert all(event["source_ip"] is None for event in events)
    assert detect_brute_force(events) == []


def test_missing_username_prevents_false_alert():
    events = [
        make_wazuh_event(index)
        for index in range(5)
    ]

    for event in events:
        event["data"]["win"]["eventdata"]["targetUserName"] = "-"

    normalized = normalize_events(events)

    assert all(event["username"] is None for event in normalized)
    assert detect_brute_force(normalized) == []
