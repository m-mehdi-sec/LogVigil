from pathlib import Path

from soc_assistant.parser import parse_jsonl
from soc_assistant.detector import detect_brute_force


def test_jsonl_to_detection():
    project_root = Path(__file__).resolve().parents[1]
    log_file = project_root / "data/samples/failed_logins.jsonl"

    events = parse_jsonl(log_file)
    findings = detect_brute_force(events)

    assert len(events) == 5
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-001"
    assert findings[0]["status"] == "needs_review"



def test_cli_reports_both_detection_rules(tmp_path):
    import json
    import subprocess
    from pathlib import Path

    sample = Path("data/samples/failed_logins.jsonl")

    success = {
        "event_id": 4624,
        "timestamp": "2026-10-12T10:05:00+02:00",
        "computer": "WIN11",
        "username": "testuser",
        "source_ip": "192.168.10.50",
        "record_id": 106,
    }

    log_file = tmp_path / "authentication_events.jsonl"

    original = sample.read_text(encoding="utf-8").rstrip("\n")
    log_file.write_text(
        original + "\n" + json.dumps(success) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        ["logvigil", str(log_file), "--report"],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr

    report = json.loads(result.stdout)

    assert report["summary"]["events_analyzed"] == 6
    assert report["summary"]["findings_count"] == 2

    rule_ids = {
        finding["rule_id"]
        for finding in report["findings"]
    }

    assert rule_ids == {"DET-001", "DET-002"}



def test_wazuh_windows_events_all_detection_rules(tmp_path):
    import json
    import subprocess

    def wazuh_event(event_id, username, minute, record_id):
        return {
            "timestamp": f"2026-10-13T10:{minute:02d}:00+02:00",
            "data": {
                "win": {
                    "system": {
                        "eventID": str(event_id),
                        "computer": "WIN11",
                        "eventRecordID": str(record_id),
                    },
                    "eventdata": {
                        "targetUserName": username,
                        "ipAddress": "192.168.10.50",
                    },
                }
            },
        }

    events = [
        wazuh_event(4625, "testuser", i, 501 + i)
        for i in range(5)
    ]

    events.extend(
        wazuh_event(4625, f"user{i}", i, 601 + i)
        for i in range(4)
    )

    events.append(wazuh_event(4624, "testuser", 5, 700))

    log_file = tmp_path / "wazuh_events.jsonl"
    log_file.write_text(
        "\n".join(json.dumps(event) for event in events) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        ["logvigil", str(log_file), "--report"],
        capture_output=True,
        text=True,
        check=True,
    )

    report = json.loads(result.stdout)
    rule_ids = {finding["rule_id"] for finding in report["findings"]}

    assert rule_ids == {"DET-001", "DET-002", "DET-003"}
    assert report["summary"]["events_analyzed"] == 10
    assert report["summary"]["highest_severity"] == "high"



def test_wazuh_account_lockout_detection(tmp_path):
    import json
    import subprocess

    event = {
        "timestamp": "2026-10-13T14:00:00+02:00",
        "data": {
            "win": {
                "system": {
                    "eventID": "4740",
                    "computer": "WIN-SRV2025",
                    "eventRecordID": "801",
                },
                "eventdata": {
                    "targetUserName": "testuser",
                },
            }
        },
    }

    log_file = tmp_path / "wazuh_lockout.jsonl"
    log_file.write_text(
        "\n".join(json.dumps(item) for item in [event, event]) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        ["logvigil", str(log_file), "--report"],
        capture_output=True,
        text=True,
        check=True,
    )

    report = json.loads(result.stdout)

    assert report["summary"]["events_analyzed"] == 2
    assert report["summary"]["findings_count"] == 1
    assert report["summary"]["highest_severity"] == "medium"

    finding = report["findings"][0]

    assert finding["rule_id"] == "DET-004"
    assert finding["username"] == "testuser"
    assert finding["source_ip"] is None
    assert finding["evidence_record_ids"] == [801]



def test_wazuh_privileged_group_change_detection(tmp_path):
    import json
    import subprocess

    def make_event(group_name, group_sid, record_id):
        return {
            "timestamp": "2026-10-13T14:00:00+02:00",
            "data": {
                "win": {
                    "system": {
                        "eventID": "4728",
                        "computer": "WIN-SRV2025",
                        "eventRecordID": str(record_id),
                    },
                    "eventdata": {
                        "targetUserName": group_name,
                        "targetSid": group_sid,
                        "memberName": "CN=testuser,DC=lab,DC=local",
                        "memberSid": "S-1-5-21-100-200-300-1105",
                        "subjectUserName": "administrator",
                    },
                }
            },
        }

    privileged = make_event(
        "Domain Admins", "S-1-5-21-100-200-300-512", 901
    )
    ordinary = make_event(
        "GG-IT-Users", "S-1-5-21-100-200-300-1100", 902
    )

    log_file = tmp_path / "group_changes.jsonl"
    log_file.write_text(
        "\n".join(
            json.dumps(event)
            for event in [privileged, privileged, ordinary]
        ) + "\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        ["logvigil", str(log_file), "--report"],
        capture_output=True,
        text=True,
        check=True,
    )

    report = json.loads(result.stdout)

    assert report["summary"]["events_analyzed"] == 3
    assert report["summary"]["findings_count"] == 1
    assert report["summary"]["highest_severity"] == "high"

    finding = report["findings"][0]
    assert finding["rule_id"] == "DET-005"
    assert finding["group_name"] == "Domain Admins"
    assert finding["actor"] == "administrator"
    assert finding["evidence_record_ids"] == [901]
