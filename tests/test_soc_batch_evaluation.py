
"""Batch evaluation of synthetic Windows security events."""

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import pytest


BASE_TIME = datetime(2026, 10, 14, 8, 0, tzinfo=timezone.utc)


def event(
    event_id="4625",
    seconds=0,
    username="testuser",
    ip="192.0.2.10",
    computer="WIN11-LAB",
    record_id=1000,
):
    timestamp = BASE_TIME + timedelta(seconds=seconds)

    return {
        "timestamp": timestamp.isoformat(),
        "data": {
            "win": {
                "system": {
                    "eventID": str(event_id),
                    "computer": computer,
                    "eventRecordID": str(record_id),
                },
                "eventdata": {
                    "targetUserName": username,
                    "ipAddress": ip,
                    "logonType": "3",
                },
            }
        },
    }


def failures(
    count=5,
    username="testuser",
    ip="192.0.2.10",
    computer="WIN11-LAB",
    start=0,
    record_start=1000,
    interval=30,
):
    return [
        event(
            seconds=start + i * interval,
            username=username,
            ip=ip,
            computer=computer,
            record_id=record_start + i,
        )
        for i in range(count)
    ]


def success(
    seconds=180,
    username="testuser",
    ip="192.0.2.10",
    computer="WIN11-LAB",
    record_id=2000,
):
    return event(
        event_id="4624",
        seconds=seconds,
        username=username,
        ip=ip,
        computer=computer,
        record_id=record_id,
    )


def lockout():
    result = event(
        event_id="4740",
        computer="WIN-SRV2025",
        record_id=3000,
    )
    result["data"]["win"]["eventdata"] = {
        "targetUserName": "testuser",
        "targetDomainName": "LAB",
        "callerComputerName": "WIN11-LAB",
    }
    return result


def run_report(tmp_path, events):
    log_file = tmp_path / "events.jsonl"

    with log_file.open("w", encoding="utf-8") as handle:
        for item in events:
            handle.write(json.dumps(item) + "\n")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_assistant.main",
            str(log_file),
            "--report",
        ],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def detected_rules(report):
    return {item["rule_id"] for item in report["findings"]}


SCENARIOS = [
    ("five_failures", failures(5), {"DET-001"}),
    ("six_failures", failures(6), {"DET-001"}),
    (
        "ten_failures",
        failures(10, interval=20),
        {"DET-001"},
    ),
    (
        "success_after_failures",
        failures(5) + [success()],
        {"DET-001", "DET-002"},
    ),
    (
        "success_after_six_failures",
        failures(6) + [success(seconds=240)],
        {"DET-001", "DET-002"},
    ),
    ("account_lockout", [lockout()], {"DET-004"}),
    ("one_failure", failures(1), set()),
    ("two_failures", failures(2), set()),
    ("three_failures", failures(3), set()),
    ("four_failures", failures(4), set()),
    ("one_success", [success()], set()),
    (
        "two_successes",
        [success(), success(record_id=2001)],
        set(),
    ),
    (
        "success_before_failures",
        [success(seconds=0)] + failures(5, start=60),
        {"DET-001"},
    ),
    (
        "different_users",
        [
            event(username=f"user{i}", record_id=4000 + i)
            for i in range(4)
        ],
        set(),
    ),
    (
        "different_ips",
        [
            event(ip=f"192.0.2.{10+i}", record_id=5000 + i)
            for i in range(4)
        ],
        set(),
    ),
    (
        "different_computers",
        [
            event(computer=f"WIN11-{i}", record_id=6000 + i)
            for i in range(4)
        ],
        set(),
    ),
    (
        "duplicate_records",
        [event(record_id=7000) for _ in range(5)],
        set(),
    ),
    (
        "failures_outside_window",
        failures(5, interval=120),
        set(),
    ),
    (
        "success_too_late",
        failures(5) + [success(seconds=1200)],
        {"DET-001"},
    ),
    (
        "success_different_ip",
        failures(5) + [success(ip="198.51.100.20")],
        {"DET-001"},
    ),
    (
        "success_different_user",
        failures(5) + [success(username="otheruser")],
        {"DET-001"},
    ),
    (
        "success_different_computer",
        failures(5) + [success(computer="WIN11-OTHER")],
        {"DET-001"},
    ),
    (
        "out_of_order_events",
        list(reversed(failures(5))),
        {"DET-001"},
    ),
    (
        "two_independent_sources",
        failures(5, record_start=8000)
        + failures(
            5,
            username="otheruser",
            ip="198.51.100.30",
            record_start=9000,
        ),
        {"DET-001"},
    ),
    (
        "no_security_events",
        [event(event_id="9999")],
        set(),
    ),
]


@pytest.mark.parametrize(
    "name,events,expected_rules",
    SCENARIOS,
    ids=[item[0] for item in SCENARIOS],
)
def test_soc_scenario(tmp_path, name, events, expected_rules):
    report = run_report(tmp_path, events)

    assert report["application"] == "LogVigil"
    assert report["summary"]["events_analyzed"] == len(events)

    actual = detected_rules(report)
    assert actual == expected_rules, (
        f"{name}: expected {expected_rules}, got {actual}"
    )

    assert report["summary"]["findings_count"] == len(
        report["findings"]
    )

    for finding in report["findings"]:
        assert finding["status"] == "needs_review"


def test_scenario_count():
    assert len(SCENARIOS) == 25
