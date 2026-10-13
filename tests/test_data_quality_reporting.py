"""Tests for data-quality warnings in SOC reports."""

from soc_assistant.models import build_analysis_report
from soc_assistant.main import format_summary
from soc_assistant.validator import validate_events


def test_report_includes_missing_computer_warning():
    events = [{
        "event_id": 4625,
        "timestamp": "2026-10-13T12:00:00+00:00",
        "computer": None,
        "username": "testuser",
        "source_ip": "192.0.2.10",
    }]

    warnings = validate_events(events)
    report = build_analysis_report(events, [], warnings)

    assert len(report["data_quality_warnings"]) == 1
    assert report["data_quality_warnings"][0]["missing_fields"] == [
        "computer"
    ]
    assert report["summary"]["findings_count"] == 0


def test_report_has_empty_warnings_by_default():
    report = build_analysis_report([], [])

    assert report["data_quality_warnings"] == []


def test_summary_displays_warning_count():
    events = [{"event_id": 4625}]
    warnings = validate_events(events)
    report = build_analysis_report(events, [], warnings)

    summary = format_summary(report)

    assert "Data quality warnings: 1" in summary


def test_warnings_do_not_change_findings():
    findings = [{
        "rule_id": "DET-004",
        "severity": "medium",
    }]
    warnings = [{
        "event_index": 1,
        "event_id": 4625,
        "missing_fields": ["computer"],
        "message": "Login event contains missing required fields.",
    }]

    report = build_analysis_report([], findings, warnings)

    assert report["summary"]["findings_count"] == 1
    assert report["findings"][0]["rule_id"] == "DET-004"
    assert len(report["data_quality_warnings"]) == 1
