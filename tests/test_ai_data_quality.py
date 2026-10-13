"""Tests for bounded data-quality information in AI context."""

from soc_assistant.ai_context import build_ai_context
from soc_assistant.models import build_analysis_report


def test_ai_context_includes_data_quality_summary():
    warnings = [
        {
            "event_index": 1,
            "event_id": 4625,
            "missing_fields": ["computer", "source_ip"],
            "message": "Missing fields.",
        },
        {
            "event_index": 2,
            "event_id": 4625,
            "missing_fields": ["computer"],
            "message": "Missing fields.",
        },
    ]

    report = build_analysis_report([], [], warnings)
    context = build_ai_context(report)

    quality = context["data_quality"]

    assert quality["warning_count"] == 2
    assert quality["missing_field_counts"] == {
        "computer": 2,
        "source_ip": 1,
    }


def test_ai_context_does_not_expose_raw_warning_data():
    warnings = [{
        "event_index": 1,
        "event_id": 4625,
        "missing_fields": ["computer"],
        "message": "UNTRUSTED_RAW_LOG_CONTENT",
    }]

    report = build_analysis_report([], [], warnings)
    context = build_ai_context(report)

    assert "UNTRUSTED_RAW_LOG_CONTENT" not in str(context)


def test_ai_context_without_warnings():
    report = build_analysis_report([], [])
    context = build_ai_context(report)

    assert context["data_quality"]["warning_count"] == 0
    assert context["data_quality"]["missing_field_counts"] == {}
