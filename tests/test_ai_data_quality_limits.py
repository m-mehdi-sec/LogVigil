"""Regression tests for bounded AI data-quality summaries."""

import json

from soc_assistant.ai_analyzer import MAX_CONTEXT_BYTES, build_ai_request
from soc_assistant.ai_context import build_ai_context
from soc_assistant.models import build_analysis_report


def test_ten_thousand_warnings_produce_bounded_context():
    warnings = [
        {
            "event_index": index,
            "event_id": 4625,
            "missing_fields": ["computer", "source_ip"],
            "message": "PRIVATE_RAW_LOG_MESSAGE",
        }
        for index in range(1, 10001)
    ]

    report = build_analysis_report([], [], warnings)
    context = build_ai_context(report)
    request = build_ai_request(context)

    quality = context["data_quality"]

    assert quality["warning_count"] == 10000
    assert quality["missing_field_counts"] == {
        "computer": 10000,
        "source_ip": 10000,
    }

    context_json = json.dumps(
        context,
        ensure_ascii=False,
        sort_keys=True,
        allow_nan=False,
    )

    assert len(context_json.encode("utf-8")) <= MAX_CONTEXT_BYTES
    assert "PRIVATE_RAW_LOG_MESSAGE" not in request["user"]
