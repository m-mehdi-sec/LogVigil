"""Integration tests for data quality in the mocked AI pipeline."""

import json

from soc_assistant.ai_pipeline import analyze_soc_report
from soc_assistant.models import build_analysis_report


def test_data_quality_reaches_ai_without_raw_logs(monkeypatch):
    """Verify safe data-quality context reaches the mocked AI client."""
    warnings = [{
        "event_index": 1,
        "event_id": 4625,
        "missing_fields": ["computer", "source_ip"],
        "message": "PRIVATE_RAW_LOG_MESSAGE",
    }]

    report = build_analysis_report([], [], warnings)
    captured = {}

    def fake_ollama(request, *, model, timeout):
        captured["request"] = request
        captured["model"] = model
        captured["timeout"] = timeout

        return {
            "risk_level": "informational",
            "observations": ["Security telemetry is incomplete."],
            "hypotheses": [],
            "recommended_actions": [
                "Review log collection completeness."
            ],
        }

    monkeypatch.setattr(
        "soc_assistant.ai_pipeline.analyze_with_ollama",
        fake_ollama,
    )

    result = analyze_soc_report(report, model="test-model", timeout=5)

    request = captured["request"]
    context = json.loads(
        request["user"].split("\n", 1)[1]
    )

    assert context["data_quality"]["warning_count"] == 1
    assert context["data_quality"]["missing_field_counts"] == {
        "computer": 1,
        "source_ip": 1,
    }
    assert "PRIVATE_RAW_LOG_MESSAGE" not in request["user"]
    assert "Missing telemetry fields" in request["user"]

    assert captured["model"] == "test-model"
    assert captured["timeout"] == 5
    assert result["application"] == "LogVigil"
    assert result["ai_analysis"]["risk_level"] == "informational"


def test_ai_context_version_remains_compatible(monkeypatch):
    """Verify the existing AI context contract remains supported."""
    report = build_analysis_report([], [])
    captured = {}

    def fake_ollama(request, *, model, timeout):
        captured["request"] = request

        return {
            "risk_level": "informational",
            "observations": [],
            "hypotheses": [],
            "recommended_actions": [],
        }

    monkeypatch.setattr(
        "soc_assistant.ai_pipeline.analyze_with_ollama",
        fake_ollama,
    )

    analyze_soc_report(report)

    context = json.loads(
        captured["request"]["user"].split("\n", 1)[1]
    )

    assert context["context_version"] == "1.0"
    assert context["data_quality"]["warning_count"] == 0
