"""Integration tests for advisory-only SOC AI analysis."""

import copy
from unittest.mock import patch

import pytest

from soc_assistant.ai_pipeline import analyze_soc_report


@pytest.fixture
def report():
    return {
        "application": "LogVigil",
        "schema_version": "1.0",
        "summary": {
            "events_analyzed": 10,
            "findings_count": 0,
            "investigation_groups_count": 0,
        },
        "findings": [],
        "investigation_groups": [],
    }


@pytest.fixture
def valid_ai_result():
    return {
        "risk_level": "low",
        "observations": ["No suspicious activity identified"],
        "hypotheses": ["Normal authentication activity"],
        "recommended_actions": ["Continue monitoring"],
    }


def run_pipeline(report, ai_result):
    with patch(
        "soc_assistant.ai_pipeline.analyze_with_ollama",
        return_value=ai_result,
    ):
        return analyze_soc_report(report)


def test_pipeline_requires_human_review(report, valid_ai_result):
    result = run_pipeline(report, valid_ai_result)
    assert result["ai_analysis"]["requires_human_review"] is True


def test_pipeline_never_authorizes_execution(report, valid_ai_result):
    result = run_pipeline(report, valid_ai_result)
    assert result["ai_analysis"]["execution_authorized"] is False


def test_pipeline_includes_advisory_notice(report, valid_ai_result):
    result = run_pipeline(report, valid_ai_result)
    assert "advisory" in result["ai_analysis"]["advisory_notice"].lower()


def test_pipeline_rejects_command_field(report, valid_ai_result):
    valid_ai_result["execute_command"] = "whoami"
    with pytest.raises(ValueError):
        run_pipeline(report, valid_ai_result)


def test_pipeline_rejects_extra_permissions(report, valid_ai_result):
    valid_ai_result["grant_admin"] = True
    with pytest.raises(ValueError):
        run_pipeline(report, valid_ai_result)


def test_pipeline_rejects_invalid_risk(report, valid_ai_result):
    valid_ai_result["risk_level"] = "unknown"
    with pytest.raises(ValueError):
        run_pipeline(report, valid_ai_result)


def test_pipeline_rejects_non_text_recommendation(report, valid_ai_result):
    valid_ai_result["recommended_actions"] = [
        {"command": "disable-firewall"}
    ]
    with pytest.raises(ValueError):
        run_pipeline(report, valid_ai_result)


def test_pipeline_keeps_recommendation_as_text(report, valid_ai_result):
    recommendation = "Review firewall configuration manually"
    valid_ai_result["recommended_actions"] = [recommendation]

    result = run_pipeline(report, valid_ai_result)

    assert result["ai_analysis"]["recommended_actions"] == [
        recommendation
    ]


def test_pipeline_preserves_report(report, valid_ai_result):
    original = copy.deepcopy(report)
    run_pipeline(report, valid_ai_result)
    assert report == original


def test_pipeline_preserves_original_ai_response(report, valid_ai_result):
    original = copy.deepcopy(valid_ai_result)
    run_pipeline(report, valid_ai_result)
    assert valid_ai_result == original
