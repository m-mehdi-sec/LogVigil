"""Tests for advisory-only AI result handling."""

import copy

import pytest

from soc_assistant.ai_safety import sanitize_ai_analysis


@pytest.fixture
def analysis():
    return {
        "risk_level": "high",
        "observations": ["Repeated failed logins"],
        "hypotheses": ["Possible credential attack"],
        "recommended_actions": ["Review authentication logs"],
    }


def test_valid_analysis_is_accepted(analysis):
    result = sanitize_ai_analysis(analysis)
    assert result["risk_level"] == "high"


def test_execution_is_never_authorized(analysis):
    result = sanitize_ai_analysis(analysis)
    assert result["execution_authorized"] is False


def test_human_review_is_required(analysis):
    result = sanitize_ai_analysis(analysis)
    assert result["requires_human_review"] is True


def test_advisory_notice_is_present(analysis):
    result = sanitize_ai_analysis(analysis)
    assert "Human review" in result["advisory_notice"]


def test_command_like_recommendation_remains_text(analysis):
    analysis["recommended_actions"] = [
        "Run rm -rf / on the host"
    ]
    result = sanitize_ai_analysis(analysis)
    assert result["recommended_actions"] == [
        "Run rm -rf / on the host"
    ]
    assert result["execution_authorized"] is False


def test_unexpected_execution_field_is_rejected(analysis):
    analysis["execute_command"] = "whoami"
    with pytest.raises(ValueError):
        sanitize_ai_analysis(analysis)


def test_invalid_risk_is_rejected(analysis):
    analysis["risk_level"] = "extreme"
    with pytest.raises(ValueError):
        sanitize_ai_analysis(analysis)


def test_non_text_action_is_rejected(analysis):
    analysis["recommended_actions"] = [{"command": "whoami"}]
    with pytest.raises(ValueError):
        sanitize_ai_analysis(analysis)


def test_oversized_action_is_rejected(analysis):
    analysis["recommended_actions"] = ["X" * 1001]
    with pytest.raises(ValueError):
        sanitize_ai_analysis(analysis)


def test_original_analysis_is_unchanged(analysis):
    original = copy.deepcopy(analysis)
    sanitize_ai_analysis(analysis)
    assert analysis == original
