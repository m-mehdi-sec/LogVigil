"""Test security boundaries for AI-generated SOC analysis."""

import pytest

from soc_assistant.ai_safety import sanitize_ai_analysis


def valid_analysis():
    return {
        "risk_level": "low",
        "observations": ["Suspicious login activity observed."],
        "hypotheses": [],
        "recommended_actions": ["Review authentication logs."],
    }


def test_ai_cannot_authorize_execution():
    analysis = valid_analysis()
    analysis["execution_authorized"] = True

    with pytest.raises(ValueError, match="Unexpected AI analysis fields"):
        sanitize_ai_analysis(analysis)


def test_ai_cannot_disable_human_review():
    analysis = valid_analysis()
    analysis["requires_human_review"] = False

    with pytest.raises(ValueError, match="Unexpected AI analysis fields"):
        sanitize_ai_analysis(analysis)


def test_ai_response_rejects_too_many_actions():
    analysis = valid_analysis()
    analysis["recommended_actions"] = ["Review logs."] * 21

    with pytest.raises(ValueError, match="Too many AI analysis items"):
        sanitize_ai_analysis(analysis)


def test_ai_response_rejects_oversized_text():
    analysis = valid_analysis()
    analysis["observations"] = ["A" * 1001]

    with pytest.raises(ValueError, match="AI analysis item exceeds size limit"):
        sanitize_ai_analysis(analysis)


def test_ai_response_requires_nonempty_text():
    analysis = valid_analysis()
    analysis["hypotheses"] = ["   "]

    with pytest.raises(ValueError, match="AI analysis item cannot be empty"):
        sanitize_ai_analysis(analysis)


def test_valid_analysis_remains_advisory_only():
    result = sanitize_ai_analysis(valid_analysis())

    assert result["execution_authorized"] is False
    assert result["requires_human_review"] is True
    assert "Human review is required" in result["advisory_notice"]
