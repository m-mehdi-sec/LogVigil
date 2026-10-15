"""Tests for local AI SOC request preparation."""

import json

import pytest

from soc_assistant.ai_analyzer import (
    MAX_CONTEXT_BYTES,
    build_ai_request,
    parse_ai_response,
    validate_ai_response,
)


def sample_context():
    return {
        "application": "LogVigil",
        "context_version": "1.0",
        "investigations": [],
    }


def sample_response():
    return {
        "risk_level": "high",
        "observations": ["Multiple failed logins"],
        "hypotheses": ["Possible brute-force activity"],
        "recommended_actions": ["Review authentication logs"],
    }


def test_request_has_separate_instructions():
    request = build_ai_request(sample_context())

    assert "system" in request
    assert "user" in request
    assert request["response_format"] == "json"


def test_request_warns_about_untrusted_data():
    request = build_ai_request(sample_context())

    assert "untrusted" in request["system"]
    assert "untrusted" in request["user"]


def test_invalid_application_rejected():
    context = sample_context()
    context["application"] = "Other"

    with pytest.raises(ValueError):
        build_ai_request(context)


def test_unsupported_context_version_rejected():
    context = sample_context()
    context["context_version"] = "2.0"

    with pytest.raises(ValueError):
        build_ai_request(context)


def test_context_size_limit():
    context = sample_context()
    context["padding"] = "x" * MAX_CONTEXT_BYTES

    with pytest.raises(ValueError):
        build_ai_request(context)


def test_valid_response_accepted():
    response = sample_response()

    assert validate_ai_response(response) == response


def test_missing_response_field_rejected():
    response = sample_response()
    del response["hypotheses"]

    with pytest.raises(ValueError):
        validate_ai_response(response)


def test_invalid_risk_level_rejected():
    response = sample_response()
    response["risk_level"] = "extreme"

    with pytest.raises(ValueError):
        validate_ai_response(response)


def test_invalid_recommendations_rejected():
    response = sample_response()
    response["recommended_actions"] = ["Review logs", 42]

    with pytest.raises(ValueError):
        validate_ai_response(response)


def test_json_response_parsing():
    response = sample_response()

    assert parse_ai_response(json.dumps(response)) == response



def test_request_rejects_ip_based_simulation_inference():
    request = build_ai_request(sample_context())
    instructions = request["system"]

    assert "192.0.2.0/24" in instructions
    assert "198.51.100.0/24" in instructions
    assert "203.0.113.0/24" in instructions
    assert "do not cite IP address classification as proof" in instructions
    assert "Only simulation_status" in instructions


def test_request_distinguishes_failed_logins_from_compromise():
    request = build_ai_request(sample_context())
    instructions = request["system"]

    assert "Failed logins alone do not establish" in instructions
    assert "without supporting evidence" in instructions
    assert "do not invent attack objectives or exercise goals" in instructions


def test_request_preserves_human_review_and_investigation():
    request = build_ai_request(sample_context())
    instructions = request["system"]

    assert "Do not recommend automatic blocking" in instructions
    assert "recommend reviewing the" in instructions
    assert "simulated detection and investigation workflow" in instructions
