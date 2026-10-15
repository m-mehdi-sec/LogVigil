"""Tests for bounded AI evidence validation."""

import copy

import pytest

from soc_assistant.ai_evidence import validate_ai_evidence


def sample_analysis():
    return {
        "risk_level": "medium",
        "observations": ["Five failed Windows logins detected"],
        "hypotheses": ["Possible password guessing activity"],
        "recommended_actions": ["Review authentication events"],
    }


def test_valid_analysis_is_accepted():
    analysis = sample_analysis()
    assert validate_ai_evidence(analysis, {}) == analysis


def test_documentation_ip_used_as_simulation_proof_is_rejected():
    analysis = sample_analysis()
    analysis["observations"] = [
        "192.0.2.50 indicates this is a controlled environment"
    ]

    with pytest.raises(ValueError, match="documentation IP"):
        validate_ai_evidence(analysis, {})


def test_documentation_ip_in_hypothesis_is_rejected():
    analysis = sample_analysis()
    analysis["hypotheses"] = [
        "This is a simulation given the documentation IP 192.0.2.50"
    ]

    with pytest.raises(ValueError, match="documentation IP"):
        validate_ai_evidence(analysis, {})


def test_documentation_ip_as_evidence_is_allowed():
    analysis = sample_analysis()
    analysis["observations"] = [
        "Failed logins originated from 192.0.2.50"
    ]

    assert validate_ai_evidence(analysis, {}) == analysis


def test_unsupported_account_compromise_claim_is_rejected():
    analysis = sample_analysis()
    analysis["hypotheses"] = [
        "The test-user account may be intentionally compromised"
    ]

    with pytest.raises(ValueError, match="account compromise"):
        validate_ai_evidence(analysis, {})


def test_evidence_validation_does_not_modify_analysis():
    analysis = sample_analysis()
    original = copy.deepcopy(analysis)

    validate_ai_evidence(analysis, {})

    assert analysis == original



def test_possible_account_compromise_is_allowed():
    analysis = sample_analysis()
    analysis["hypotheses"] = [
        "Possible account compromise following repeated failed logins "
        "and a successful login"
    ]

    assert validate_ai_evidence(analysis, {}) == analysis


def test_deliberately_compromised_test_account_is_rejected():
    analysis = sample_analysis()
    analysis["hypotheses"] = [
        "The test-user account may be deliberately compromised"
    ]

    with pytest.raises(ValueError, match="account compromise"):
        validate_ai_evidence(analysis, {})



def test_documentation_ip_in_review_recommendation_is_allowed():
    analysis = sample_analysis()
    analysis["recommended_actions"] = [
        "Review the documentation IP 192.0.2.50 in the test environment"
    ]

    assert validate_ai_evidence(analysis, {}) == analysis


def test_documentation_ip_description_is_allowed():
    analysis = sample_analysis()
    analysis["observations"] = [
        "Source IP 192.0.2.50 is a documentation address"
    ]

    assert validate_ai_evidence(analysis, {}) == analysis



def test_real_qwen_observation_is_rejected():
    analysis = sample_analysis()
    analysis["observations"] = [
        "Source IP 192.0.2.50 classified as documentation IP range "
        "(192.0.2.0/24), indicating this is a controlled environment "
        "or test network"
    ]

    with pytest.raises(ValueError, match="documentation IP"):
        validate_ai_evidence(analysis, {})


def test_real_qwen_compromise_hypothesis_is_rejected():
    analysis = sample_analysis()
    analysis["hypotheses"] = [
        "The test-user account may be intentionally compromised "
        "in the simulation to demonstrate detection capabilities"
    ]

    with pytest.raises(ValueError, match="account compromise"):
        validate_ai_evidence(analysis, {})


def test_real_qwen_ip_recommendation_is_allowed():
    analysis = sample_analysis()
    analysis["recommended_actions"] = [
        "Confirm that the source IP 192.0.2.50 is part of the "
        "intended test environment and not a misconfigured production system"
    ]

    assert validate_ai_evidence(analysis, {}) == analysis
