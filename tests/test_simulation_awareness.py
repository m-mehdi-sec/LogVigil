"""Regression tests for explicit simulation declarations."""

import json
import sys
from unittest.mock import patch

import pytest

from soc_assistant.ai_analyzer import build_ai_request
from soc_assistant.ai_context import build_ai_context
from soc_assistant.ai_pipeline import analyze_soc_report
from soc_assistant import main as cli


@pytest.fixture
def report():
    return {
        "application": "LogVigil",
        "schema_version": "1.0",
        "summary": {
            "events_analyzed": 1,
            "findings_count": 1,
            "investigation_groups_count": 1,
        },
        "findings": [{
            "finding_id": "LV-0001",
            "rule_id": "DET-001",
            "severity": "medium",
            "source_ip": "192.0.2.50",
        }],
        "investigation_groups": [{
            "investigation_id": "INV-0001",
            "highest_severity": "medium",
            "finding_ids": ["LV-0001"],
        }],
    }


@pytest.mark.parametrize(
    ("simulation", "expected"),
    [
        (True, "user_declared_simulation"),
        (False, "unknown"),
    ],
)
def test_simulation_context(report, simulation, expected):
    context = build_ai_context(report, simulation=simulation)
    assert context["simulation_status"] == expected


def test_documentation_ip_does_not_imply_simulation(report):
    context = build_ai_context(report)
    assert context["simulation_status"] == "unknown"


@pytest.mark.parametrize("value", [None, 1, "true", [], {}])
def test_invalid_simulation_type_rejected(report, value):
    with pytest.raises(ValueError):
        build_ai_context(report, simulation=value)


def test_ai_request_contains_simulation_instructions(report):
    context = build_ai_context(report, simulation=True)
    request = build_ai_request(context)
    assert "controlled simulation" in request["system"]
    assert "user_declared_simulation" in request["user"]


def test_pipeline_forwards_simulation(report):
    ai_result = {
        "risk_level": "medium",
        "observations": ["Five failed logins"],
        "hypotheses": ["Possible credential attack"],
        "recommended_actions": ["Review the logs"],
    }

    with patch(
        "soc_assistant.ai_pipeline.analyze_with_ollama",
        return_value=ai_result,
    ) as mocked:
        result = analyze_soc_report(report, simulation=True)

    assert "user_declared_simulation" in mocked.call_args.args[0]["user"]
    assert result["ai_analysis"]["execution_authorized"] is False
    assert result["ai_analysis"]["requires_human_review"] is True


def test_cli_simulation_context(tmp_path, monkeypatch, capsys):
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps({
            "event_id": 4625,
            "timestamp": "2026-10-15T10:00:00Z",
            "computer": "LAB-WIN11",
            "username": "test-user",
            "source_ip": "192.0.2.50",
        }) + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys, "argv",
        ["logvigil", str(path), "--ai-context", "--simulation"],
    )

    cli.main()

    result = json.loads(capsys.readouterr().out)
    assert result["simulation_status"] == "user_declared_simulation"


def test_cli_simulation_rejected_without_ai_mode(
    tmp_path, monkeypatch
):
    path = tmp_path / "events.jsonl"
    path.write_text("{}\n", encoding="utf-8")

    monkeypatch.setattr(
        sys, "argv",
        ["logvigil", str(path), "--simulation"],
    )

    with pytest.raises(SystemExit) as error:
        cli.main()

    assert error.value.code == 2


@pytest.mark.parametrize(
    ("simulation", "expected"),
    [
        (True, "user_declared_simulation"),
        (False, "unknown"),
    ],
)
def test_pipeline_exposes_simulation_status(report, simulation, expected):
    ai_result = {
        "risk_level": "low",
        "observations": [],
        "hypotheses": [],
        "recommended_actions": [],
    }

    with patch(
        "soc_assistant.ai_pipeline.analyze_with_ollama",
        return_value=ai_result,
    ):
        result = analyze_soc_report(report, simulation=simulation)

    assert result["simulation_status"] == expected
    assert result["ai_analysis"]["execution_authorized"] is False
    assert result["ai_analysis"]["requires_human_review"] is True
