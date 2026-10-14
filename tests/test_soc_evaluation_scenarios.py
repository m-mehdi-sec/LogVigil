"""Validate the human-reviewed SOC evaluation scenarios."""

import json
from pathlib import Path


SCENARIO_FILE = (
    Path(__file__).resolve().parents[1]
    / "evaluation"
    / "soc_scenarios.json"
)

VALID_RULE_IDS = {
    "DET-001",
    "DET-002",
    "DET-003",
    "DET-004",
    "DET-005",
}


def test_evaluation_scenarios_are_valid():
    data = json.loads(SCENARIO_FILE.read_text(encoding="utf-8"))

    assert data["evaluation_version"] == "1.0"

    scenarios = data["scenarios"]
    assert len(scenarios) == 5

    ids = [scenario["id"] for scenario in scenarios]
    assert len(ids) == len(set(ids))

    for scenario in scenarios:
        assert scenario["id"].startswith("SOC-")
        assert isinstance(scenario["name"], str)
        assert scenario["name"].strip()

        assert set(scenario["rule_ids"]) <= VALID_RULE_IDS

        for field in (
            "expected_observations",
            "acceptable_hypotheses",
            "unsupported_conclusions",
        ):
            values = scenario[field]

            assert isinstance(values, list)
            assert values
            assert all(
                isinstance(value, str) and value.strip()
                for value in values
            )


def test_evaluation_includes_missing_telemetry():
    data = json.loads(SCENARIO_FILE.read_text(encoding="utf-8"))

    scenario = next(
        item for item in data["scenarios"]
        if item["id"] == "SOC-004"
    )

    assert scenario["data_quality_warning_count"] == 5
    assert scenario["rule_ids"] == []


def test_evaluation_includes_no_findings():
    data = json.loads(SCENARIO_FILE.read_text(encoding="utf-8"))

    scenario = next(
        item for item in data["scenarios"]
        if item["id"] == "SOC-005"
    )

    assert scenario["rule_ids"] == []
    assert scenario["data_quality_warning_count"] == 0
