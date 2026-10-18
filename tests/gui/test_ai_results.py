"""GUI regression tests for LogVigil AI investigation results."""

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtWidgets import QApplication

from soc_assistant.gui.ai_results import AIResultView, format_items


@pytest.fixture(scope="module")
def app():
    instance = QApplication.instance() or QApplication([])
    yield instance


@pytest.fixture
def viewer(app):
    widget = AIResultView()
    yield widget
    widget.close()


def sample_report():
    return {
        "application": "LogVigil",
        "model": "qwen3:4b",
        "ai_attempts": 1,
        "ai_validation_status": "passed_limited_checks",
        "simulation_status": "unknown",
        "verified_evidence": {
            "summary": {"events_analyzed": 5, "findings_count": 1},
            "findings": [{
                "finding_id": "LV-0001", "rule_id": "DET-001",
                "severity": "medium", "computer": "WIN11",
                "username": "testuser", "source_ip": "192.168.10.50",
                "evidence_record_ids": [101, 102, 103, 104, 105],
            }],
        },
        "ai_analysis": {
            "risk_level": "medium",
            "observations": ["Five failed logins", "Review needed"],
            "hypotheses": ["Possible password attack"],
            "recommended_actions": ["Review authentication logs"],
        },
        "ai_evidence_notice": "AI statements require human review.",
    }


def test_viewer_has_four_tabs(viewer):
    assert [viewer.tabs.tabText(i) for i in range(viewer.tabs.count())] == [
        "Overview", "Verified Evidence", "AI Assessment", "Raw JSON"
    ]


def test_verified_evidence_separated_from_ai(viewer):
    viewer.display_report(sample_report())
    evidence = viewer.evidence.toPlainText()
    assessment = viewer.assessment.toPlainText()
    assert "DET-001" in evidence
    assert "WIN11" in evidence
    assert "101" in evidence
    assert "Possible password attack" not in evidence
    assert "Possible password attack" in assessment


def test_assessment_shows_actions_and_review_notice(viewer):
    viewer.display_report(sample_report())
    content = viewer.assessment.toPlainText()
    assert "Risk level: medium" in content
    assert "Review authentication logs" in content
    assert "human review" in content.lower()


def test_literal_newlines_are_normalized():
    content = format_items([r"First observation\n\nSecond sentence", "Another observation"])
    assert r"\n" not in content
    assert "First observation\n\nSecond sentence" in content
    assert "2. Another observation" in content


def test_raw_json_is_unchanged(viewer):
    report = sample_report()
    viewer.display_report(report)
    assert json.loads(viewer.raw.toPlainText()) == report


def test_empty_report_is_safe(viewer):
    viewer.display_report({})
    assert "Not available" in viewer.overview.toPlainText()
    assert "None reported" in viewer.assessment.toPlainText()


def test_invalid_report_is_safe(viewer):
    viewer.display_report(None)
    assert "Invalid investigation result" in viewer.overview.toPlainText()


def test_clear_resets_all_tabs(viewer):
    viewer.display_report(sample_report())
    viewer.clear()
    assert "Run an AI investigation" in viewer.overview.toPlainText()
    assert viewer.raw.toPlainText() == ""
    assert viewer.tabs.currentIndex() == 0
