from soc_assistant.main import format_summary


def test_summary_with_investigations():
    report = {
        "summary": {
            "events_analyzed": 120,
            "findings_count": 3,
            "investigation_groups_count": 1,
            "highest_severity": "high",
        },
        "investigation_groups": [
            {
                "investigation_id": "INV-0001",
                "finding_ids": ["LV-0001", "LV-0002", "LV-0003"],
                "findings_count": 3,
                "highest_severity": "high",
            }
        ],
    }

    output = format_summary(report)

    assert "Events analyzed: 120" in output
    assert "Findings: 3" in output
    assert "Investigation groups: 1" in output
    assert "Highest severity: HIGH" in output
    assert "INV-0001 | HIGH | 3 findings" in output
    assert "LV-0001, LV-0002, LV-0003" in output


def test_summary_without_findings():
    report = {
        "summary": {
            "events_analyzed": 10,
            "findings_count": 0,
            "investigation_groups_count": 0,
            "highest_severity": None,
        },
        "investigation_groups": [],
    }

    output = format_summary(report)

    assert "Events analyzed: 10" in output
    assert "Findings: 0" in output
    assert "Investigation groups: 0" in output
    assert "Highest severity: NONE" in output
    assert "INV-0001" not in output
