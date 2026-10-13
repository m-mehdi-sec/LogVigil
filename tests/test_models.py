from soc_assistant.models import build_analysis_report


def test_analysis_report_structure():
    events = [
        {"event_id": 4625},
        {"event_id": 4625},
    ]
    findings = [
        {"rule_id": "DET-001", "status": "needs_review"}
    ]

    report = build_analysis_report(events, findings)

    assert report["application"] == "LogVigil"
    assert report["schema_version"] == "1.0"
    assert report["summary"]["events_analyzed"] == 2
    assert report["summary"]["findings_count"] == 1
    assert report["findings"] == [
        {
            **findings[0],
            "finding_id": "LV-0001",
            "related_finding_ids": [],
            "investigation_id": "INV-0001",
        }
    ]
    assert "finding_id" not in findings[0]



def test_report_counts_findings_by_severity():
    from soc_assistant.models import build_analysis_report

    events = [{} for _ in range(6)]

    findings = [
        {"rule_id": "DET-002", "severity": "high"},
        {"rule_id": "DET-001", "severity": "medium"},
    ]

    report = build_analysis_report(events, findings)
    summary = report["summary"]

    assert summary["events_analyzed"] == 6
    assert summary["findings_count"] == 2
    assert summary["severity_counts"] == {
        "critical": 0,
        "high": 1,
        "medium": 1,
        "low": 0,
        "informational": 0,
    }



def test_report_generates_unique_finding_ids():
    from soc_assistant.models import build_analysis_report

    findings = [
        {"rule_id": "DET-002", "severity": "high"},
        {"rule_id": "DET-001", "severity": "medium"},
    ]

    report = build_analysis_report([{}] * 6, findings)

    assert [f["finding_id"] for f in report["findings"]] == [
        "LV-0001",
        "LV-0002",
    ]

    assert all("finding_id" not in f for f in findings)



def test_related_findings_share_evidence():
    from soc_assistant.models import build_analysis_report

    findings = [
        {
            "rule_id": "DET-002",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
            "evidence_record_ids": [101, 102, 103, 104, 105, 106],
        },
        {
            "rule_id": "DET-001",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
            "evidence_record_ids": [101, 102, 103, 104, 105],
        },
    ]

    report = build_analysis_report([], findings)
    first, second = report["findings"]

    assert first["related_finding_ids"] == ["LV-0002"]
    assert second["related_finding_ids"] == ["LV-0001"]


def test_unrelated_findings_from_different_ips():
    from soc_assistant.models import build_analysis_report

    findings = [
        {
            "rule_id": "DET-002",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
            "evidence_record_ids": [101, 102, 103, 104, 105],
        },
        {
            "rule_id": "DET-001",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.99",
            "evidence_record_ids": [101, 102, 103, 104, 105],
        },
    ]

    report = build_analysis_report([], findings)

    assert all(
        finding["related_finding_ids"] == []
        for finding in report["findings"]
    )



def test_investigation_groups_count():
    from soc_assistant.models import build_analysis_report

    findings = [
        {
            "rule_id": "DET-002",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
            "evidence_record_ids": [101, 102, 103, 104, 105, 106],
        },
        {
            "rule_id": "DET-001",
            "computer": "WIN11",
            "username": "testuser",
            "source_ip": "192.168.10.50",
            "evidence_record_ids": [101, 102, 103, 104, 105],
        },
        {
            "rule_id": "DET-001",
            "computer": "WIN11",
            "username": "otheruser",
            "source_ip": "192.168.10.99",
            "evidence_record_ids": [201, 202, 203, 204, 205],
        },
    ]

    report = build_analysis_report([], findings)

    assert report["summary"]["findings_count"] == 3
    assert report["summary"]["investigation_groups_count"] == 2

    empty_report = build_analysis_report([], [])
    assert empty_report["summary"]["investigation_groups_count"] == 0



def test_report_highest_severity():
    from soc_assistant.models import build_analysis_report

    findings = [
        {"rule_id": "DET-001", "severity": "medium"},
        {"rule_id": "DET-002", "severity": "high"},
    ]

    report = build_analysis_report([], findings)

    assert report["summary"]["highest_severity"] == "high"

    empty_report = build_analysis_report([], [])
    assert empty_report["summary"]["highest_severity"] is None
