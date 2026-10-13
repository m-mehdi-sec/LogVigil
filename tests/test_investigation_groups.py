from soc_assistant.models import build_analysis_report


def finding(rule_id, username, ip, evidence, severity):
    return {
        "rule_id": rule_id,
        "computer": "WIN11",
        "username": username,
        "source_ip": ip,
        "evidence_record_ids": evidence,
        "severity": severity,
    }


def test_investigation_groups_have_unique_ids():
    findings = [
        finding("DET-001", "alice", "10.0.0.5", ["e1"], "medium"),
        finding("DET-002", "alice", "10.0.0.5", ["e1"], "high"),
        finding("DET-004", "bob", "10.0.0.9", ["e2"], "critical"),
    ]

    report = build_analysis_report([], findings)
    groups = report["investigation_groups"]

    assert len(groups) == 2
    assert groups[0] == {
        "investigation_id": "INV-0001",
        "finding_ids": ["LV-0001", "LV-0002"],
        "findings_count": 2,
        "highest_severity": "high",
    }
    assert groups[1]["investigation_id"] == "INV-0002"
    assert groups[1]["finding_ids"] == ["LV-0003"]
    assert groups[1]["highest_severity"] == "critical"


def test_findings_reference_their_investigation():
    findings = [
        finding("DET-001", "alice", "10.0.0.5", ["e1"], "medium"),
        finding("DET-002", "alice", "10.0.0.5", ["e1"], "high"),
        finding("DET-004", "bob", "10.0.0.9", ["e2"], "low"),
    ]

    report = build_analysis_report([], findings)

    assert [
        item["investigation_id"]
        for item in report["findings"]
    ] == ["INV-0001", "INV-0001", "INV-0002"]


def test_indirect_correlation_creates_one_group():
    findings = [
        finding("DET-001", "alice", "10.0.0.5", ["e1"], "low"),
        finding("DET-003", None, "10.0.0.5", ["e1", "e2"], "high"),
        finding("DET-002", "bob", "10.0.0.5", ["e2"], "medium"),
    ]

    report = build_analysis_report([], findings)

    assert report["summary"]["investigation_groups_count"] == 1
    assert report["investigation_groups"][0]["finding_ids"] == [
        "LV-0001", "LV-0002", "LV-0003"
    ]
    assert report["investigation_groups"][0]["highest_severity"] == "high"


def test_empty_report_has_no_investigations():
    report = build_analysis_report([], [])

    assert report["investigation_groups"] == []
    assert report["summary"]["investigation_groups_count"] == 0


def test_investigation_groups_are_deterministic():
    findings = [
        finding("DET-004", "bob", "10.0.0.9", ["e2"], "high"),
        finding("DET-001", "alice", "10.0.0.5", ["e1"], "low"),
        finding("DET-002", "alice", "10.0.0.5", ["e1"], "medium"),
    ]

    first = build_analysis_report([], findings)
    second = build_analysis_report([], findings)

    assert first == second
    assert first["investigation_groups"][0]["finding_ids"] == [
        "LV-0001"
    ]
    assert first["investigation_groups"][1]["finding_ids"] == [
        "LV-0002", "LV-0003"
    ]
