from soc_assistant.models import build_analysis_report


def make_finding(rule_id, username, source_ip, evidence):
    return {
        "rule_id": rule_id,
        "severity": "high",
        "computer": "WIN11",
        "username": username,
        "source_ip": source_ip,
        "evidence_record_ids": evidence,
    }


def test_det003_correlates_with_det001_and_det002():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-002", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-003", None, "10.0.0.5", ["e1"]),
    ]

    report = build_analysis_report([], findings)
    results = report["findings"]

    assert results[2]["related_finding_ids"] == [
        "LV-0001", "LV-0002"
    ]
    assert "LV-0003" in results[0]["related_finding_ids"]
    assert "LV-0003" in results[1]["related_finding_ids"]
    assert report["summary"]["investigation_groups_count"] == 1


def test_det003_requires_overlapping_evidence():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-003", None, "10.0.0.5", ["e2"]),
    ]

    report = build_analysis_report([], findings)

    assert all(
        not finding["related_finding_ids"]
        for finding in report["findings"]
    )
    assert report["summary"]["investigation_groups_count"] == 2


def test_det003_requires_same_source_ip():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-003", None, "10.0.0.9", ["e1"]),
    ]

    report = build_analysis_report([], findings)

    assert all(
        not finding["related_finding_ids"]
        for finding in report["findings"]
    )
    assert report["summary"]["investigation_groups_count"] == 2


def test_det003_requires_same_computer():
    first = make_finding("DET-001", "alice", "10.0.0.5", ["e1"])
    second = make_finding("DET-003", None, "10.0.0.5", ["e1"])
    second["computer"] = "WIN-SRV2025"

    report = build_analysis_report([], [first, second])

    assert all(
        not finding["related_finding_ids"]
        for finding in report["findings"]
    )
    assert report["summary"]["investigation_groups_count"] == 2


def test_det003_does_not_correlate_without_source_ip():
    first = make_finding("DET-001", "alice", None, ["e1"])
    second = make_finding("DET-003", None, None, ["e1"])

    report = build_analysis_report([], [first, second])

    assert all(
        not finding["related_finding_ids"]
        for finding in report["findings"]
    )
    assert report["summary"]["investigation_groups_count"] == 2


def test_det001_det002_require_same_username():
    first = make_finding("DET-001", "alice", "10.0.0.5", ["e1"])
    second = make_finding("DET-002", "bob", "10.0.0.5", ["e1"])

    report = build_analysis_report([], [first, second])

    assert all(
        not finding["related_finding_ids"]
        for finding in report["findings"]
    )
    assert report["summary"]["investigation_groups_count"] == 2


def test_multiple_independent_investigation_groups():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-002", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-003", None, "10.0.0.5", ["e1"]),
        make_finding("DET-001", "bob", "10.0.0.9", ["e2"]),
        make_finding("DET-002", "bob", "10.0.0.9", ["e2"]),
        make_finding("DET-003", None, "10.0.0.9", ["e2"]),
    ]

    report = build_analysis_report([], findings)
    results = report["findings"]

    first_group = {"LV-0001", "LV-0002", "LV-0003"}
    second_group = {"LV-0004", "LV-0005", "LV-0006"}

    assert report["summary"]["findings_count"] == 6
    assert report["summary"]["investigation_groups_count"] == 2

    for finding in results[:3]:
        assert set(finding["related_finding_ids"]) == (
            first_group - {finding["finding_id"]}
        )

    for finding in results[3:]:
        assert set(finding["related_finding_ids"]) == (
            second_group - {finding["finding_id"]}
        )


def test_indirect_correlation_forms_one_investigation_group():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-003", None, "10.0.0.5", ["e1", "e2"]),
        make_finding("DET-002", "bob", "10.0.0.5", ["e2"]),
    ]

    report = build_analysis_report([], findings)
    results = report["findings"]

    assert results[0]["related_finding_ids"] == ["LV-0002"]
    assert results[1]["related_finding_ids"] == [
        "LV-0001", "LV-0003"
    ]
    assert results[2]["related_finding_ids"] == ["LV-0002"]

    assert report["summary"]["findings_count"] == 3
    assert report["summary"]["investigation_groups_count"] == 1


def test_same_source_without_shared_evidence_stays_separate():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-002", "alice", "10.0.0.5", ["e2"]),
        make_finding("DET-003", None, "10.0.0.5", ["e3"]),
    ]

    report = build_analysis_report([], findings)

    assert report["summary"]["findings_count"] == 3
    assert report["summary"]["investigation_groups_count"] == 3

    for finding in report["findings"]:
        assert finding["related_finding_ids"] == []


def test_empty_evidence_does_not_create_correlation():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", []),
        make_finding("DET-002", "alice", "10.0.0.5", []),
        make_finding("DET-003", None, "10.0.0.5", []),
    ]

    report = build_analysis_report([], findings)

    assert report["summary"]["investigation_groups_count"] == 3

    for finding in report["findings"]:
        assert finding["related_finding_ids"] == []


def test_missing_evidence_field_does_not_create_correlation():
    first = make_finding("DET-001", "alice", "10.0.0.5", ["e1"])
    second = make_finding("DET-003", None, "10.0.0.5", ["e1"])

    del second["evidence_record_ids"]

    report = build_analysis_report([], [first, second])

    assert report["summary"]["investigation_groups_count"] == 2

    for finding in report["findings"]:
        assert finding["related_finding_ids"] == []


def test_unrelated_detection_rules_remain_separate():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-002", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-003", None, "10.0.0.5", ["e1"]),
        make_finding("DET-004", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-005", "alice", "10.0.0.5", ["e1"]),
    ]

    report = build_analysis_report([], findings)
    results = report["findings"]

    assert report["summary"]["findings_count"] == 5
    assert report["summary"]["investigation_groups_count"] == 3

    assert set(results[0]["related_finding_ids"]) == {
        "LV-0002", "LV-0003"
    }
    assert set(results[1]["related_finding_ids"]) == {
        "LV-0001", "LV-0003"
    }
    assert set(results[2]["related_finding_ids"]) == {
        "LV-0001", "LV-0002"
    }

    assert results[3]["related_finding_ids"] == []
    assert results[4]["related_finding_ids"] == []


def test_report_does_not_modify_original_findings():
    from copy import deepcopy

    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-002", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-003", None, "10.0.0.5", ["e1"]),
    ]

    original = deepcopy(findings)

    report = build_analysis_report([], findings)

    assert findings == original

    for finding in findings:
        assert "finding_id" not in finding
        assert "related_finding_ids" not in finding

    assert report["summary"]["investigation_groups_count"] == 1
    assert all(
        "finding_id" in finding
        and "related_finding_ids" in finding
        for finding in report["findings"]
    )


def test_report_is_deterministic():
    findings = [
        make_finding("DET-001", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-002", "alice", "10.0.0.5", ["e1"]),
        make_finding("DET-003", None, "10.0.0.5", ["e1"]),
        make_finding("DET-004", "bob", "10.0.0.9", ["e2"]),
    ]

    first_report = build_analysis_report([], findings)
    second_report = build_analysis_report([], findings)

    assert first_report == second_report

    assert first_report["summary"]["investigation_groups_count"] == 2

    for finding in first_report["findings"]:
        related_ids = finding["related_finding_ids"]

        assert len(related_ids) == len(set(related_ids))
        assert finding["finding_id"] not in related_ids


def test_empty_report_has_no_investigation_groups():
    report = build_analysis_report([], [])

    assert report["application"] == "LogVigil"
    assert report["schema_version"] == "1.0"
    assert report["findings"] == []

    summary = report["summary"]

    assert summary["events_analyzed"] == 0
    assert summary["findings_count"] == 0
    assert summary["investigation_groups_count"] == 0
    assert summary["highest_severity"] is None

    assert summary["severity_counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }
