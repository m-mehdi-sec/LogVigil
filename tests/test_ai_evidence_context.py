"""Tests for bounded evidence and source IP context."""

import copy

from soc_assistant.ai_context import build_ai_context


def make_report(source_ip, evidence_ids):
    return {
        "summary": {
            "events_analyzed": 5,
            "findings_count": 1,
            "investigation_groups_count": 1,
        },
        "findings": [{
            "finding_id": "LV-0001",
            "rule_id": "DET-001",
            "severity": "medium",
            "source_ip": source_ip,
            "evidence_record_ids": evidence_ids,
        }],
        "investigation_groups": [{
            "investigation_id": "INV-0001",
            "highest_severity": "medium",
            "finding_ids": ["LV-0001"],
        }],
    }


def get_finding(report):
    return build_ai_context(report)["investigations"][0]["findings"][0]


def test_documentation_ip_classification():
    finding = get_finding(make_report("192.0.2.50", [101, 102]))
    assert finding["source_ip_classification"] == "documentation"


def test_private_ip_classification():
    finding = get_finding(make_report("192.168.10.20", [101]))
    assert finding["source_ip_classification"] == "private"


def test_evidence_ids_preserved():
    finding = get_finding(make_report("192.0.2.50", [101, 102]))
    assert finding["evidence_record_ids"] == [101, 102]


def test_evidence_ids_bounded():
    finding = get_finding(make_report("192.0.2.50", list(range(100))))
    assert len(finding["evidence_record_ids"]) == 20


def test_invalid_evidence_ids_excluded():
    finding = get_finding(
        make_report("192.0.2.50", [101, True, "102", -1, 103])
    )
    assert finding["evidence_record_ids"] == [101, 103]


def test_missing_evidence_ids_not_invented():
    report = make_report("192.0.2.50", None)
    finding = get_finding(report)
    assert "evidence_record_ids" not in finding


def test_original_report_unchanged():
    report = make_report("192.0.2.50", [101, 102])
    original = copy.deepcopy(report)

    get_finding(report)

    assert report == original
