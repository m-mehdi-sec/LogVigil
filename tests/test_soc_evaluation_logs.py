"""Integration tests for synthetic SOC evaluation logs."""

import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVALUATION_LOGS = PROJECT_ROOT / "evaluation" / "logs"


def run_logvigil_report(filename):
    """Run LogVigil CLI against a synthetic evaluation log."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_assistant.main",
            str(EVALUATION_LOGS / filename),
            "--report",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=15,
    )

    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_soc_001_repeated_failed_logins():
    report = run_logvigil_report(
        "soc_001_failed_logins.jsonl"
    )

    assert report["summary"]["events_analyzed"] == 5
    assert report["summary"]["findings_count"] == 1
    assert report["summary"]["investigation_groups_count"] == 1

    finding = report["findings"][0]

    assert finding["rule_id"] == "DET-001"
    assert finding["severity"] == "medium"
    assert finding["status"] == "needs_review"
    assert finding["event_count"] == 5
    assert finding["username"] == "testuser"
    assert finding["source_ip"] == "192.0.2.10"

    assert report["data_quality_warnings"] == []


def test_soc_002_success_after_failures():
    """Verify correlated failed and successful logins."""
    report = run_logvigil_report(
        "soc_002_success_after_failures.jsonl"
    )

    summary = report["summary"]

    assert summary["events_analyzed"] == 6
    assert summary["findings_count"] == 2
    assert summary["investigation_groups_count"] == 1
    assert summary["highest_severity"] == "high"

    findings = {
        finding["rule_id"]: finding
        for finding in report["findings"]
    }

    assert set(findings) == {"DET-001", "DET-002"}

    failed = findings["DET-001"]
    successful = findings["DET-002"]

    assert failed["severity"] == "medium"
    assert successful["severity"] == "high"

    assert failed["status"] == "needs_review"
    assert successful["status"] == "needs_review"

    assert failed["investigation_id"] == successful["investigation_id"]
    assert successful["finding_id"] in failed["related_finding_ids"]
    assert failed["finding_id"] in successful["related_finding_ids"]

    assert report["data_quality_warnings"] == []
