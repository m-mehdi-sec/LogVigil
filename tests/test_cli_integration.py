"""Integration tests for the LogVigil command-line interface."""

import json
import subprocess
import sys

import pytest


@pytest.fixture
def cli_log_file(tmp_path):
    """Create a synthetic Windows event log."""
    path = tmp_path / "synthetic.jsonl"

    events = [
        {
            "event_id": 4625,
            "timestamp": f"2026-10-13T10:00:{i:02d}Z",
            "computer": "WIN11",
            "username": "alice",
            "source_ip": "10.0.0.5",
        }
        for i in range(5)
    ]

    path.write_text(
        "".join(json.dumps(event) + "\n" for event in events),
        encoding="utf-8",
    )

    return path


def run_cli(*args):
    """Execute LogVigil in a separate Python process."""
    return subprocess.run(
        [sys.executable, "-m", "soc_assistant.main", *map(str, args)],
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_generates_json_report(cli_log_file):
    result = run_cli(cli_log_file, "--report")

    assert result.returncode == 0, result.stderr

    report = json.loads(result.stdout)

    assert report["application"] == "LogVigil"
    assert report["summary"]["events_analyzed"] == 5
    assert "investigation_groups" in report


def test_cli_displays_readable_summary(cli_log_file):
    result = run_cli(cli_log_file, "--report", "--summary")

    assert result.returncode == 0, result.stderr
    assert "LogVigil - SOC Analysis Summary" in result.stdout
    assert "Events analyzed: 5" in result.stdout
    assert "Investigation groups:" in result.stdout


def test_cli_saves_json_report(cli_log_file, tmp_path):
    output = tmp_path / "reports" / "report.json"

    result = run_cli(
        cli_log_file, "--report", "--output", output
    )

    assert result.returncode == 0, result.stderr
    assert output.exists()

    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["application"] == "LogVigil"
    assert "investigation_groups" in report


def test_cli_saves_text_summary(cli_log_file, tmp_path):
    output = tmp_path / "summary.txt"

    result = run_cli(
        cli_log_file,
        "--report",
        "--summary",
        "--output",
        output,
    )

    assert result.returncode == 0, result.stderr

    content = output.read_text(encoding="utf-8")

    assert "LogVigil - SOC Analysis Summary" in content
    assert "Events analyzed: 5" in content


def test_summary_requires_report(cli_log_file):
    result = run_cli(cli_log_file, "--summary")

    assert result.returncode != 0
    assert "--summary requires --report" in result.stderr


def test_cli_does_not_overwrite_existing_report(
    cli_log_file, tmp_path
):
    output = tmp_path / "existing.json"
    output.write_text("ORIGINAL DATA", encoding="utf-8")

    result = run_cli(
        cli_log_file, "--report", "--output", output
    )

    assert result.returncode != 0
    assert "Error saving results:" in result.stderr
    assert output.read_text(encoding="utf-8") == "ORIGINAL DATA"


def test_cli_ai_context_json(cli_log_file):
    result = run_cli(cli_log_file, "--ai-context")

    assert result.returncode == 0, result.stderr

    context = json.loads(result.stdout)

    assert context["application"] == "LogVigil"
    assert context["context_version"] == "1.0"
    assert "investigations" in context


def test_cli_ai_context_limits(cli_log_file):
    result = run_cli(
        cli_log_file,
        "--ai-context",
        "--max-groups", "1",
        "--max-findings", "1",
    )

    assert result.returncode == 0, result.stderr

    context = json.loads(result.stdout)

    assert context["limits"]["max_groups"] == 1
    assert context["limits"]["max_findings"] == 1
    assert len(context["investigations"]) <= 1
    assert sum(
        len(group["findings"])
        for group in context["investigations"]
    ) <= 1


def test_cli_ai_context_output(cli_log_file, tmp_path):
    output = tmp_path / "ai_context.json"

    result = run_cli(
        cli_log_file,
        "--ai-context",
        "--output",
        output,
    )

    assert result.returncode == 0, result.stderr
    assert output.exists()

    context = json.loads(output.read_text(encoding="utf-8"))

    assert context["application"] == "LogVigil"


def test_cli_rejects_conflicting_modes(cli_log_file):
    result = run_cli(
        cli_log_file, "--ai-context", "--report"
    )

    assert result.returncode != 0
    assert "cannot be combined" in result.stderr


def test_cli_rejects_invalid_ai_limits(cli_log_file):
    result = run_cli(
        cli_log_file,
        "--ai-context",
        "--max-groups", "0",
    )

    assert result.returncode != 0
    assert "AI context limits must be positive" in result.stderr
