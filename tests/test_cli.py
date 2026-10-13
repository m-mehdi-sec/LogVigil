import subprocess
import sys


def test_missing_log_file():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_assistant.main",
            "data/samples/finns_inte.jsonl",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "Error:" in result.stderr
    assert "No such file or directory" in result.stderr
    assert "Traceback" not in result.stderr


def test_logvigil_command():
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    log_file = project_root / "data/samples/failed_logins.jsonl"

    result = subprocess.run(
        [sys.executable, "-m", "soc_assistant.main", str(log_file)],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert '"rule_id": "DET-001"' in result.stdout
    assert '"status": "needs_review"' in result.stdout


def test_json_export(tmp_path):
    import json
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    log_file = project_root / "data/samples/failed_logins.jsonl"
    output_file = tmp_path / "results.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_assistant.main",
            str(log_file),
            "--output",
            str(output_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert "Results saved to:" in result.stdout
    assert output_file.is_file()

    findings = json.loads(output_file.read_text(encoding="utf-8"))
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "DET-001"
    assert findings[0]["status"] == "needs_review"


def test_json_export_does_not_overwrite_existing_file(tmp_path):
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    log_file = project_root / "data/samples/failed_logins.jsonl"
    output_file = tmp_path / "existing.json"
    original_content = '{"important": "keep this"}\n'
    output_file.write_text(original_content, encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_assistant.main",
            str(log_file),
            "--output",
            str(output_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert "Error saving results:" in result.stderr
    assert output_file.read_text(encoding="utf-8") == original_content


def test_cli_no_findings(tmp_path):
    import json

    log_file = tmp_path / "normal_logins.jsonl"
    log_file.write_text(
        '{"event_id": 4625, "timestamp": "2026-10-12T10:00:00+02:00", '
        '"computer": "WIN11", "username": "testuser", '
        '"source_ip": "192.168.10.50", "record_id": 201}\n',
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_assistant.main",
            str(log_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert json.loads(result.stdout) == []


def test_structured_soc_report(tmp_path):
    import json
    from pathlib import Path

    project_root = Path(__file__).resolve().parents[1]
    log_file = project_root / "data/samples/failed_logins.jsonl"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_assistant.main",
            str(log_file),
            "--report",
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0

    report = json.loads(result.stdout)

    assert report["application"] == "LogVigil"
    assert report["schema_version"] == "1.0"
    assert report["summary"]["events_analyzed"] == 5
    assert report["summary"]["findings_count"] == 1
    assert report["findings"][0]["rule_id"] == "DET-001"
    assert report["findings"][0]["status"] == "needs_review"
