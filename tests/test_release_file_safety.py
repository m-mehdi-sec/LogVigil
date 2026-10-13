
"""Release checks for LogVigil CLI file handling."""

import json
import subprocess
import sys
from pathlib import Path


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "soc_assistant.main", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_missing_input_file(tmp_path):
    missing = tmp_path / "missing.jsonl"

    result = run_cli(missing, "--report")

    assert result.returncode != 0
    assert "Traceback" not in result.stderr


def test_existing_output_is_preserved(tmp_path):
    source = tmp_path / "events.jsonl"
    output = tmp_path / "report.json"

    source.write_text("", encoding="utf-8")
    output.write_text("DO NOT OVERWRITE", encoding="utf-8")

    result = run_cli(source, "--report", "--output", output)

    assert result.returncode != 0
    assert output.read_text(encoding="utf-8") == "DO NOT OVERWRITE"


def test_new_output_contains_valid_json(tmp_path):
    source = tmp_path / "events.jsonl"
    output = tmp_path / "report.json"

    source.write_text("", encoding="utf-8")

    result = run_cli(source, "--report", "--output", output)

    assert result.returncode == 0
    assert output.exists()

    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["application"] == "LogVigil"
    assert report["summary"]["events_analyzed"] == 0


def test_invalid_input_does_not_create_output(tmp_path):
    source = tmp_path / "invalid.jsonl"
    output = tmp_path / "report.json"

    source.write_text("{invalid json\n", encoding="utf-8")

    result = run_cli(source, "--report", "--output", output)

    assert result.returncode != 0
    assert not output.exists()
