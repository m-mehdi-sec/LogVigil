"""Tests for explicit AI analysis through the CLI."""

import json
import sys
from unittest.mock import patch

import pytest

from soc_assistant import main as cli
from soc_assistant.ollama_client import OllamaClientError


@pytest.fixture
def log_file(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps({
            "event_id": 4625,
            "timestamp": "2026-10-13T10:00:00Z",
            "computer": "WIN11",
            "username": "alice",
            "source_ip": "10.0.0.5",
        }) + "\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def fake_analysis():
    return {
        "application": "LogVigil",
        "analysis_version": "1.0",
        "model": "qwen-test",
        "context_summary": {
            "investigations_sent": 0,
            "findings_sent": 0,
        },
        "ai_analysis": {
            "risk_level": "low",
            "observations": [],
            "hypotheses": [],
            "recommended_actions": [],
        },
    }


def invoke(monkeypatch, *args):
    monkeypatch.setattr(
        sys, "argv", ["logvigil", *map(str, args)]
    )
    cli.main()


def test_ai_mode_returns_json(
    monkeypatch, capsys, log_file, fake_analysis
):
    with patch.object(
        cli, "analyze_soc_report", return_value=fake_analysis
    ):
        invoke(monkeypatch, log_file, "--analyze-ai")

    result = json.loads(capsys.readouterr().out)
    assert result == fake_analysis


def test_normal_mode_never_calls_ai(
    monkeypatch, capsys, log_file
):
    with patch.object(cli, "analyze_soc_report") as mocked:
        invoke(monkeypatch, log_file)

    mocked.assert_not_called()
    assert isinstance(json.loads(capsys.readouterr().out), list)


def test_ai_model_and_timeout_forwarded(
    monkeypatch, log_file, fake_analysis, capsys
):
    with patch.object(
        cli, "analyze_soc_report", return_value=fake_analysis
    ) as mocked:
        invoke(
            monkeypatch, log_file, "--analyze-ai",
            "--model", "qwen-test",
            "--ai-timeout", "15",
        )

    assert mocked.call_args.kwargs["model"] == "qwen-test"
    assert mocked.call_args.kwargs["timeout"] == 15


def test_ai_context_limits_forwarded(
    monkeypatch, log_file, fake_analysis, capsys
):
    with patch.object(
        cli, "analyze_soc_report", return_value=fake_analysis
    ) as mocked:
        invoke(
            monkeypatch, log_file, "--analyze-ai",
            "--max-groups", "2",
            "--max-findings", "3",
        )

    assert mocked.call_args.kwargs["max_groups"] == 2
    assert mocked.call_args.kwargs["max_findings"] == 3


def test_ai_output_saved(
    monkeypatch, log_file, fake_analysis, tmp_path
):
    output = tmp_path / "analysis.json"

    with patch.object(
        cli, "analyze_soc_report", return_value=fake_analysis
    ):
        invoke(
            monkeypatch, log_file,
            "--analyze-ai", "--output", output,
        )

    assert json.loads(output.read_text()) == fake_analysis


def test_ai_output_does_not_overwrite(
    monkeypatch, log_file, fake_analysis, tmp_path
):
    output = tmp_path / "analysis.json"
    output.write_text("ORIGINAL", encoding="utf-8")

    with patch.object(
        cli, "analyze_soc_report", return_value=fake_analysis
    ):
        with pytest.raises(SystemExit) as error:
            invoke(
                monkeypatch, log_file,
                "--analyze-ai", "--output", output,
            )

    assert error.value.code == 1
    assert output.read_text() == "ORIGINAL"


def test_ai_connection_error_handled(monkeypatch, log_file, capsys):
    with patch.object(
        cli,
        "analyze_soc_report",
        side_effect=OllamaClientError("Connection refused"),
    ):
        with pytest.raises(SystemExit) as error:
            invoke(monkeypatch, log_file, "--analyze-ai")

    assert error.value.code == 1
    assert "AI analysis failed:" in capsys.readouterr().err


def test_ai_conflicting_modes_rejected(monkeypatch, log_file):
    with pytest.raises(SystemExit) as error:
        invoke(
            monkeypatch, log_file,
            "--analyze-ai", "--report",
        )

    assert error.value.code == 2


def test_invalid_model_rejected(monkeypatch, log_file):
    with pytest.raises(SystemExit) as error:
        invoke(
            monkeypatch, log_file,
            "--analyze-ai", "--model", "../ bad model",
        )

    assert error.value.code == 2


def test_invalid_timeout_rejected(monkeypatch, log_file):
    with pytest.raises(SystemExit) as error:
        invoke(
            monkeypatch, log_file,
            "--analyze-ai", "--ai-timeout", "0",
        )

    assert error.value.code == 2
