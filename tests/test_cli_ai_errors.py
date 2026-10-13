"""Test user-friendly CLI error handling for AI failures."""

import sys

import pytest

from soc_assistant.main import main
from soc_assistant.ollama_client import OllamaClientError


@pytest.mark.parametrize(
    "error, expected_message",
    [
        (
            OllamaClientError("Unable to connect to local Ollama"),
            "AI analysis failed: Unable to connect to local Ollama",
        ),
        (
            ValueError("AI context exceeds maximum size"),
            "AI analysis failed: AI context exceeds maximum size",
        ),
    ],
)
def test_cli_ai_failure_has_clean_exit(
    monkeypatch, tmp_path, capsys, error, expected_message
):
    log_file = tmp_path / "empty.jsonl"
    log_file.write_text("", encoding="utf-8")

    monkeypatch.setattr(
        sys,
        "argv",
        ["logvigil", "--analyze-ai", str(log_file)],
    )

    def fake_analyze_soc_report(*args, **kwargs):
        raise error

    monkeypatch.setattr(
        "soc_assistant.main.analyze_soc_report",
        fake_analyze_soc_report,
    )

    with pytest.raises(SystemExit) as exit_info:
        main()

    captured = capsys.readouterr()

    assert exit_info.value.code == 1
    assert expected_message in captured.err
    assert "Traceback" not in captured.err
    assert captured.out == ""
