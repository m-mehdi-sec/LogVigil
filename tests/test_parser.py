import pytest

from soc_assistant.parser import parse_jsonl


def test_invalid_json_reports_line_number(tmp_path):
    log_file = tmp_path / "invalid.jsonl"
    log_file.write_text(
        '{"event_id": 4625}\n'
        '{"event_id": \n',
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Invalid JSON on line 2"):
        parse_jsonl(log_file)


def test_json_array_is_rejected(tmp_path):
    log_file = tmp_path / "array.jsonl"
    log_file.write_text('[1, 2, 3]\n', encoding="utf-8")

    with pytest.raises(ValueError, match="Expected JSON object on line 1"):
        parse_jsonl(log_file)
