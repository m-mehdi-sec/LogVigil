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


def test_parser_rejects_oversized_line(tmp_path):
    from soc_assistant.parser import MAX_LINE_BYTES

    log_file = tmp_path / "oversized.jsonl"
    log_file.write_bytes(b"x" * (MAX_LINE_BYTES + 1))

    with pytest.raises(ValueError, match="line 1 exceeds size limit"):
        parse_jsonl(log_file)


def test_parser_rejects_oversized_file(tmp_path):
    from soc_assistant.parser import MAX_FILE_BYTES

    log_file = tmp_path / "large.jsonl"

    with log_file.open("wb") as file:
        file.truncate(MAX_FILE_BYTES + 1)

    with pytest.raises(ValueError, match="file exceeds size limit"):
        parse_jsonl(log_file)


def test_parser_rejects_too_many_events(tmp_path):
    from soc_assistant.parser import MAX_EVENTS

    log_file = tmp_path / "events.jsonl"
    log_file.write_text(
        '{"event_id":4625}\n' * (MAX_EVENTS + 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="event limit"):
        parse_jsonl(log_file)


def test_parser_accepts_valid_wazuh_event(tmp_path):
    log_file = tmp_path / "wazuh.jsonl"
    log_file.write_text(
        '{"data":{"win":{"system":{"eventID":"4625"},'
        '"eventdata":{"targetUserName":"test-user"}}}}\n',
        encoding="utf-8",
    )

    events = parse_jsonl(log_file)

    assert len(events) == 1
    assert events[0]["data"]["win"]["system"]["eventID"] == "4625"


def test_parser_rejects_symlink(tmp_path):
    target = tmp_path / "target.jsonl"
    target.write_text('{"event_id":4625}\\n', encoding="utf-8")

    link = tmp_path / "link.jsonl"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="Symbolic links"):
        parse_jsonl(link)


def test_parser_accepts_exact_line_limit(tmp_path):
    from soc_assistant.parser import MAX_LINE_BYTES

    log_file = tmp_path / "boundary.jsonl"
    prefix = b'{"value":"'
    suffix = b'"}\n'
    payload = prefix + b"a" * (
        MAX_LINE_BYTES - len(prefix) - len(suffix)
    ) + suffix

    assert len(payload) == MAX_LINE_BYTES
    log_file.write_bytes(payload)

    assert len(parse_jsonl(log_file)) == 1


def test_parser_rejects_invalid_utf8(tmp_path):
    log_file = tmp_path / "invalid_utf8.jsonl"
    log_file.write_bytes(b'{"value":"\\xff"}\\n')

    with pytest.raises(ValueError, match="Invalid JSON on line 1"):
        parse_jsonl(log_file)
