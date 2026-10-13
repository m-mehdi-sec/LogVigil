import json
from pathlib import Path


def parse_jsonl(file_path):
    """Read JSONL log events from a local file."""
    events = []

    with Path(file_path).open("r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}"
                ) from error

            if not isinstance(event, dict):
                raise ValueError(
                    f"Expected JSON object on line {line_number}"
                )

            events.append(event)

    return events
