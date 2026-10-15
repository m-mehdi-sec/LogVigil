"""Parse bounded local JSONL security telemetry."""

import json
from pathlib import Path

MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_EVENTS = 10_000


def parse_jsonl(file_path):
    """Read bounded JSONL events from a local regular file."""
    import os
    import stat

    events = []
    path = Path(file_path)

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)

    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Secure file opening is not supported")

    flags |= os.O_NOFOLLOW

    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == getattr(__import__("errno"), "ELOOP"):
            raise ValueError("Symbolic links are not allowed") from error
        raise

    with os.fdopen(descriptor, "rb") as file:
        metadata = os.fstat(file.fileno())

        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Log file must be a regular file")

        if metadata.st_size > MAX_FILE_BYTES:
            raise ValueError("Log file exceeds size limit")

        total_bytes = 0

        for line_number, raw in enumerate(
            iter(lambda: file.readline(MAX_LINE_BYTES + 1), b""),
            start=1,
        ):
            total_bytes += len(raw)

            if total_bytes > MAX_FILE_BYTES:
                raise ValueError("Log file exceeds size limit")

            if len(raw) > MAX_LINE_BYTES:
                raise ValueError(
                    f"Log line {line_number} exceeds size limit"
                )

            if not raw.strip():
                continue

            if len(events) >= MAX_EVENTS:
                raise ValueError("Log file exceeds event limit")

            try:
                event = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError(
                    f"Invalid JSON on line {line_number}"
                ) from error

            if not isinstance(event, dict):
                raise ValueError(
                    f"Expected JSON object on line {line_number}"
                )

            events.append(event)

    return events
