"""Validate normalized security events without modifying them."""


def validate_events(events):
    """Return data-quality warnings for supported login events."""
    warnings = []

    for index, event in enumerate(events, start=1):
        if event.get("event_id") not in (4624, 4625):
            continue

        missing_fields = [
            field
            for field in ("timestamp", "computer", "username", "source_ip")
            if not event.get(field)
        ]

        if missing_fields:
            warnings.append({
                "event_index": index,
                "event_id": event["event_id"],
                "missing_fields": missing_fields,
                "message": "Login event contains missing required fields.",
            })

    return warnings
