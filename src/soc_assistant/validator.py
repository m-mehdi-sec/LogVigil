"""Validate normalized security events without modifying them."""


def validate_events(events):
    """Return data-quality warnings for supported login events."""
    warnings = []

    for index, event in enumerate(events, start=1):
        if event.get("event_id") not in (4624, 4625):
            continue

        missing_fields = [
            field
            for field in ("timestamp", "computer", "username")
            if not event.get(field)
        ]

        logon_type = event.get("logon_type")

        if logon_type is not None:
            logon_type = str(logon_type).strip()

        # Local, service, unlock, and cached logons may lack a source IP.
        local_logon_types = {"2", "5", "7", "11"}

        if (
            not event.get("source_ip")
            and logon_type not in local_logon_types
        ):
            missing_fields.append("source_ip")

        if missing_fields:
            warnings.append({
                "event_index": index,
                "event_id": event["event_id"],
                "missing_fields": missing_fields,
                "message": "Login event contains missing required fields.",
            })

    return warnings
