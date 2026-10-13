"""Normalize supported log events into the LogVigil schema."""

from ipaddress import ip_address


def normalize_event(event):
    """Convert a Wazuh Windows event into a LogVigil event."""
    data = event.get("data", {})
    if not isinstance(data, dict):
        return event

    win = data.get("win", {})
    if not isinstance(win, dict):
        return event

    system = win.get("system", {})
    eventdata = win.get("eventdata", {})

    if not isinstance(system, dict) or not isinstance(eventdata, dict):
        return event

    event_id = system.get("eventID")

    if event_id is None:
        return event

    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        return event

    record_id = system.get("eventRecordID")

    if record_id is not None:
        try:
            record_id = int(record_id)
        except (TypeError, ValueError):
            record_id = None

    source_ip = eventdata.get("ipAddress")

    if isinstance(source_ip, str):
        source_ip = source_ip.strip()

        try:
            parsed_ip = ip_address(source_ip)
            source_ip = str(
                parsed_ip.ipv4_mapped
                if getattr(parsed_ip, "ipv4_mapped", None)
                else parsed_ip
            )
        except ValueError:
            source_ip = None
    else:
        source_ip = None

    username = eventdata.get("targetUserName")

    if isinstance(username, str):
        username = username.strip()
        if username in {"", "-"}:
            username = None

    return {
        "event_id": event_id,
        "timestamp": system.get("systemTime") or event.get("timestamp"),
        "computer": system.get("computer"),
        "username": username,
        "source_ip": source_ip,
        "record_id": record_id,
        "group_name": eventdata.get("targetUserName"),
        "group_sid": eventdata.get("targetSid"),
        "member_sid": eventdata.get("memberSid"),
        "member_name": eventdata.get("memberName"),
        "actor": eventdata.get("subjectUserName"),
    }


def normalize_events(events):
    """Normalize a collection of events."""
    return [normalize_event(event) for event in events]
