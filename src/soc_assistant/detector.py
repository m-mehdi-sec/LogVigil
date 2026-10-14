from datetime import datetime, timedelta

from soc_assistant.ip_utils import is_usable_source_ip


def detect_brute_force(events):
    """Detect five failed logins within five minutes."""
    groups = {}
    seen_records = set()

    for event in events:
        if event.get("event_id") != 4625:
            continue

        username = event.get("username")
        source_ip = event.get("source_ip")
        computer = event.get("computer")

        if not username or not is_usable_source_ip(source_ip) or not computer:
            continue

        record_id = event.get("record_id")
        if record_id is not None:
            record_key = (computer, record_id)
            if record_key in seen_records:
                continue
            seen_records.add(record_key)

        timestamp_value = event.get("timestamp")
        if not isinstance(timestamp_value, str) or not timestamp_value.strip():
            raise ValueError("Missing or invalid timestamp in login event")

        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError as error:
            raise ValueError(
                f"Invalid timestamp in login event: {timestamp_value}"
            ) from error

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError(
                "Timestamp must include a timezone offset"
            )

        key = (computer, username, source_ip)
        groups.setdefault(key, []).append((timestamp, record_id))

    findings = []

    for (computer, username, source_ip), timestamps in groups.items():
        timestamps.sort(key=lambda item: item[0])

        for i in range(len(timestamps) - 4):
            if timestamps[i + 4][0] - timestamps[i][0] <= timedelta(minutes=5):
                findings.append({
                    "rule_id": "DET-001",
                    "severity": "medium",
                    "title": "Multiple Failed Login Attempts",
                    "description": (
                        "Five failed login attempts were detected "
                        "within five minutes for the same user, "
                        "source IP, and computer."
                    ),
                    "computer": computer,
                    "username": username,
                    "source_ip": source_ip,
                    "event_count": 5,
                    "first_seen": timestamps[i][0].isoformat(),
                    "last_seen": timestamps[i + 4][0].isoformat(),
                    "evidence_record_ids": [
                        item[1]
                        for item in timestamps[i:i + 5]
                        if item[1] is not None
                    ],
                    "status": "needs_review",
                    "recommended_action": (
                        "Review authentication logs, verify the source IP, "
                        "and check for successful logins after the failures."
                    ),
                })
                break

    return findings


def detect_success_after_failures(events):
    """Detect a successful login after repeated failed attempts."""
    brute_force_findings = detect_brute_force(events)
    findings = []

    for finding in brute_force_findings:
        last_failed = datetime.fromisoformat(finding["last_seen"])

        for event in events:
            if event.get("event_id") != 4624:
                continue

            if (
                event.get("computer") != finding["computer"]
                or event.get("username") != finding["username"]
                or event.get("source_ip") != finding["source_ip"]
            ):
                continue

            timestamp_value = event.get("timestamp")
            if not isinstance(timestamp_value, str):
                raise ValueError("Missing timestamp in successful login")

            try:
                success_time = datetime.fromisoformat(timestamp_value)
            except ValueError as error:
                raise ValueError(
                    "Invalid timestamp in successful login"
                ) from error

            if success_time.tzinfo is None or success_time.utcoffset() is None:
                raise ValueError(
                    "Successful login timestamp must include a timezone"
                )

            time_difference = success_time - last_failed

            if timedelta(0) <= time_difference <= timedelta(minutes=5):
                evidence_ids = list(finding["evidence_record_ids"])
                if event.get("record_id") is not None:
                    evidence_ids.append(event["record_id"])

                findings.append({
                    "rule_id": "DET-002",
                    "severity": "high",
                    "title": "Successful Login After Multiple Failures",
                    "description": (
                        "A successful login followed five failed attempts "
                        "for the same user, source IP, and computer."
                    ),
                    "computer": finding["computer"],
                    "username": finding["username"],
                    "source_ip": finding["source_ip"],
                    "first_seen": finding["first_seen"],
                    "last_seen": success_time.isoformat(),
                    "evidence_record_ids": evidence_ids,
                    "status": "needs_review",
                    "recommended_action": (
                        "Verify whether the successful login was authorized "
                        "and review related authentication activity."
                    ),
                })
                break

    return findings



def detect_account_enumeration(events):
    """Detect failed logins against five different usernames."""
    groups = {}
    seen_records = set()

    for event in events:
        if event.get("event_id") != 4625:
            continue

        computer = event.get("computer")
        username = event.get("username")
        source_ip = event.get("source_ip")
        timestamp_value = event.get("timestamp")

        if not computer or not username or not is_usable_source_ip(source_ip):
            continue

        if not isinstance(timestamp_value, str):
            raise ValueError("Missing timestamp in failed login")

        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError as error:
            raise ValueError("Invalid timestamp in failed login") from error

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("Failed login timestamp must include a timezone")

        record_id = event.get("record_id")

        if record_id is not None:
            record_key = (computer, record_id)
            if record_key in seen_records:
                continue
            seen_records.add(record_key)

        key = (computer, source_ip)
        groups.setdefault(key, []).append(
            (timestamp, username, event.get("record_id"))
        )

    findings = []

    for (computer, source_ip), attempts in groups.items():
        attempts.sort(key=lambda item: item[0])

        for start in range(len(attempts)):
            window = [
                attempt
                for attempt in attempts[start:]
                if attempt[0] - attempts[start][0] <= timedelta(minutes=5)
            ]

            usernames = {attempt[1] for attempt in window}

            if len(usernames) >= 5:
                findings.append({
                    "rule_id": "DET-003",
                    "severity": "medium",
                    "title": "Multiple Usernames Targeted",
                    "description": (
                        "Failed login attempts targeted at least five "
                        "different usernames from the same source IP."
                    ),
                    "computer": computer,
                    "source_ip": source_ip,
                    "usernames": sorted(usernames),
                    "event_count": len(window),
                    "first_seen": window[0][0].isoformat(),
                    "last_seen": window[-1][0].isoformat(),
                    "evidence_record_ids": [
                        item[2] for item in window if item[2] is not None
                    ],
                    "status": "needs_review",
                    "recommended_action": (
                        "Review targeted accounts, investigate the source IP, "
                        "and check for related successful logins."
                    ),
                })
                break

    return findings



def detect_account_lockout(events):
    """Detect Windows account lockout events (Event ID 4740)."""
    findings = []
    seen_records = set()

    for event in events:
        if event.get("event_id") != 4740:
            continue

        computer = event.get("computer")
        username = event.get("username")

        if not computer or not username:
            continue

        record_id = event.get("record_id")
        if record_id is not None:
            record_key = (computer, record_id)
            if record_key in seen_records:
                continue
            seen_records.add(record_key)

        timestamp_value = event.get("timestamp")

        if not isinstance(timestamp_value, str) or not timestamp_value.strip():
            raise ValueError("Missing timestamp in account lockout event")

        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError as error:
            raise ValueError(
                "Invalid timestamp in account lockout event"
            ) from error

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError(
                "Account lockout timestamp must include a timezone"
            )

        findings.append({
            "rule_id": "DET-004",
            "severity": "medium",
            "title": "User Account Locked Out",
            "description": (
                "Windows reported that a user account was locked out."
            ),
            "computer": computer,
            "username": username,
            "source_ip": event.get("source_ip"),
            "first_seen": timestamp.isoformat(),
            "last_seen": timestamp.isoformat(),
            "evidence_record_ids": (
                [record_id] if record_id is not None else []
            ),
            "status": "needs_review",
            "recommended_action": (
                "Investigate the lockout cause, review failed logins, "
                "and verify whether the activity was authorized."
            ),
        })

    return findings



def detect_privileged_group_change(events):
    """Detect members added to privileged Windows security groups."""
    findings = []
    seen_records = set()

    privileged_names = {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
    }

    for event in events:
        if event.get("event_id") not in {4728, 4732, 4756}:
            continue

        computer = event.get("computer")
        group_name = event.get("group_name")
        group_sid = event.get("group_sid")

        if not computer:
            continue

        if isinstance(group_sid, str) and group_sid.strip():
            sid = group_sid.strip().upper()
            privileged = (
                sid == "S-1-5-32-544"
                or (
                    sid.startswith("S-1-5-21-")
                    and sid.rsplit("-", 1)[-1] in {"512", "518", "519"}
                )
            )
        else:
            privileged = (
                isinstance(group_name, str)
                and group_name.strip().casefold() in privileged_names
            )

        if not privileged:
            continue

        timestamp_value = event.get("timestamp")

        if not isinstance(timestamp_value, str) or not timestamp_value.strip():
            raise ValueError("Missing timestamp in group membership event")

        try:
            timestamp = datetime.fromisoformat(timestamp_value)
        except ValueError as error:
            raise ValueError(
                "Invalid timestamp in group membership event"
            ) from error

        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError(
                "Group membership timestamp must include a timezone"
            )

        record_id = event.get("record_id")

        if record_id is not None:
            record_key = (computer, record_id)
            if record_key in seen_records:
                continue
            seen_records.add(record_key)

        findings.append({
            "rule_id": "DET-005",
            "severity": "high",
            "title": "Privileged Group Membership Changed",
            "description": (
                "A member was added to a privileged Windows security group."
            ),
            "computer": computer,
            "group_name": group_name,
            "group_sid": group_sid,
            "member_name": event.get("member_name"),
            "member_sid": event.get("member_sid"),
            "actor": event.get("actor"),
            "first_seen": timestamp.isoformat(),
            "last_seen": timestamp.isoformat(),
            "evidence_record_ids": (
                [record_id] if record_id is not None else []
            ),
            "status": "needs_review",
            "recommended_action": (
                "Verify that the membership change was authorized, "
                "identify the actor, and review related account activity."
            ),
        })

    return findings
