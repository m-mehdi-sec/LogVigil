def build_analysis_report(events, findings):
    """Build a structured SOC analysis report."""
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "informational": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "informational")
        if severity in severity_counts:
            severity_counts[severity] += 1

    numbered_findings = []

    for index, finding in enumerate(findings, start=1):
        numbered_findings.append({
            **finding,
            "finding_id": f"LV-{index:04d}",
        })

    for finding in numbered_findings:
        related_ids = []

        if finding.get("rule_id") in {"DET-001", "DET-002", "DET-003"}:
            for other in numbered_findings:
                if other["finding_id"] == finding["finding_id"]:
                    continue

                rule_pair = {
                    finding.get("rule_id"),
                    other.get("rule_id"),
                }

                if rule_pair == {"DET-001", "DET-002"}:
                    match_fields = ("computer", "username", "source_ip")
                elif rule_pair in (
                    {"DET-001", "DET-003"},
                    {"DET-002", "DET-003"},
                ):
                    match_fields = ("computer", "source_ip")
                else:
                    continue

                same_source = all(
                    finding.get(field) is not None
                    and finding.get(field) == other.get(field)
                    for field in match_fields
                )

                evidence_overlap = bool(
                    set(finding.get("evidence_record_ids", []))
                    & set(other.get("evidence_record_ids", []))
                )

                if same_source and evidence_overlap:
                    related_ids.append(other["finding_id"])

        finding["related_finding_ids"] = related_ids

    findings_by_id = {
        finding["finding_id"]: finding
        for finding in numbered_findings
    }

    remaining_ids = set(findings_by_id)
    investigation_groups = []

    severity_order = (
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    )

    # Build connected investigation groups.
    while remaining_ids:
        start_id = min(remaining_ids)
        remaining_ids.remove(start_id)
        pending = [start_id]
        group_ids = set()

        while pending:
            finding_id = pending.pop()
            group_ids.add(finding_id)

            for related_id in findings_by_id[finding_id]["related_finding_ids"]:
                if related_id in remaining_ids:
                    remaining_ids.remove(related_id)
                    pending.append(related_id)

        ordered_ids = sorted(group_ids)

        group_severities = {
            findings_by_id[finding_id].get(
                "severity", "informational"
            )
            for finding_id in ordered_ids
        }

        highest_group_severity = next(
            (
                severity
                for severity in severity_order
                if severity in group_severities
            ),
            None,
        )

        investigation_id = (
            f"INV-{len(investigation_groups) + 1:04d}"
        )

        for finding_id in ordered_ids:
            findings_by_id[finding_id]["investigation_id"] = (
                investigation_id
            )

        investigation_groups.append({
            "investigation_id": investigation_id,
            "finding_ids": ordered_ids,
            "findings_count": len(ordered_ids),
            "highest_severity": highest_group_severity,
        })

    investigation_groups_count = len(investigation_groups)


    highest_severity = next(
        (
            severity
            for severity in severity_order
            if severity_counts[severity] > 0
        ),
        None,
    )

    return {
        "application": "LogVigil",
        "schema_version": "1.0",
        "summary": {
            "events_analyzed": len(events),
            "findings_count": len(findings),
            "investigation_groups_count": investigation_groups_count,
            "severity_counts": severity_counts,
            "highest_severity": highest_severity,
        },
        "findings": numbered_findings,
        "investigation_groups": investigation_groups,
    }
