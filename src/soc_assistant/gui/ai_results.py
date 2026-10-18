"""Read-only presentation of local AI SOC investigation results."""

import json

from PySide6.QtWidgets import (
    QLabel, QPlainTextEdit, QTabWidget, QVBoxLayout, QWidget,
)


def format_value(value):
    if value is None:
        return "Not available"
    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, ensure_ascii=False)
    return str(value)


def format_items(items):
    if not isinstance(items, list) or not items:
        return "None reported"

    formatted = []

    for index, item in enumerate(items, 1):
        text = format_value(item)

        # Normalize literal escaped newlines in display text.
        text = text.replace(chr(92) + "n", chr(10))

        formatted.append(f"{index}. {text}")

    return chr(10).join(formatted)


class AIResultView(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)

        self.overview = self.make_tab("Overview")
        self.evidence = self.make_tab("Verified Evidence")
        self.assessment = self.make_tab("AI Assessment")
        self.raw = self.make_tab("Raw JSON")

        self.clear()

    def make_tab(self, title):
        editor = QPlainTextEdit()
        editor.setReadOnly(True)
        self.tabs.addTab(editor, title)
        return editor

    def clear(self):
        self.overview.setPlainText(
            "Run an AI investigation to view the summary."
        )
        self.evidence.clear()
        self.assessment.clear()
        self.raw.clear()
        self.tabs.setCurrentIndex(0)

    def show_error(self, message):
        self.overview.setPlainText(message)
        self.tabs.setCurrentIndex(0)

    def display_report(self, result):
        if not isinstance(result, dict):
            self.show_error("Invalid investigation result.")
            return

        verified = result.get("verified_evidence", {})
        if not isinstance(verified, dict):
            verified = {}

        summary = verified.get("summary", {})
        if not isinstance(summary, dict):
            summary = {}

        findings = verified.get("findings", [])
        if not isinstance(findings, list):
            findings = []

        ai = result.get("ai_analysis", {})
        if not isinstance(ai, dict):
            ai = {}

        self.overview.setPlainText("\n".join([
            "LOGVIGIL | AI INVESTIGATION",
            "",
            "LOCAL ANALYSIS",
            f"Model: {format_value(result.get('model'))}",
            f"Simulation: {format_value(result.get('simulation_status'))}",
            f"AI validation: {format_value(result.get('ai_validation_status'))}",
            f"AI attempts: {format_value(result.get('ai_attempts'))}",
            "",
            "VERIFIED EVIDENCE",
            f"Events: {format_value(summary.get('events_analyzed'))}",
            f"Findings: {format_value(summary.get('findings_count'))}",
            f"Highest severity: {format_value(summary.get('highest_severity'))}",
            "",
            "AI ASSESSMENT",
            f"AI risk level: {format_value(ai.get('risk_level'))}",
            "",
            "AI-generated statements are not independently "
            "fact-verified. Human review is required.",
        ]))

        evidence_lines = [
            "VERIFIED LOGVIGIL EVIDENCE",
            "",
            "Source: Deterministic detection engine",
            "",
            f"Events analyzed: {format_value(summary.get('events_analyzed'))}",
            f"Findings: {format_value(summary.get('findings_count'))}",
            "",
        ]

        if findings:
            for index, finding in enumerate(findings, 1):
                if not isinstance(finding, dict):
                    continue
                evidence_lines.extend([
                    f"FINDING {index}",
                    f"ID: {format_value(finding.get('finding_id'))}",
                    f"Rule: {format_value(finding.get('rule_id'))}",
                    f"Severity: {format_value(finding.get('severity'))}",
                    f"Title: {format_value(finding.get('title'))}",
                    f"Host: {format_value(finding.get('computer'))}",
                    f"User: {format_value(finding.get('username'))}",
                    f"Source IP: {format_value(finding.get('source_ip'))}",
                    "Evidence record IDs:",
                    format_value(finding.get('evidence_record_ids')),
                    "",
                ])
        else:
            evidence_lines.append(
                "No detailed findings included in the AI response."
            )

        self.evidence.setPlainText("\n".join(evidence_lines))

        self.assessment.setPlainText("\n".join([
            "QWEN | AI-GENERATED ASSESSMENT",
            "",
            f"Risk level: {format_value(ai.get('risk_level'))}",
            "",
            "OBSERVATIONS",
            format_items(ai.get("observations")),
            "",
            "HYPOTHESES",
            format_items(ai.get("hypotheses")),
            "",
            "RECOMMENDED ACTIONS",
            format_items(ai.get("recommended_actions")),
            "",
            "SAFETY NOTICE",
            format_value(result.get("ai_evidence_notice")),
            "",
            "Recommendations require human review.",
            "No automatic remediation is performed by this viewer.",
        ]))

        self.raw.setPlainText(
            json.dumps(result, indent=2, ensure_ascii=False)
        )
        self.tabs.setCurrentIndex(0)
