"""Read-only detailed findings from the current GUI session."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


COLUMNS = (
    ("finding_id", "Finding ID"),
    ("rule_id", "Detection"),
    ("severity", "Severity"),
    ("title", "Title"),
    ("computer", "Host"),
    ("username", "User"),
    ("source_ip", "Source IP"),
    ("status", "Status"),
)


class Findings(QWidget):
    def __init__(self):
        super().__init__()
        self.findings = []
        self.visible_findings = []
        self.source = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 30, 32, 30)
        layout.setSpacing(14)

        heading = QLabel("Findings")
        heading.setObjectName("pageTitle")
        layout.addWidget(heading)

        self.description = QLabel(
            "Detailed security findings · Current GUI session"
        )
        self.description.setObjectName("description")
        layout.addWidget(self.description)

        controls = QHBoxLayout()

        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search detection, severity, host, user or IP..."
        )
        self.search.textChanged.connect(self.apply_filter)
        controls.addWidget(self.search, 1)

        self.clear_button = QPushButton("Clear Session Findings")
        self.clear_button.clicked.connect(self.clear_findings)
        controls.addWidget(self.clear_button)

        layout.addLayout(controls)

        self.summary = QLabel()
        self.summary.setObjectName("description")
        layout.addWidget(self.summary)

        self.table = QTableWidget()
        self.table.setColumnCount(len(COLUMNS))
        self.table.setHorizontalHeaderLabels(
            [label for _, label in COLUMNS]
        )
        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.table.setAlternatingRowColors(True)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self.show_selected)
        layout.addWidget(self.table, 3)

        detail_heading = QLabel("Finding Details & Evidence")
        detail_heading.setObjectName("sectionTitle")
        layout.addWidget(detail_heading)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        layout.addWidget(self.details, 2)

        self.apply_filter()

    def load_report(self, report, source):
        if not isinstance(report, dict):
            return

        findings = report.get("findings", [])
        if not isinstance(findings, list):
            return

        self.findings = [
            finding for finding in findings
            if isinstance(finding, dict)
        ]
        self.source = source
        self.apply_filter()

    def clear_findings(self):
        self.findings = []
        self.source = None
        self.apply_filter()

    def apply_filter(self, *_):
        query = self.search.text().strip().casefold()

        self.visible_findings = [
            finding for finding in self.findings
            if not query or any(
                query in str(finding.get(key, "")).casefold()
                for key, _ in COLUMNS
            )
        ]

        self.table.blockSignals(True)
        self.table.setRowCount(len(self.visible_findings))

        for row_index, finding in enumerate(self.visible_findings):
            for column_index, (key, _) in enumerate(COLUMNS):
                value = finding.get(key, "")
                item = QTableWidgetItem(str(value))
                self.table.setItem(row_index, column_index, item)

        self.table.blockSignals(False)
        self.table.resizeColumnsToContents()

        self.summary.setText(
            f"{len(self.visible_findings)} findings displayed · "
            f"{len(self.findings)} total · "
            f"Source: {self.source or 'No analysis loaded'}"
        )

        self.details.clear()
        if not self.visible_findings:
            self.details.setPlainText(
                "No findings loaded for the current GUI session."
            )

    def show_selected(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return

        index = selected[0].row()
        if index >= len(self.visible_findings):
            return

        finding = self.visible_findings[index]

        evidence = finding.get("evidence_record_ids", [])
        if not isinstance(evidence, list):
            evidence = []

        lines = [
            f"Finding: {finding.get('finding_id', 'N/A')}",
            f"Detection: {finding.get('rule_id', 'N/A')}",
            f"Title: {finding.get('title', 'N/A')}",
            f"Severity: {finding.get('severity', 'N/A')}",
            f"Status: {finding.get('status', 'N/A')}",
            "",
            "DESCRIPTION",
            str(finding.get("description", "Not available")),
            "",
            "AFFECTED SYSTEM",
            f"Host: {finding.get('computer', 'N/A')}",
            f"User: {finding.get('username', 'N/A')}",
            f"Source IP: {finding.get('source_ip', 'N/A')}",
            "",
            "TIMELINE",
            f"First seen: {finding.get('first_seen', 'N/A')}",
            f"Last seen: {finding.get('last_seen', 'N/A')}",
            f"Event count: {finding.get('event_count', 'N/A')}",
            "",
            "EVIDENCE RECORD IDS",
            ", ".join(map(str, evidence)) or "Not available",
            "",
            "INVESTIGATION",
            str(finding.get("investigation_id", "N/A")),
            "",
            "RECOMMENDED ACTION",
            str(finding.get("recommended_action", "Not available")),
            "",
            "Human review required. No automatic remediation.",
        ]

        self.details.setPlainText("\n".join(lines))
