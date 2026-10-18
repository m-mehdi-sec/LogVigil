"""Read-only report and findings views for LogVigil."""

from datetime import datetime

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

from soc_assistant.logvigil_dashboard import REPORTS, load_reports


COLUMNS = (
    ("name", "Export"),
    ("events", "Events"),
    ("findings", "Findings"),
    ("warnings", "Warnings"),
    ("groups", "Investigations"),
    ("severity", "Severity"),
)


class ReportView(QWidget):
    def __init__(self, findings_only=False):
        super().__init__()
        self.findings_only = findings_only
        self.rows = []
        self.visible_rows = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 30, 32, 30)
        layout.setSpacing(14)

        heading = QLabel(
            "Findings" if findings_only else "Reports"
        )
        heading.setObjectName("pageTitle")
        layout.addWidget(heading)

        description = QLabel(
            "Stored analysis summaries containing security findings"
            if findings_only else
            "Local analysis history · Read-only report viewer"
        )
        description.setObjectName("description")
        layout.addWidget(description)

        controls = QHBoxLayout()

        self.search = QLineEdit()
        self.search.setPlaceholderText(
            "Search exports, severity or report values..."
        )
        self.search.textChanged.connect(self.apply_filter)
        controls.addWidget(self.search, 1)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self.refresh)
        controls.addWidget(self.refresh_button)

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
        self.table.itemSelectionChanged.connect(
            self.show_selected
        )
        layout.addWidget(self.table, 3)

        detail_heading = QLabel("Report Details")
        detail_heading.setObjectName("sectionTitle")
        layout.addWidget(detail_heading)

        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText(
            "Select a report to inspect its stored summary."
        )
        layout.addWidget(self.details, 2)

        self.updated = QLabel()
        self.updated.setObjectName("description")
        layout.addWidget(self.updated)

        self.refresh()

    def refresh(self):
        self.rows = load_reports(REPORTS)

        if self.findings_only:
            self.rows = [
                row for row in self.rows
                if row["findings"] > 0
            ]

        self.updated.setText(
            "Last refreshed: "
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        self.apply_filter()

    def apply_filter(self, *_):
        query = self.search.text().strip().casefold()

        self.visible_rows = [
            row for row in self.rows
            if not query or any(
                query in str(row[key]).casefold()
                for key, _ in COLUMNS
            )
        ]

        self.table.setRowCount(len(self.visible_rows))

        for index, row in enumerate(self.visible_rows):
            for column, (key, _) in enumerate(COLUMNS):
                item = QTableWidgetItem(str(row[key]))
                item.setData(Qt.ItemDataRole.UserRole, row["name"])
                self.table.setItem(index, column, item)

        self.table.resizeColumnsToContents()

        count = len(self.visible_rows)
        events = sum(row["events"] for row in self.visible_rows)
        findings = sum(
            row["findings"] for row in self.visible_rows
        )

        self.summary.setText(
            f"{count} reports · {events:,} events · "
            f"{findings:,} findings"
        )

        self.details.clear()

        if count == 0:
            self.details.setPlainText(
                "No matching stored summaries found."
            )

    def show_selected(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return

        index = selected[0].row()

        if index >= len(self.visible_rows):
            return

        row = self.visible_rows[index]

        lines = [
            f"Export: {row['name']}",
            "",
            f"Events analyzed: {row['events']}",
            f"Findings: {row['findings']}",
            f"Data quality warnings: {row['warnings']}",
            f"Investigation groups: {row['groups']}",
            f"Highest severity: {row['severity']}",
            "",
            "Source: Local LogVigil summary",
            "Scope: Stored analysis summary only",
            "Detailed evidence is not included in this summary.",
        ]

        self.details.setPlainText("\n".join(lines))
