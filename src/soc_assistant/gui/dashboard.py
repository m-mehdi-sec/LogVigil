"""Read-only LogVigil SOC dashboard."""

from collections import Counter
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (
    QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from soc_assistant.logvigil_dashboard import REPORTS, load_reports


class ActivityChart(QWidget):
    """Draw event counts from stored reports."""

    def __init__(self):
        super().__init__()
        self.values = []
        self.setMinimumHeight(150)

    def set_values(self, values):
        self.values = values
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        width = self.width()
        height = self.height()

        painter.setPen(QPen(QColor("#28434a"), 1))
        for index in range(1, 5):
            y = int(height * index / 5)
            painter.drawLine(0, y, width, y)

        if not self.values:
            painter.setPen(QColor("#8ca5ae"))
            painter.drawText(
                self.rect(),
                Qt.AlignmentFlag.AlignCenter,
                "No report data available"
            )
            return

        maximum = max(max(self.values), 1)
        count = len(self.values)
        spacing = width / max(count, 1)
        bar_width = max(2, min(25, int(spacing * 0.65)))

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QColor("#39d8d0"))

        for index, value in enumerate(self.values):
            bar_height = int((value / maximum) * (height - 20))
            x = int(index * spacing + (spacing - bar_width) / 2)
            painter.drawRoundedRect(
                x, height - bar_height - 5,
                bar_width, bar_height, 3, 3
            )


class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.rows = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(15)

        header = QHBoxLayout()
        title = QLabel("SOC Dashboard")
        title.setObjectName("pageTitle")
        header.addWidget(title)
        header.addStretch()

        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        header.addWidget(refresh)
        layout.addLayout(header)

        self.status = QLabel("Loading reports...")
        self.status.setObjectName("description")
        layout.addWidget(self.status)

        cards = QGridLayout()
        cards.setSpacing(12)
        self.metrics = {}

        definitions = [
            ("files", "Files analyzed"),
            ("events", "Security events"),
            ("findings", "Findings"),
            ("warnings", "Data warnings"),
            ("groups", "Investigations"),
        ]

        for index, (key, caption) in enumerate(definitions):
            frame = QFrame()
            frame.setObjectName("metricCard")
            inner = QVBoxLayout(frame)
            inner.setContentsMargins(17, 15, 17, 15)

            value = QLabel("0")
            value.setObjectName("metricValue")
            label = QLabel(caption)
            label.setObjectName("metricLabel")

            inner.addWidget(value)
            inner.addWidget(label)
            self.metrics[key] = value
            cards.addWidget(frame, 0, index)

        layout.addLayout(cards)

        charts = QHBoxLayout()
        charts.setSpacing(12)

        activity_card = QFrame()
        activity_card.setObjectName("chartCard")
        activity_layout = QVBoxLayout(activity_card)

        activity_title = QLabel("Event Activity")
        activity_title.setObjectName("sectionTitle")
        activity_layout.addWidget(activity_title)

        self.chart = ActivityChart()
        activity_layout.addWidget(self.chart)

        charts.addWidget(activity_card, 2)

        severity_card = QFrame()
        severity_card.setObjectName("chartCard")
        severity_layout = QVBoxLayout(severity_card)

        severity_title = QLabel("Severity Distribution")
        severity_title.setObjectName("sectionTitle")
        severity_layout.addWidget(severity_title)

        self.severity = QLabel("No reports")
        self.severity.setWordWrap(True)
        severity_layout.addWidget(self.severity)
        severity_layout.addStretch()

        charts.addWidget(severity_card, 1)
        layout.addLayout(charts)

        section = QLabel("Recent Analyses")
        section.setObjectName("sectionTitle")
        layout.addWidget(section)

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search reports or severity...")
        self.search.textChanged.connect(self.filter_rows)
        layout.addWidget(self.search)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "Export", "Events", "Findings",
            "Warnings", "Groups", "Severity"
        ])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(
            QTableWidget.EditTrigger.NoEditTriggers
        )
        self.table.setSelectionBehavior(
            QTableWidget.SelectionBehavior.SelectRows
        )
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.Stretch
        )
        for column in range(1, 6):
            self.table.horizontalHeader().setSectionResizeMode(
                column, QHeaderView.ResizeMode.ResizeToContents
            )

        layout.addWidget(self.table, 1)

        footer = QLabel(
            "Local reports only · No live telemetry · "
            "Counts are not deduplicated incidents"
        )
        footer.setObjectName("description")
        layout.addWidget(footer)

        self.refresh()

    def refresh(self):
        self.rows = load_reports(REPORTS)

        self.status.setText(
            f"Last refreshed: {datetime.now().strftime('%H:%M:%S')} "
            f"· {len(self.rows)} reports loaded"
        )

        self.metrics["files"].setText(str(len(self.rows)))
        for key in ("events", "findings", "warnings", "groups"):
            self.metrics[key].setText(
                f"{sum(row[key] for row in self.rows):,}"
            )

        self.chart.set_values([
            row["events"] for row in reversed(self.rows)
        ])

        counts = Counter(row["severity"] for row in self.rows)
        severity_lines = [
            f"{key}: {counts[key]}"
            for key in (
                "CRITICAL", "HIGH", "MEDIUM",
                "LOW", "INFORMATIONAL", "NONE"
            )
            if counts[key]
        ]

        self.severity.setText(
            "\n".join(severity_lines) if severity_lines
            else "No reports available"
        )

        self.filter_rows(self.search.text())

    def filter_rows(self, query):
        query = query.casefold()
        filtered = [
            row for row in self.rows
            if query in row["name"].casefold()
            or query in row["severity"].casefold()
        ]

        self.table.setRowCount(len(filtered))

        for index, row in enumerate(filtered):
            values = [
                row["name"], row["events"], row["findings"],
                row["warnings"], row["groups"], row["severity"]
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if isinstance(value, int):
                    item.setTextAlignment(
                        Qt.AlignmentFlag.AlignCenter
                    )
                self.table.setItem(index, column, item)
