"""LogVigil desktop application."""

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel,
    QListWidget, QMainWindow, QStackedWidget,
    QVBoxLayout, QWidget,
)

from soc_assistant.gui.dashboard import Dashboard
from soc_assistant.gui.analysis import LogImport, RunAnalysis
from soc_assistant.gui.ai_investigation import AIInvestigation
from soc_assistant.gui.report_views import ReportView
from soc_assistant.gui.findings import Findings
from soc_assistant.gui.settings import Settings
from soc_assistant.gui.process_utils import stop_process


PAGES = [
    ("Dashboard", "▦"),
    ("Log Import", "⇩"),
    ("Run Analysis", "▶"),
    ("AI Investigation", "✧"),
    ("Findings", "⚑"),
    ("Reports", "▤"),
    ("Settings", "⚙"),
]


STYLE = """
QMainWindow, QWidget {
    background: #080f17;
    color: #e8f2f5;
    font-family: Arial;
    font-size: 13px;
}
#sidebar {
    background: #060c12;
    border-right: 1px solid #20343c;
}
#brand {
    color: #39d8d0;
    font-size: 20px;
    font-weight: bold;
    padding: 12px 4px;
}
#topbar {
    background: #0b151d;
    border-bottom: 1px solid #20343c;
}
#topTitle {
    font-size: 17px;
    font-weight: bold;
}
#version, #description {
    color: #8ca5ae;
}
#pageTitle {
    font-size: 27px;
    font-weight: bold;
}
#sectionTitle {
    font-size: 17px;
    font-weight: bold;
}
#metricCard, #chartCard {
    background: #101d25;
    border: 1px solid #203943;
    border-radius: 12px;
}
#metricCard QLabel, #chartCard QLabel {
    background: transparent;
    border: none;
}
#metricValue {
    font-size: 27px;
    font-weight: bold;
    color: #f2fcff;
}
#metricLabel {
    color: #92adb5;
}
QListWidget {
    background: transparent;
    border: none;
    outline: none;
}
QListWidget::item {
    padding: 13px 5px;
    margin: 3px 0;
    border-radius: 8px;
    color: #a8c0c8;
}
QListWidget::item:selected {
    background: #14343b;
    color: #4be2d8;
}
QPushButton {
    background: #14343b;
    border: 1px solid #28616a;
    border-radius: 7px;
    padding: 9px 14px;
    color: #dffaf8;
}
QPushButton:hover {
    background: #20505a;
}
QLineEdit {
    background: #101e27;
    border: 1px solid #29414b;
    border-radius: 7px;
    padding: 9px;
}
QTableWidget {
    background: #0d1922;
    alternate-background-color: #14242e;
    selection-background-color: #20515b;
    gridline-color: #203943;
    border: 1px solid #29414b;
    border-radius: 8px;
}
QHeaderView::section {
    background: #14262f;
    color: #b9d3d9;
    padding: 9px;
    border: none;
}
"""


class LogVigilWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("LogVigil | SOC Analysis")
        self.resize(1400, 850)
        self.setMinimumSize(1050, 680)

        root = QWidget()
        root_layout = QHBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(210)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(10, 20, 10, 15)

        brand = QLabel("LogVigil")
        brand.setObjectName("brand")
        brand.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(brand)

        self.navigation = QListWidget()
        self.navigation.setSpacing(5)
        self.navigation.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.navigation.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.navigation.setTextElideMode(
            Qt.TextElideMode.ElideNone
        )

        for name, icon in PAGES:
            self.navigation.addItem(f"{icon}  {name}")

        side_layout.addWidget(self.navigation)
        side_layout.addStretch()

        version = QLabel("v1.1.0")
        version.setObjectName("version")
        version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        side_layout.addWidget(version)

        content = QWidget()
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        topbar = QFrame()
        topbar.setObjectName("topbar")
        top_layout = QHBoxLayout(topbar)
        top_layout.setContentsMargins(28, 12, 28, 12)

        top_title = QLabel("Security Operations")
        top_title.setObjectName("topTitle")
        top_layout.addWidget(top_title)
        top_layout.addStretch()
        top_layout.addWidget(QLabel("LOCAL SOC  •  OFFLINE FIRST"))

        content_layout.addWidget(topbar)

        self.pages = QStackedWidget()
        self.log_import = LogImport()
        self.run_analysis = RunAnalysis()
        self.ai_investigation = AIInvestigation()
        self.findings = Findings()
        self.run_analysis.report_ready.connect(
            self.findings.load_report
        )
        self.ai_investigation.report_ready.connect(
            self.findings.load_report
        )
        self.log_import.file_selected.connect(
            self.run_analysis.set_file
        )
        self.log_import.file_selected.connect(
            self.ai_investigation.set_file
        )

        for name, _ in PAGES:
            if name == "Dashboard":
                self.pages.addWidget(Dashboard())
                continue
            if name == "Log Import":
                self.pages.addWidget(self.log_import)
                continue
            if name == "Run Analysis":
                self.pages.addWidget(self.run_analysis)
                continue
            if name == "AI Investigation":
                self.pages.addWidget(self.ai_investigation)
                continue
            if name == "Findings":
                self.pages.addWidget(self.findings)
                continue
            if name == "Reports":
                self.pages.addWidget(ReportView())
                continue
            if name == "Settings":
                self.pages.addWidget(Settings())
                continue

            page = QWidget()
            layout = QVBoxLayout(page)
            layout.setContentsMargins(32, 30, 32, 30)

            title = QLabel(name)
            title.setObjectName("pageTitle")
            layout.addWidget(title)

            description = QLabel("GUI module under development.")
            description.setObjectName("description")
            layout.addWidget(description)
            layout.addStretch()

            self.pages.addWidget(page)

        content_layout.addWidget(self.pages, 1)
        root_layout.addWidget(sidebar)
        root_layout.addWidget(content, 1)

        self.setCentralWidget(root)
        self.navigation.currentRowChanged.connect(
            self.pages.setCurrentIndex
        )
        self.navigation.setCurrentRow(0)



    def closeEvent(self, event):
        """Stop child processes before closing the GUI."""
        stop_process(self.run_analysis.process)
        stop_process(self.ai_investigation.process)
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    app.setStyleSheet(STYLE)
    window = LogVigilWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
