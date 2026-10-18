"""Interactive GUI for existing LogVigil CLI analysis."""

import json
import sys
from pathlib import Path

from PySide6.QtCore import QProcess, Signal
from PySide6.QtWidgets import (
    QFileDialog, QFrame, QHBoxLayout, QLabel,
    QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)


class LogImport(QWidget):
    file_selected = Signal(str)

    def __init__(self):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 30, 32, 30)
        layout.setSpacing(18)

        title = QLabel("Log Import")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        description = QLabel(
            "Select a local JSONL file for LogVigil analysis."
        )
        description.setObjectName("description")
        layout.addWidget(description)

        card = QFrame()
        card.setObjectName("chartCard")
        inner = QVBoxLayout(card)
        inner.setContentsMargins(24, 24, 24, 24)

        self.file_label = QLabel("No file selected")
        self.file_label.setWordWrap(True)
        inner.addWidget(self.file_label)

        self.details = QLabel("Select a file to continue.")
        self.details.setObjectName("description")
        inner.addWidget(self.details)

        browse = QPushButton("Browse JSONL File")
        browse.clicked.connect(self.browse)
        inner.addWidget(browse)

        layout.addWidget(card)
        layout.addStretch()

    def browse(self):
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select LogVigil JSONL File",
            str(Path.home()),
            "JSONL Files (*.jsonl)"
        )

        if not filename:
            return

        path = Path(filename)
        if not path.is_file() or path.is_symlink():
            self.details.setText("Invalid or unsupported file.")
            return

        self.file_label.setText(str(path))
        self.details.setText(
            f"File size: {path.stat().st_size:,} bytes"
        )
        self.file_selected.emit(str(path))


class RunAnalysis(QWidget):
    report_ready = Signal(dict, str)

    def __init__(self):
        super().__init__()
        self.selected_file = None
        self.process = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 30, 32, 30)
        layout.setSpacing(15)

        title = QLabel("Run Analysis")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        self.file_label = QLabel("No log file selected")
        self.file_label.setObjectName("description")
        self.file_label.setWordWrap(True)
        layout.addWidget(self.file_label)

        controls = QHBoxLayout()

        self.run_button = QPushButton("Run Detection Analysis")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self.run_analysis)
        controls.addWidget(self.run_button)

        self.status = QLabel("Ready")
        self.status.setObjectName("description")
        controls.addWidget(self.status)
        controls.addStretch()

        layout.addLayout(controls)

        results_title = QLabel("Analysis Results")
        results_title.setObjectName("sectionTitle")
        layout.addWidget(results_title)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setPlaceholderText(
            "Analysis results will appear here."
        )
        layout.addWidget(self.output, 1)

    def set_file(self, filename):
        self.selected_file = filename
        self.file_label.setText(filename)
        self.run_button.setEnabled(
            self.process is None or
            self.process.state() == QProcess.ProcessState.NotRunning
        )
        self.status.setText("Ready to analyze")

    def run_analysis(self):
        if self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning:
            return
        if not self.selected_file:
            return

        self.output.clear()
        self.status.setText("Analysis running...")
        self.run_button.setEnabled(False)

        self.process = QProcess(self)
        self.process.setProgram(sys.executable)
        self.process.setArguments([
            "-m", "soc_assistant.main",
            self.selected_file,
            "--report",
        ])

        self.process.finished.connect(self.finished)
        self.process.errorOccurred.connect(self.process_error)
        self.process.start()

    def process_error(self, error):
        if error != QProcess.ProcessError.FailedToStart:
            return

        self.status.setText("Process failed to start")
        self.output.setPlainText(self.process.errorString())
        self.run_button.setEnabled(True)

    def finished(self, exit_code, exit_status):
        if self.status.text() == "Process failed to start":
            return
        stdout = bytes(
            self.process.readAllStandardOutput()
        ).decode("utf-8", errors="replace")

        stderr = bytes(
            self.process.readAllStandardError()
        ).decode("utf-8", errors="replace")

        if exit_code != 0 or exit_status != QProcess.ExitStatus.NormalExit:
            self.status.setText("Analysis failed")
            self.output.setPlainText(stderr or stdout)
        else:
            try:
                report = json.loads(stdout)
                summary = report.get("summary", {})
                self.status.setText(
                    "Analysis completed · "
                    f"{summary.get('events_analyzed', 0)} events · "
                    f"{summary.get('findings_count', 0)} findings"
                )
                self.output.setPlainText(
                    json.dumps(report, indent=2, ensure_ascii=False)
                )
                self.report_ready.emit(
                    report, "Run Analysis"
                )
            except json.JSONDecodeError:
                self.status.setText("Invalid analysis output")
                self.output.setPlainText(stdout)

        self.run_button.setEnabled(
            self.process is None or
            self.process.state() == QProcess.ProcessState.NotRunning
        )
