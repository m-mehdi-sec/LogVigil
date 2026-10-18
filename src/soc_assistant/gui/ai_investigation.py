"""Local Ollama and Qwen investigation interface."""

import json
import sys
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from PySide6.QtCore import QProcess, Qt, Signal
from PySide6.QtSvgWidgets import QSvgWidget
from soc_assistant.gui.ai_results import AIResultView
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtGui import QPainter, QPixmap, QColor
from PySide6.QtWidgets import (
    QCheckBox, QFrame, QHBoxLayout, QLabel,
    QPlainTextEdit, QPushButton, QVBoxLayout, QWidget,
)


class AIInvestigation(QWidget):
    report_ready = Signal(dict, str)

    def __init__(self):
        super().__init__()
        self.selected_file = None
        self.process = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 30, 32, 30)
        layout.setSpacing(16)

        title = QLabel("AI Investigation")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        subtitle = QLabel(
            "Local AI-assisted SOC investigation · Human review required"
        )
        subtitle.setObjectName("description")
        layout.addWidget(subtitle)

        connection = QFrame()
        connection.setObjectName("chartCard")
        connection_layout = QVBoxLayout(connection)
        connection_layout.setSpacing(16)

        asset_dir = Path(__file__).resolve().parent / "assets"

        def make_brand_card(logo_name, brand_name, detail):
            card = QFrame()
            card.setStyleSheet(
                "QFrame { background: #142633; "
                "border: 1px solid #294352; border-radius: 10px; }"
            )
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(16, 14, 16, 14)
            card_layout.setSpacing(16)

            logo_path = asset_dir / logo_name
            renderer = QSvgRenderer(str(logo_path))

            if not renderer.isValid():
                raise RuntimeError(f"Invalid SVG: {logo_path}")

            # Preserve the original SVG aspect ratio.
            original_size = renderer.defaultSize()
            max_width = 76
            max_height = 76

            scale = min(
                max_width / original_size.width(),
                max_height / original_size.height(),
            )

            width = max(1, round(original_size.width() * scale))
            height = max(1, round(original_size.height() * scale))

            pixmap = QPixmap(width, height)
            pixmap.fill(QColor("transparent"))

            painter = QPainter(pixmap)
            renderer.render(painter)
            painter.end()

            # Ollama's black artwork needs white pixels
            # against the dark SOC interface.
            if logo_name == "ollama.svg":
                image = pixmap.toImage()
                for y in range(image.height()):
                    for x in range(image.width()):
                        pixel = image.pixelColor(x, y)
                        if pixel.alpha() > 0:
                            pixel.setRed(255)
                            pixel.setGreen(255)
                            pixel.setBlue(255)
                            image.setPixelColor(x, y, pixel)
                pixmap = QPixmap.fromImage(image)

            logo = QLabel()
            logo.setPixmap(pixmap)
            logo.setFixedSize(width, height)
            logo.setStyleSheet(
                "border: none; background: transparent;"
            )

            card_layout.addWidget(logo)

            text_layout = QVBoxLayout()
            name = QLabel(brand_name)
            name.setStyleSheet(
                "font-size: 17px; font-weight: 700; "
                "color: #f0f7fb; border: none;"
            )
            status = QLabel(detail)
            status.setStyleSheet(
                "font-size: 13px; color: #9db5c2; border: none;"
            )
            text_layout.addWidget(name)
            text_layout.addWidget(status)
            card_layout.addLayout(text_layout, 1)
            return card, status

        brands = QHBoxLayout()
        brands.setSpacing(14)

        ollama_card, self.ollama_status = make_brand_card(
            "ollama.svg", "Ollama", "Connection not checked"
        )
        qwen_card, self.model_status = make_brand_card(
            "qwen.svg", "Qwen3:4b", "Model not checked"
        )

        brands.addWidget(ollama_card)
        brands.addWidget(qwen_card)
        connection_layout.addLayout(brands)

        check_button = QPushButton("Check Ollama Connection")
        check_button.clicked.connect(self.check_connection)
        connection_layout.addWidget(check_button)

        layout.addWidget(connection)

        self.file_label = QLabel("No log file selected")
        self.file_label.setObjectName("description")
        self.file_label.setWordWrap(True)
        layout.addWidget(self.file_label)

        options = QHBoxLayout()

        self.rag = QCheckBox("Use Local RAG")
        self.simulation = QCheckBox("Simulation Mode")

        options.addWidget(self.rag)
        options.addWidget(self.simulation)
        options.addStretch()

        layout.addLayout(options)

        controls = QHBoxLayout()

        self.run_button = QPushButton("Run AI Investigation")
        self.run_button.setEnabled(False)
        self.run_button.clicked.connect(self.run_ai)
        controls.addWidget(self.run_button)

        self.status = QLabel("Ready")
        self.status.setObjectName("description")
        controls.addWidget(self.status)
        controls.addStretch()

        layout.addLayout(controls)

        result_title = QLabel("AI Investigation Results")
        result_title.setObjectName("sectionTitle")
        layout.addWidget(result_title)

        self.result_view = AIResultView()
        self.output = self.result_view.raw
        layout.addWidget(self.result_view, 1)

        footer = QLabel(
            "Local AI only · No automatic remediation · "
            "Human review required"
        )
        footer.setObjectName("description")
        layout.addWidget(footer)

    def set_file(self, filename):
        self.selected_file = filename
        self.file_label.setText(filename)
        self.run_button.setEnabled(
            self.process is None or
            self.process.state() == QProcess.ProcessState.NotRunning
        )

    def check_connection(self):
        try:
            with urlopen(
                "http://127.0.0.1:11434/api/tags",
                timeout=3,
            ) as response:
                data = json.load(response)

            models = [
                model.get("name", "")
                for model in data.get("models", [])
            ]

            if "qwen3:4b" in models:
                self.ollama_status.setText("Ollama: Connected")
                self.model_status.setText("Qwen3:4b: Available")
            else:
                self.ollama_status.setText("Ollama: Connected")
                self.model_status.setText(
                    "Qwen3:4b: Not installed"
                )

        except (URLError, OSError, ValueError) as error:
            self.ollama_status.setText("Ollama: Offline")
            self.model_status.setText(str(error))

    def run_ai(self):
        if self.process is not None and self.process.state() != QProcess.ProcessState.NotRunning:
            return
        if not self.selected_file:
            return

        self.result_view.clear()
        self.status.setText("AI investigation running...")
        self.run_button.setEnabled(False)

        arguments = [
            "-m", "soc_assistant.main",
            self.selected_file,
            "--analyze-ai",
            "--model", "qwen3:4b",
        ]

        if self.rag.isChecked():
            arguments.append("--rag")

        if self.simulation.isChecked():
            arguments.append("--simulation")

        self.process = QProcess(self)
        self.process.setProgram(sys.executable)
        self.process.setArguments(arguments)
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
            self.status.setText("AI investigation failed")
            self.output.setPlainText(stderr or stdout)
        else:
            try:
                result = json.loads(stdout)
                self.status.setText("AI investigation completed")
                self.result_view.display_report(result)
                self.report_ready.emit(
                    result, "AI Investigation"
                )
            except json.JSONDecodeError:
                self.status.setText("Invalid AI response")
                self.output.setPlainText(stdout)

        self.run_button.setEnabled(
            self.process is None or
            self.process.state() == QProcess.ProcessState.NotRunning
        )
