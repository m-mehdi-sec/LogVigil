"""Read-only environment and security settings for LogVigil."""

import json
import platform
import sys
from datetime import datetime
from urllib.error import URLError
from urllib.request import urlopen

from PySide6 import __version__ as pyside_version
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel,
    QPushButton, QVBoxLayout, QWidget,
)

from soc_assistant.logvigil_dashboard import REPORTS, load_reports


class Settings(QWidget):
    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 30, 32, 30)
        layout.setSpacing(16)

        title = QLabel("Settings")
        title.setObjectName("pageTitle")
        layout.addWidget(title)

        description = QLabel(
            "Local environment · Read-only configuration overview"
        )
        description.setObjectName("description")
        layout.addWidget(description)

        self.environment = self.make_card(
            "Application Environment"
        )
        layout.addWidget(self.environment[0])

        self.ai = self.make_card("Local AI Configuration")
        layout.addWidget(self.ai[0])

        self.security = self.make_card(
            "Security & Execution Boundaries"
        )
        layout.addWidget(self.security[0])

        controls = QHBoxLayout()

        refresh = QPushButton("Refresh Environment Status")
        refresh.clicked.connect(self.refresh)
        controls.addWidget(refresh)
        controls.addStretch()

        layout.addLayout(controls)

        self.updated = QLabel()
        self.updated.setObjectName("description")
        layout.addWidget(self.updated)

        layout.addStretch()
        self.refresh()

    def make_card(self, heading):
        card = QFrame()
        card.setObjectName("chartCard")

        inner = QVBoxLayout(card)
        inner.setContentsMargins(22, 20, 22, 20)
        inner.setSpacing(10)

        title = QLabel(heading)
        title.setObjectName("sectionTitle")
        inner.addWidget(title)

        value = QLabel()
        value.setWordWrap(True)
        value.setTextInteractionFlags(
            value.textInteractionFlags()
        )
        inner.addWidget(value)

        return card, value

    def refresh(self):
        reports = load_reports(REPORTS)

        self.environment[1].setText(
            "Application: LogVigil\n"
            "GUI release target: v1.1.0\n"
            f"Python: {platform.python_version()}\n"
            f"PySide6: {pyside_version}\n"
            f"Python executable: {sys.executable}\n"
            f"Stored summaries: {len(reports)}\n"
            f"Report directory: {REPORTS}"
        )

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

            ollama = "Connected"
            qwen = (
                "Available"
                if "qwen3:4b" in models
                else "Not detected"
            )

        except (URLError, OSError, ValueError):
            ollama = "Offline or unavailable"
            qwen = "Not checked"

        self.ai[1].setText(
            f"Ollama endpoint: http://127.0.0.1:11434\n"
            f"Ollama status: {ollama}\n"
            f"Default model: qwen3:4b\n"
            f"Model status: {qwen}\n"
            "Execution: Local inference"
        )

        self.security[1].setText(
            "Automatic remediation: Not provided by this GUI\n"
            "Human review: Required\n"
            "Environment settings: Read-only\n"
            "Report access: Local summaries\n"
            "Remote AI services: Not configured by this GUI"
        )

        self.updated.setText(
            "Last checked: "
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
