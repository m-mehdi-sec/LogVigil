"""Regression tests for GUI process guards."""

import os
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PySide6.QtCore import QProcess
from PySide6.QtWidgets import QApplication

from soc_assistant.gui.analysis import RunAnalysis
from soc_assistant.gui.ai_investigation import AIInvestigation


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.mark.parametrize(
    "widget_class,method_name",
    [
        (RunAnalysis, "run_analysis"),
        (AIInvestigation, "run_ai"),
    ],
)
def test_running_process_blocks_duplicate_start(
    app, widget_class, method_name
):
    widget = widget_class()
    try:
        widget.selected_file = "sample.jsonl"

        process = Mock()
        process.state.return_value = QProcess.ProcessState.Running
        widget.process = process

        getattr(widget, method_name)()

        assert widget.process is process
        process.state.assert_called()
    finally:
        widget.close()


@pytest.mark.parametrize(
    "widget_class",
    [RunAnalysis, AIInvestigation],
)
def test_failed_start_shows_error(app, widget_class):
    widget = widget_class()
    try:
        process = Mock()
        process.errorString.return_value = "Unable to start Python"
        widget.process = process

        widget.process_error(QProcess.ProcessError.FailedToStart)

        assert widget.status.text() == "Process failed to start"
        assert "Unable to start Python" in widget.output.toPlainText()
        assert widget.run_button.isEnabled()
    finally:
        widget.close()


@pytest.mark.parametrize(
    "widget_class",
    [RunAnalysis, AIInvestigation],
)
def test_crashed_process_is_not_successful(app, widget_class):
    widget = widget_class()
    try:
        process = Mock()
        process.readAllStandardOutput.return_value = b"{}"
        process.readAllStandardError.return_value = b"Process crashed"
        process.state.return_value = QProcess.ProcessState.NotRunning
        widget.process = process

        widget.finished(0, QProcess.ExitStatus.CrashExit)

        assert "failed" in widget.status.text().lower()
        assert "Process crashed" in widget.output.toPlainText()
    finally:
        widget.close()


@pytest.mark.parametrize(
    "widget_class",
    [RunAnalysis, AIInvestigation],
)
def test_finished_preserves_start_failure(app, widget_class):
    widget = widget_class()
    try:
        process = Mock()
        process.errorString.return_value = "Unable to start Python"
        widget.process = process

        widget.process_error(QProcess.ProcessError.FailedToStart)
        widget.finished(1, QProcess.ExitStatus.CrashExit)

        assert widget.status.text() == "Process failed to start"
        assert "Unable to start Python" in widget.output.toPlainText()
    finally:
        widget.close()
