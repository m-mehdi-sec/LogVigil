"""Regression tests for GUI subprocess shutdown."""

import sys

from PySide6.QtCore import QProcess

from soc_assistant.gui.process_utils import stop_process


def test_stop_none():
    stop_process(None)


def test_stop_not_running():
    process = QProcess()
    stop_process(process)
    assert process.state() == QProcess.ProcessState.NotRunning


def test_stop_running_process():
    process = QProcess()
    process.start(
        sys.executable,
        ["-c", "import time; time.sleep(30)"],
    )
    assert process.waitForStarted(3000)

    try:
        stop_process(process)
        assert process.state() == QProcess.ProcessState.NotRunning
    finally:
        if process.state() != QProcess.ProcessState.NotRunning:
            process.kill()
            process.waitForFinished(3000)


def test_stop_process_fallback():
    class FakeProcess:
        def __init__(self):
            self.running = True
            self.killed = False

        def state(self):
            if self.running:
                return QProcess.ProcessState.Running
            return QProcess.ProcessState.NotRunning

        def terminate(self):
            pass

        def waitForFinished(self, timeout):
            if self.killed:
                self.running = False
                return True
            return False

        def kill(self):
            self.killed = True

    process = FakeProcess()
    stop_process(process, timeout_ms=1)

    assert process.killed
    assert process.state() == QProcess.ProcessState.NotRunning
