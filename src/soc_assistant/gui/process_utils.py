"""Helpers for safe GUI subprocess shutdown."""

from PySide6.QtCore import QProcess


def stop_process(process, timeout_ms=1500):
    """Stop a running child process before its owner is destroyed."""
    if process is None:
        return

    if process.state() == QProcess.ProcessState.NotRunning:
        return

    process.terminate()
    if not process.waitForFinished(timeout_ms):
        process.kill()
        process.waitForFinished(1500)
