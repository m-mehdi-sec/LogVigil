"""Offline regression tests for LogVigil's SMB importer and HTML dashboard."""
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from soc_assistant import logvigil_dashboard as dashboard
from soc_assistant import logvigil_smb_import as importer


@pytest.fixture
def isolated_import(tmp_path, monkeypatch):
    source = tmp_path / 'share'
    source.mkdir()
    state_dir = tmp_path / 'state'
    monkeypatch.setattr(importer, 'SOURCE', source)
    monkeypatch.setattr(importer, 'STATE_DIR', state_dir)
    monkeypatch.setattr(importer, 'STATE', state_dir / 'processed-smb.json')
    monkeypatch.setattr(importer, 'LOCK', state_dir / 'smb-import.lock')
    monkeypatch.setattr(importer, 'REPORT_DIR', state_dir / 'reports')
    monkeypatch.setattr(importer.os.path, 'ismount', lambda p: p == source)
    return source, state_dir


def test_import_requires_mounted_share(isolated_import, monkeypatch):
    monkeypatch.setattr(importer.os.path, 'ismount', lambda p: False)
    assert importer.main() == 1


def test_import_refuses_invalid_state(isolated_import):
    _, state_dir = isolated_import
    state_dir.mkdir()
    (state_dir / 'processed-smb.json').write_text('not-json', encoding='utf-8')
    assert importer.main() == 1
    assert (state_dir / 'processed-smb.json').read_text(encoding='utf-8') == 'not-json'


def test_import_deduplicates_and_updates_dashboard(isolated_import, monkeypatch):
    source, state_dir = isolated_import
    filename = 'thinkpad-security-20261015T1441207470096Z.jsonl'
    path = source / filename
    path.write_text('{"event_id":4740}\n', encoding='utf-8')
    os.utime(path, (1, 1))
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if '-m' in args:
            return SimpleNamespace(returncode=0, stdout='Events analyzed: 1\nFindings: 1\n', stderr='')
        return SimpleNamespace(returncode=0, stdout='Dashboard generated', stderr='')

    monkeypatch.setattr(importer.subprocess, 'run', fake_run)
    assert importer.main() == 0
    assert len(calls) == 2
    assert (state_dir / 'reports' / (filename + '.summary.txt')).exists()
    saved = json.loads((state_dir / 'processed-smb.json').read_text(encoding='utf-8'))
    assert saved[filename] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert importer.main() == 0
    assert len(calls) == 2


def test_failed_analysis_does_not_acknowledge(isolated_import, monkeypatch):
    source, state_dir = isolated_import
    path = source / 'thinkpad-security-20261015T1441207470096Z.jsonl'
    path.write_text('{}\n', encoding='utf-8')
    os.utime(path, (1, 1))
    monkeypatch.setattr(importer.subprocess, 'run', lambda *a, **k: SimpleNamespace(returncode=1, stderr='test failure'))
    assert importer.main() == 1
    assert not (state_dir / 'processed-smb.json').exists()


def test_dashboard_failure_keeps_successful_import_state(isolated_import, monkeypatch):
    source, state_dir = isolated_import
    filename = 'thinkpad-security-20261015T1441207470096Z.jsonl'
    path = source / filename
    path.write_text('{}\n', encoding='utf-8')
    os.utime(path, (1, 1))
    count = 0

    def fake_run(args, **kwargs):
        nonlocal count
        count += 1
        if count == 1:
            return SimpleNamespace(returncode=0, stdout='Events analyzed: 1', stderr='')
        return SimpleNamespace(returncode=1, stdout='', stderr='dashboard failure')

    monkeypatch.setattr(importer.subprocess, 'run', fake_run)
    assert importer.main() == 1
    assert filename in json.loads((state_dir / 'processed-smb.json').read_text(encoding='utf-8'))


def test_dashboard_escapes_untrusted_filename():
    html = dashboard.render([{'name': '<script>alert(1)</script>', 'events': 1, 'findings': 0,
                              'warnings': 0, 'groups': 0, 'severity': 'NONE'}])
    assert '<script>' not in html
    assert '&lt;script&gt;' in html


def test_dashboard_rejects_malformed_reports(tmp_path):
    report = tmp_path / 'thinkpad-security-20261015T1441207470096Z.jsonl.summary.txt'
    report.write_text('Events analyzed: 1\nFindings: 1\n', encoding='utf-8')
    assert dashboard.load_reports(tmp_path) == []


def test_dashboard_reads_valid_summary(tmp_path):
    report = tmp_path / 'thinkpad-security-20261015T1441207470096Z.jsonl.summary.txt'
    report.write_text('Events analyzed: 2\nFindings: 1\nData quality warnings: 0\n'
                      'Investigation groups: 1\nHighest severity: MEDIUM\n', encoding='utf-8')
    rows = dashboard.load_reports(tmp_path)
    assert len(rows) == 1
    assert rows[0]['findings'] == 1
    assert rows[0]['severity'] == 'MEDIUM'
