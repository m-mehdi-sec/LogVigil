"""Analyze new LogVigil exports from a mounted, read-only SMB share.

Run periodically with launchd; never modifies or deletes SMB source files.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

SOURCE = Path('/Volumes/LogVigil-Logs')
ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = Path.home() / 'Library' / 'Application Support' / 'LogVigil'
STATE = STATE_DIR / 'processed-smb.json'
LOCK = STATE_DIR / 'smb-import.lock'
REPORT_DIR = STATE_DIR / 'reports'
PATTERN = re.compile(r'^thinkpad-security-\d{8}T\d{13}Z\.jsonl$')
MAX_FILES_PER_RUN = 20
MAX_FILE_BYTES = 1_048_576
MIN_AGE_SECONDS = 10


def atomic_json(path, value):
    fd, tmp = tempfile.mkstemp(prefix='.state-', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as out:
            json.dump(value, out, sort_keys=True)
            out.write('\n')
            out.flush()
            os.fsync(out.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def main():
    os.umask(0o077)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    with LOCK.open('a+') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print('LogVigil SMB import is already running.')
            return 0
        if not SOURCE.is_dir() or not os.path.ismount(SOURCE):
            print('SMB share is not mounted; no files processed.', file=sys.stderr)
            return 1
        if STATE.exists():
            try:
                state = json.loads(STATE.read_text(encoding='utf-8'))
                if not isinstance(state, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in state.items()):
                    raise ValueError('Invalid state format')
            except (ValueError, OSError) as exc:
                print(f'Invalid import state; refusing to reset: {exc}', file=sys.stderr)
                return 1
        else:
            state = {}
        processed = 0
        for path in sorted(SOURCE.iterdir(), key=lambda p: p.name):
            if not PATTERN.fullmatch(path.name) or path.is_symlink() or not path.is_file():
                continue
            before = path.stat()
            if before.st_size > MAX_FILE_BYTES or before.st_size == 0 or time.time() - before.st_mtime < MIN_AGE_SECONDS:
                continue
            digest = hashlib.sha256()
            with path.open('rb') as handle:
                while chunk := handle.read(65536):
                    digest.update(chunk)
            after = path.stat()
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                continue
            signature = digest.hexdigest()
            if state.get(path.name) == signature:
                continue
            # The analysis process reads the source; state advances only on success.
            result = subprocess.run(
                [sys.executable, '-m', 'soc_assistant.main', str(path), '--report', '--summary'],
                cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
            )
            if result.returncode != 0:
                print(f'Analysis failed for {path.name}: {result.stderr.strip()}', file=sys.stderr)
                return 1
            # Recheck before acknowledging in case the source changed during analysis.
            current = path.stat()
            if (before.st_size, before.st_mtime_ns) != (current.st_size, current.st_mtime_ns):
                print(f'Source changed during analysis: {path.name}', file=sys.stderr)
                return 1
            report = REPORT_DIR / f'{path.name}.summary.txt'
            report.write_text(result.stdout, encoding='utf-8')
            state[path.name] = signature
            atomic_json(STATE, state)
            print(f'Analyzed: {path.name}')
            processed += 1
            if processed >= MAX_FILES_PER_RUN:
                break
        print(f'New files analyzed: {processed}')

        if processed > 0:
            dashboard = subprocess.run(
                [sys.executable, str(ROOT / 'src/soc_assistant/logvigil_dashboard.py')],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if dashboard.returncode != 0:
                print(
                    f'Dashboard update failed: {dashboard.stderr.strip()}',
                    file=sys.stderr,
                )
                return 1
            print('Dashboard updated.')

        return 0


if __name__ == '__main__':
    raise SystemExit(main())
