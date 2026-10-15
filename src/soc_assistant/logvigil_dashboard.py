"""Generate an offline, read-only LogVigil dashboard from local summary files."""
from collections import Counter
from datetime import datetime, timezone
from html import escape
from pathlib import Path
import os
import re
import tempfile

BASE = Path.home() / 'Library' / 'Application Support' / 'LogVigil'
REPORTS = BASE / 'reports'
OUTPUT = BASE / 'dashboard.html'
FILENAME = re.compile(r'^thinkpad-security-\d{8}T\d{13}Z\.jsonl\.summary\.txt$')
FIELDS = {
    'events': re.compile(r'^Events analyzed: (\d+)$', re.M),
    'findings': re.compile(r'^Findings: (\d+)$', re.M),
    'warnings': re.compile(r'^Data quality warnings: (\d+)$', re.M),
    'groups': re.compile(r'^Investigation groups: (\d+)$', re.M),
    'severity': re.compile(r'^Highest severity: (NONE|INFORMATIONAL|LOW|MEDIUM|HIGH|CRITICAL)$', re.M),
}


def load_reports(folder):
    if not folder.is_dir():
        return []
    rows = []
    for path in sorted(folder.iterdir(), key=lambda p: p.name, reverse=True)[:1000]:
        if not FILENAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
            continue
        if path.stat().st_size > 65536:
            continue
        try:
            content = path.read_text(encoding='utf-8')
        except (OSError, UnicodeError):
            continue
        match = {key: pattern.search(content) for key, pattern in FIELDS.items()}
        if any(value is None for value in match.values()):
            continue
        rows.append({'name': path.name.removesuffix('.jsonl.summary.txt'),
                     **{key: int(match[key].group(1)) for key in ('events', 'findings', 'warnings', 'groups')},
                     'severity': match['severity'].group(1)})
        if len(rows) == 100:
            break
    return rows


def render(rows):
    totals = {key: sum(row[key] for row in rows) for key in ('events', 'findings', 'warnings', 'groups')}
    counts = Counter(row['severity'] for row in rows)
    cards = ''.join(f'<div class="card"><div class="number">{value:,}</div><div>{label}</div></div>' for label, value in
                    [('Files analyzed', len(rows)), ('Events', totals['events']), ('Findings', totals['findings']),
                     ('Warnings', totals['warnings']), ('Investigations', totals['groups'])])
    body = ''.join('<tr>' + ''.join(f'<td>{escape(str(value))}</td>' for value in
                   (row['name'], row['events'], row['findings'], row['warnings'], row['groups'], row['severity'])) + '</tr>'
                   for row in rows)
    generated = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    severity = ', '.join(f'{key}: {counts[key]}' for key in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', 'NONE') if counts[key]) or 'No reports yet'
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LogVigil | SOC Dashboard</title><style>
:root{{color-scheme:dark}}body{{font:15px system-ui,-apple-system,sans-serif;background:#0c1321;color:#e5eaf2;max-width:1100px;margin:40px auto;padding:0 20px}}
h1{{font-size:2rem}}.muted{{color:#a5b2c7}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:25px 0}}
.card{{background:#17243a;border:1px solid #2a3b55;border-radius:12px;padding:18px}}.number{{font-size:1.8rem;font-weight:700;margin-bottom:5px}}
.table-wrap{{overflow-x:auto}}table{{border-collapse:collapse;width:100%;background:#142036}}th,td{{text-align:left;padding:12px;border-bottom:1px solid #2a3b55;white-space:nowrap}}th{{color:#b8c8df}}
</style></head><body><h1>LogVigil <span class="muted">/ SOC Dashboard</span></h1>
<p class="muted">Offline, read-only view · Generated {escape(generated)} · Latest 100 valid summaries</p>
<section class="cards">{cards}</section><p><strong>Highest severity per file:</strong> {escape(severity)}</p>
<h2>Recent analyses</h2><div class="table-wrap"><table><thead><tr><th>Export</th><th>Events</th><th>Findings</th><th>Warnings</th><th>Groups</th><th>Severity</th></tr></thead><tbody>{body or '<tr><td colspan="6">No analysis summaries found yet.</td></tr>'}</tbody></table></div>
<p class="muted">Counts reflect stored summaries, not deduplicated security incidents. No live connection or automatic refresh.</p></body></html>'''


def main():
    os.umask(0o077)
    BASE.mkdir(parents=True, exist_ok=True)
    html = render(load_reports(REPORTS))
    fd, temp = tempfile.mkstemp(prefix='.dashboard-', suffix='.html', dir=BASE)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as file:
            file.write(html)
        os.replace(temp, OUTPUT)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    print(f'Dashboard generated: {OUTPUT}')


if __name__ == '__main__':
    main()
