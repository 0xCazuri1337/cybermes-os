P = r'C:/Users/Administrator/.hermes/cyber/tools/w10_t24_probe_page.py'

# Which URL actually FETCHES here? The T24 fixture needs a page that returns
# live prose, so a missing quote yields NOT_FOUND -> FABRICATED. example.org
# returned FETCH_FAILED -> UNVERIFIED, which never reaches the conflict branch --
# the test was measuring the wrong path entirely.
import io
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(r'C:/Users/Administrator/.hermes/cyber')
sys.path.insert(0, str(ROOT))
from wks import pipeline  # noqa: E402

CANDIDATES = [
    'https://example.com/',
    'https://www.iana.org/help/example-domains',
    'https://httpwg.org/specs/rfc9530.html',
]

for url in CANDIDATES:
    try:
        r = pipeline.fetch(url)
        text = r.get('text') or ''
        print('%-46s ok=%-5s len=%d' % (url, r.get('ok'), len(text)))
    except Exception as exc:
        print('%-46s ERR %s %s' % (url, type(exc).__name__, str(exc)[:60]))

# build the fixture against whichever URL is live and long
live = None
for url in CANDIDATES:
    try:
        r = pipeline.fetch(url)
        if r.get('ok') and len(r.get('text') or '') > 400:
            live = url
            break
    except Exception:
        continue
if not live:
    raise SystemExit('no live page available for the fixture')

sb = Path(tempfile.mkdtemp(prefix='wks-t24probe-'))
(sb / 'research' / 'incoming').mkdir(parents=True)
env = dict(os.environ, WKS_ROOT=str(sb), PYTHONPATH=str(ROOT))
import subprocess  # noqa: E402
subprocess.run([sys.executable, '-m', 'wks.cli', 'init'], cwd=str(ROOT), env=env,
               capture_output=True, text=True, timeout=600)
subprocess.run([sys.executable, '-m', 'wks.cli', 'add-class', 't24cl',
                'T24 Sandbox Class', 'web'], cwd=str(ROOT), env=env,
               capture_output=True, text=True, timeout=600)

absent = 'zzzq a span deliberately absent from any live page'
item = {
    'item_key': 't24cl.fp_rule.never_matches_the_page',
    'class_id': 't24cl', 'kind': 'fp_rule',
    'claim': 'A claim whose quote is absent from the cited page.',
    'body': 'x' * 220,
    'disproof': 'Refuted if the quoted span is present on the cited page.',
    'surface': 'web', 'severity_hint': 'low', 'hunting_value': 1,
    'sources': [
        {'url': live, 'source_type': 'docs', 'host': live.split('/')[2],
         'quote': absent},
        {'url': live + '#two', 'source_type': 'docs', 'host': live.split('/')[2],
         'quote': 'qqqw another absent span'},
    ],
}
f = sb / 'research' / 'incoming' / 't24probe.json'
f.write_text(json.dumps({'items': [item]}, indent=1), encoding='utf-8')

out = subprocess.run([sys.executable, '-m', 'wks.ingest', str(f)], cwd=str(ROOT),
                     env=env, capture_output=True, text=True, timeout=1800)
print('\nLIVE URL USED:', live)
print(out.stdout[-1200:])
if out.stderr.strip():
    print('STDERR:', out.stderr[-500:])

import sqlite3  # noqa: E402
con = sqlite3.connect(str(sb / 'db' / 'wks.db'))
rows = con.execute("SELECT count(*) FROM conflict WHERE status='open'").fetchone()[0]
print('open conflict rows after ONE real ingest:', rows)
con.close()
import shutil  # noqa: E402
shutil.rmtree(sb, ignore_errors=True)