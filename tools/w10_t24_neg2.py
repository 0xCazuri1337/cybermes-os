P = r'C:/Users/Administrator/.hermes/cyber/wks/ingest.py'

# Prove T24 actually fails without the fix. A regression test that has only ever
# passed protects nothing, so this swaps the dedupe block back to the original
# unconditional INSERT (by line range, not by text -- the earlier attempt used a
# 20-space literal against a 16-space block and never matched), runs T24, and
# restores the fix in a finally block.
import io
import os
import shutil
import subprocess
import sys
import time

BAK = P + '.t24bak'
shutil.copy2(P, BAK)
lines = io.open(BAK, encoding='utf-8').read().split('\n')

START_MARK = 'urls = [s.get("url") for s in it["sources"]]'
END_MARK = '("repeat-rejection fingerprint=%s" % fingerprint, row["id"]))'

si = next(i for i, l in enumerate(lines) if l.strip() == START_MARK)
ei = next(i for i, l in enumerate(lines) if l.strip() == END_MARK)
assert ei > si, 'markers out of order'
print('replacing lines %d..%d' % (si + 1, ei + 1))

BUGGY = [
    '                con.execute(',
    '                    "INSERT INTO conflict (class_id,topic,claim_a,claim_b,'
    'status,created_at)"',
    "                    \" VALUES (?,?,?,?,'open',datetime('now'))\",",
    '                    (cid, "fabricated-evidence", it["claim"],',
    '                     f"cited quote not present on page: "',
    "                     f\"{[s.get('url') for s in it['sources']]}\"))",
]

io.open(P, 'w', encoding='utf-8').write('\n'.join(lines[:si] + BUGGY + lines[ei + 1:]))
try:
    t0 = time.time()
    p = subprocess.run(
        [sys.executable, 'eval/test_wks_conflict_idempotence.py'],
        cwd=r'C:/Users/Administrator/.hermes/cyber',
        capture_output=True, text=True, timeout=2400)
    print('=== T24 under the PRE-FIX writer (must FAIL) ===')
    print(p.stdout[-2000:])
    print('exit code:', p.returncode, '(%.0fs)' % (time.time() - t0))
    print('\nVERDICT: T24 is %s without the fix'
          % ('RED (good -- it catches the bug)' if p.returncode != 0
             else 'GREEN (BAD -- the test cannot fail)'))
finally:
    shutil.copy2(BAK, P)
    os.remove(BAK)
    fixed = io.open(P, encoding='utf-8').read()
    print('\nfix restored:', 'repeat-rejection fingerprint' in fixed)