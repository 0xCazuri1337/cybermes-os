P = r'C:/Users/Administrator/.hermes/cyber/wks/ingest.py'

# Prove T24 actually fails without the fix. A regression test that has only ever
# passed protects nothing, so this restores the unconditional INSERT, runs T24,
# and puts the fix back -- failing loudly rather than reverting silently.
import io
import shutil
import subprocess
import sys
import time

BAK = P + '.t24bak'
shutil.copy2(P, BAK)
src = io.open(BAK, encoding='utf-8').read()

FIXED = """                    urls = [s.get("url") for s in it["sources"]]
                    fingerprint = json.dumps(
                        {"class_id": cid, "claim": it["claim"], "urls": sorted(
                            u for u in urls if u)},
                        sort_keys=True, separators=(",", ":"))
                    detail = f"cited quote not present on page: {urls}"
                    row = con.execute(
                        "SELECT id, resolution FROM conflict WHERE status='open'"
                        " AND class_id=? AND claim_a=? AND claim_b=?",
                        (cid, it["claim"], detail)).fetchone()
                    if row is None:
                        con.execute(
                            "INSERT INTO conflict"
                            " (class_id,topic,claim_a,claim_b,status,created_at)"
                            " VALUES (?,?,?,?,'open',datetime('now'))",
                            (cid, "fabricated-evidence", it["claim"], detail))
                    else:
                        # already recorded: count the recurrence instead of
                        # duplicating the row
                        con.execute(
                            "UPDATE conflict SET resolution=?"
                            " WHERE id=?",
                            ("repeat-rejection fingerprint=%s" % fingerprint, row["id"]))"""

PREFIX = '''                con.execute(
                    "INSERT INTO conflict (class_id,topic,claim_a,claim_b,status,created_at)"
                    " VALUES (?,?,?,?,'open',datetime('now'))",
                    (cid, "fabricated-evidence", it["claim"],
                     f"cited quote not present on page: "
                     f"{[s.get('url') for s in it['sources']]}"))'''

assert FIXED in src, 'fixed block not found -- cannot build the negative control'
buggy = src.replace(FIXED, PREFIX.rstrip('\n'), 1)
io.open(P, 'w', encoding='utf-8').write(buggy)

try:
    t0 = time.time()
    p = subprocess.run(
        [sys.executable, 'eval/test_wks_conflict_idempotence.py'],
        cwd=r'C:/Users/Administrator/.hermes/cyber',
        capture_output=True, text=True, timeout=2400)
    print('=== T24 under the PRE-FIX writer (must FAIL) ===')
    print(p.stdout[-2200:])
    print('exit code:', p.returncode, '(%.0fs)' % (time.time() - t0))
    print('\nVERDICT: T24 is %s without the fix'
          % ('RED (good -- it catches the bug)' if p.returncode != 0
             else 'GREEN (BAD -- the test cannot fail)'))
finally:
    shutil.copy2(BAK, P)
    io.open(P + '.t24bak', encoding='utf-8').close()
    import os
    os.remove(P + '.t24bak')
    print('\nfix restored from backup')