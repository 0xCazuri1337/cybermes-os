"""Locate the EXACT divergence point between a stored quote and the live page,
so a producer can re-cut a verbatim span instead of guessing.

Prints the longest common prefix length and the two windows that differ.
"""
import difflib
import html
import os
import re
import sqlite3
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")


def plain(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=35) as r:
        s = r.read().decode("utf-8", "ignore")
    s = re.sub(r"(?is)<(script|style|nav|footer)[^>]*>.*?</\1>", " ", s)
    s = TAG.sub(" ", s)
    s = html.unescape(html.unescape(s))
    for a, b in (("\u00a0", " "), ("\u200b", ""), ("`", ""), ("\u2019", "'"),
                 ("\u201c", '"'), ("\u201d", '"'), ("\u2018", "'")):
        s = s.replace(a, b)
    return WS.sub(" ", s)


PAIRS = [
    ("xss.fp_rule.sink_reachability.source_never_reaches_execution_sink",
     "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"),
    ("xss.fp_rule.json_api.content_type_json_is_not_html_execution",
     "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"),
    ("ad_group_policy.technique.sysvol_gpo_write_changes_every_host",
     "https://attack.mitre.org/techniques/T1484/001/"),
]

con = sqlite3.connect("file:" + os.path.join(ROOT, "db", "wks.db") + "?mode=ro", uri=True)
cur = con.cursor()
for key, url in PAIRS:
    cur.execute("""select isr.quote from item i join item_source isr on isr.item_id=i.id
                   join source s on s.id=isr.source_id where i.item_key=? and s.url=?""",
                (key, url))
    quote = cur.fetchone()[0]
    page = plain(url)
    q = WS.sub(" ", quote).strip()
    print("=" * 78)
    print(key)
    # longest common prefix anchored at the quote's first occurrence of its 6-word head
    head = " ".join(q.split()[:6])
    i = page.find(head)
    if i == -1:
        i = page.find(" ".join(q.split()[:3]))
    if i == -1:
        print("  head absent from page:", repr(head))
        continue
    seg = page[i:i + len(q) + 400]
    sm = difflib.SequenceMatcher(None, q, seg, autojunk=False)
    n = 0
    for a, b, size in sm.get_matching_blocks():
        if a == b and a > 0:
            n = a + size
        elif a > 0:
            n = max(n, a + size)
    print("  longest common prefix:", n, "of", len(q))
    print("  QUOTE tail:", repr(q[n:n + 110]))
    print("  PAGE  tail:", repr(seg[n:n + 110]))
    # also report the first differing opcode
    for tag, a1, a2, b1, b2 in sm.get_opcodes():
        if tag != "equal":
            print("  first diff %s at q[%d:%d] vs p[%d:%d]" % (tag, a1, a2, b1, b2))
            print("     quote:", repr(q[a1:a2])[:150])
            print("     page :", repr(seg[b1:b2])[:150])
            break