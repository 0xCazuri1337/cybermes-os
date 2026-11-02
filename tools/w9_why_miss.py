"""Why did find_quote reject quotes the gate accepted at ingest time?
Test the gate matcher against the LIVE page text for the exact stored quotes,
then against progressively looser variants, to locate the divergence.

Also check whether the quote exceeds the 200-char brief limit.
"""
import io
import os
import re
import sqlite3
import sys
import urllib.request
import html

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from wks.verify_quotes import find_quote  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")


def raw_fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=35) as r:
        return r.read().decode("utf-8", "ignore")


def plain(html_text):
    s = re.sub(r"(?is)<(script|style|nav|footer)[^>]*>.*?</\1>", " ", html_text)
    s = TAG.sub(" ", s)
    s = html.unescape(html.unescape(s))
    return WS.sub(" ", s).replace("\u00a0", " ")


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
    r = cur.fetchone()
    if not r:
        print("no citation", key, url)
        continue
    quote = r[0]
    page = plain(raw_fetch(url))
    print("=" * 78)
    print(key)
    print("  quote len =", len(quote), "(brief limit 200)")
    print("  find_quote(page, quote)      ->", bool(find_quote(page, quote)))
    variants = {
        "curly->straight quotes": quote.replace("\u201c", '"').replace("\u201d", '"')
                                    .replace("\u2018", "'").replace("\u2019", "'"),
        "strip < > backticks": quote.replace("`", "").replace("<", "").replace(">", ""),
        "collapse spaces": WS.sub(" ", quote),
    }
    if "attack.mitre.org" in url:
        # MITRE renders placeholders as <DOMAIN>; the stored quote dropped them
        variants["mitre placeholders dropped from quote"] = re.sub(
            r"\s*\\<[A-Z_]+>\\?", "", quote)
        variants["mitre placeholders blanked in quote"] = re.sub(
            r"<[A-Z_]+>", "<DOMAIN>", quote)
    for label, v in variants.items():
        print("  %-40s -> %s" % (label, bool(find_quote(page, v))))
    # what does the page actually hold around the divergence?
    frag = " ".join(WS.sub(" ", quote).split()[:6])
    i = page.find(frag.split()[0])
    print("  page around first words:", repr(page[i:i + 220]) if i != -1 else "NOT FOUND")