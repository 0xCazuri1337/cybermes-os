"""Independent audit of promoted items: re-fetch each cited URL and confirm the
quote is on the page. Parent-side, no child trust."""
import json, os, random, sqlite3, sys, urllib.request, re, html

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "db", "wks.db")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
N = int(sys.argv[1]) if len(sys.argv) > 1 else 12
TAG = re.compile(r"<[^>]+>")

def fetch(url, timeout=30):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    try:
        s = raw.decode("utf-8", "ignore")
    except Exception:
        return ""
    s = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", s)
    s = TAG.sub(" ", s)
    s = html.unescape(html.unescape(s))
    s = s.replace("\u00a0", " ").replace("\u200b", "")
    s = re.sub(r"\s+", " ", s)
    return s

def norm(q):
    q = q.replace("\u00a0", " ").replace("\u200b", "")
    return re.sub(r"\s+", " ", q).strip()

con = sqlite3.connect("file:" + DB + "?mode=ro", uri=True)
cur = con.cursor()
cur.execute("PRAGMA table_info(item)")
icols = [r[1] for r in cur.fetchall()]
print("item cols:", icols)
cur.execute("PRAGMA table_info(item_source)")
print("item_source cols:", [r[1] for r in cur.fetchall()])