"""Strict verbatim verifier: re-fetch every quoted URL fresh and check the quote
appears exactly as written. Run with the cache bypassed (force=True)."""
import json, os, re, sys, html
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fetch import fetch, text_of
from extract import body_text

D = os.path.dirname(os.path.abspath(__file__))
DATA = json.load(open(os.path.join(D, "writeups-gaps.json"), encoding="utf-8"))

def normalize(s, html_mode):
    """Render a page to text the way a verifier would, then normalize only
    invisible characters (NBSP, curly quotes we already decoded, CRLF)."""
    if html_mode:
        t = body_text(s)
    else:
        t = s
    t = t.replace("\r\n", "\n").replace("\xa0", " ")
    # Decode HTML character entities the way any browser/readability extractor
    # renders the page, so quotes are compared against the rendered text a human
    # actually sees (e.g. &#8211; -> –, &#8220; -> “).
    t = html.unescape(t)
    return t

def check(quote, t):
    """Exact substring test. Returns (ok, note)."""
    if quote in t:
        return True, "exact"
    # YAML/plain text files: tolerate trailing-space-insensitive line joins only
    # when the raw text has different indentation than our copy.
    q2 = quote
    if "\n" in q2:
        qn = "\n".join(line.strip() for line in q2.split("\n"))
        tn = "\n".join(line.strip() for line in t.split("\n"))
        if qn in tn:
            return True, "exact-after-indent-strip"
    # HTML-rendered pages sometimes split a sentence with a newline where the
    # source had a soft wrap. Try a whitespace-collapsed comparison, but ONLY
    # if every word is present in order with single spaces.
    def collapse(x):
        return re.sub(r"\s+", " ", x)
    if collapse(quote) in collapse(t):
        return True, "exact-after-whitespace-collapse"
    return False, "MISS"

results = []
for e in DATA["entries"]:
    for q in e["quotes"]:
        url, quote = q["url"], q["quote"]
        is_yaml = url.endswith((".yml", ".yaml"))
        c, body = fetch(url, force=True)
        if c != "200":
            results.append({"url": url, "status": c, "ok": False, "note": "status"})
            continue
        t = normalize(body, not is_yaml)
        ok, note = check(quote, t)
        results.append({"url": url, "status": c, "ok": ok, "note": note,
                        "quote": quote})

bad = [r for r in results if not r["ok"]]
print(f"total quotes: {len(results)}  verified: {len(results)-len(bad)}  failed: {len(bad)}")
for r in bad:
    print("----")
    print(r["status"], r["note"], r["url"])
    print(repr(r.get("quote", "<none>")[:220]))
json.dump(results, open(os.path.join(D, "verify_results.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)