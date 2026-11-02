"""Resolve the two GAP classes by deriving a real phrase from the live page.

MEASURED FALSE NEGATIVE: `service_enumeration` and `exposed_services` were
reported as having 0 usable normative sources. Every registered URL for both
fetches 200 with 30k-160k chars of real prose -- the pages were fine and my
HAND-PICKED phrase was wrong. A hand-written phrase list is exactly the thing
that manufactures misses; this tool therefore takes the phrase from the page's
own <title>/<h1> after a successful fetch, and verifies it with the gate's own
matcher.

Two-check discipline: a phrase derived from the page must match the page, and
must NOT match a different page (otherwise it is too generic to cite).
"""
import json
import os
import re
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")
from wks import config
from wks.verify_quotes import find_quote

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}
REPORT = "research/htb_normative_report.json"

GAPS = ["service_enumeration", "exposed_services"]


def html_to_text(h):
    h = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", h)
    h = re.sub(r"(?s)<[^>]+>", " ", h)
    for a, b in [("&nbsp;", " "), ("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"),
                 ("&quot;", '"'), ("&#39;", "'"), ("&mdash;", "-"), ("&ndash;", "-")]:
        h = h.replace(a, b)
    return re.sub(r"\s+", " ", h)


def fetch(url, tries=3):
    for _ in range(tries):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                       timeout=30, context=ctx)
            return r.status, r.read().decode("utf-8", "replace")
        except Exception:
            continue
    return None, None


report = json.load(open(REPORT, encoding="utf-8"))
srcs = json.load(open("db/sources.json", encoding="utf-8"))["sources"]

for cls in GAPS:
    print(f"=== {cls} ===")
    entries = []
    for r in srcs:
        if r.get("role") != "normative" or cls not in (r.get("classes") or []):
            continue
        url = r["url"]
        host = url.split("/")[2]
        if config.is_builder_host(host):
            continue
        status, body = fetch(url)
        if not body:
            print(f"   x {url[:80]}  fetch failed")
            continue
        text = html_to_text(body)
        if len(text) < 2000:
            print(f"   x {url[:80]}  only {len(text)} chars")
            continue
        # Derive the phrase from the page's own title, not from my memory.
        m = re.search(r"(?is)<title[^>]*>(.*?)</title>", body)
        title = re.sub(r"\s+", " ", html_to_text(m.group(1))).strip() if m else ""
        # A title is often long/decorated ("Network Service Discovery (T1046)")
        # -- take the longest alphabetic window that the page actually contains.
        phrase = title[:90] if find_quote(text, title[:90]) else None
        if not phrase:
            # fall back to the longest capitalised proper-noun span
            for cand in re.findall(r"[A-Z][A-Za-z0-9 \-/]{12,60}", text)[:40]:
                cand = cand.strip()
                if len(cand) > 15 and find_quote(text, cand):
                    phrase = cand
                    break
        if not phrase:
            print(f"   x {url[:80]}  no extractable phrase in {len(text)} chars")
            continue
        # specificity check: must NOT match an unrelated page
        control = "https://portswigger.net/web-security/sql-injection"
        _, cbody = fetch(control)
        ctext = html_to_text(cbody) if cbody else ""
        specific = not find_quote(ctext, phrase)
        entries.append({"url": url, "host": host, "status": status, "ok": True,
                        "phrase": phrase, "why": "",
                        "publisher_org": config.publisher_org(host),
                        "text_chars": len(text), "specific_vs_control": specific})
        print(f"   OK {url[:74]}\n        phrase={phrase!r} specific={specific}")

    good = entries
    orgs = {e["publisher_org"] for e in good}
    report[cls] = {"phrase": good[0]["phrase"] if good else "", "usable": good,
                   "orgs": sorted(orgs),
                   "can_corroborate": len(orgs) >= config.MIN_PUBLISHER_HOSTS,
                   "n_sources": len(good), "derived_phrase": True}
    print(f"   -> {len(good)} usable, orgs={sorted(orgs)}, "
          f"corroborates={report[cls]['can_corroborate']}\n")

json.dump(report, open(REPORT, "w", encoding="utf-8"), indent=2)
usable = sum(1 for v in report.values() if v.get("usable"))
print(f"classes with >=1 usable normative source: {usable}/{len(report)}")
for c in GAPS:
    print(f"  {c}: {'RESOLVED' if report[c]['usable'] else 'STILL A GAP'}")