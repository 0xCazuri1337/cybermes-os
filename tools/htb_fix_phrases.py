"""Strip HTML entities from derived normative phrases, and keep only the prose.

MEASURED: `htb_fill_gaps.py` derived each normative quote from the page's
<title>, and MITRE's titles end in the entity `&reg;`
("Network Service Discovery, Technique T1046 - Enterprise | MITRE ATT&CK&reg;").
The gate fetches the page and UNESCAPES entities, so the body contains a real
registered-trademark glyph, never the literal `&reg;` -- the quote could not
match and two otherwise-valid items were refused as FABRICATED.

An entity is a rendering artefact, not evidence. So: unescape the derived
phrase, keep only the part before a pipe separator, trim to a sentence-ish
length, and then RE-VERIFY it against the live page with the gate's own
matcher. A phrase that cannot be re-verified is dropped rather than shipped.
"""
import ast
import io
import json
import os
import re
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")
from wks import config, pipeline
from wks.verify_quotes import find_quote

REPORT = "research/htb_normative_report.json"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}

rep = json.load(open(REPORT, encoding="utf-8"))
fixed = dropped = 0

for cls, v in rep.items():
    for e in v.get("usable", []):
        ph = e.get("phrase")
        if not ph:
            continue
        try:
            req = urllib.request.Request(e["url"], headers=UA)
            with urllib.request.urlopen(req, timeout=30, context=ctx) as r:
                ctype = r.headers.get("Content-Type", "")
                body = r.read()
        except Exception:
            continue
        text = pipeline.extract_text(body, ctype)
        if find_quote(text, ph):
            continue                      # already good
        import html as html_mod
        cand = html_mod.unescape(ph)
        # drop the site suffix after a pipe; keep the human-readable head
        cand = cand.split("|")[0].strip()
        cand = re.sub(r"\s+", " ", cand)
        if len(cand) > 110:
            cand = cand[:110].rsplit(" ", 1)[0]
        if cand and find_quote(text, cand):
            print(f"  FIXED  {cls:<24} {ph[:52]!r} -> {cand[:52]!r}")
            e["phrase"] = cand
            e["phrase_note"] = "entity/pipe-trimmed from <title>"
            fixed += 1
        else:
            print(f"  DROP   {cls:<24} no verifiable phrase for {e['url'][:56]}")
            e["ok"] = False
            dropped += 1

json.dump(rep, open(REPORT, "w", encoding="utf-8"), indent=2)
print(f"\nfixed={fixed} dropped={dropped}")

# report-level rebuild: usable lists no longer contain the dropped entries
for cls, v in rep.items():
    v["usable"] = [e for e in v.get("usable", []) if e.get("ok", True)]
    v["orgs"] = sorted({e["publisher_org"] for e in v["usable"]})
    v["can_corroborate"] = len(v["orgs"]) >= config.MIN_PUBLISHER_HOSTS
json.dump(rep, open(REPORT, "w", encoding="utf-8"), indent=2)
usable = sum(1 for v in rep.values() if v.get("usable"))
print(f"classes with >=1 usable normative source: {usable}/{len(rep)}")
for c in ("exposed_services", "service_enumeration"):
    v = rep.get(c, {})
    print(f"  {c}: usable={len(v.get('usable', []))} orgs={v.get('orgs')}")