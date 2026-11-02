"""Round-5: (a) prove book.hacktricks.wiki is a catch-all shell, not real prose,
(b) extract REAL hrefs from dirkjan.nl instead of guessing paths.

(a) matters because three different deep URLs returned byte-identical 9358-char
bodies. A 200 with the same length on every path is the signature of an SPA
shell, and shipping it in a brief would spend every child's fetch budget on a
page that holds none of the cited text -- the same shape as the WSTG
`/latest` page that returns 200 and 5.4KB with none of the quote.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402

A = "https://book.hacktricks.wiki/en/windows-hardening/active-directory-exploitation/"
B = "https://book.hacktricks.wiki/en/generic-methodologies-and-resources/"
C = "https://book.hacktricks.wiki/en/pentesting-methodologies/"

ta = (pipeline.fetch(A).get("text") or "")
tb = (pipeline.fetch(B).get("text") or "")
tc = (pipeline.fetch(C).get("text") or "")
print("hacktricks A==B:", ta == tb, " A==C:", ta == tc, " len:", len(ta))

AD_MARKERS = ["Delegation", "DCSync", "Kerberos", "NTLM", "Group Policy", "RDP"]
for m in AD_MARKERS:
    print("  hacktricks contains %-14s %s" % (m, m.lower() in ta.lower()))

print()
print("--- dirkjan.nl real hrefs ---")
r = pipeline.fetch("https://dirkjan.nl/")
raw = r.get("raw") or r.get("text") or ""
hrefs = sorted(set(re.findall(r'href="(https?://dirkjan\.nl/[^"#]+)"', r.get("html") or "")))
if not hrefs:
    hrefs = sorted(set(re.findall(r'(https?://dirkjan\.nl/[a-z0-9\-]+/)', raw)))
for h in hrefs:
    print(" ", h)