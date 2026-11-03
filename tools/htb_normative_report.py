"""Validate EVERY registered normative source (role == 'normative') against the
gate's own quote matcher, using the class -> sources.json mapping.

Never guess a URL: db/sources.json is the single registry (OPERATOR.md). The
three failures in the earlier hand-written probe (deser, file_upload, idor) were
all invented paths -- the registered URLs for those same classes fetch fine.

Prints a per-class PASS/FAIL table plus a machine-readable report used by the
item builder, so an item can only ever be paired with a source proven
fetchable AND carrying the phrase we intend to quote.
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
REPORT = "knowledge/materials/htb_normative_report.json"

srcs = json.load(open("db/sources.json", encoding="utf-8"))["sources"]
by_class = {}
for r in srcs:
    if r.get("role") != "normative":
        continue
    for c in (r.get("classes") or []):
        by_class.setdefault(c, []).append(r)

# Phrase must be a real, distinctive token likely on the page. Derived from the
# registry's own title/note where possible, else a class vocabulary token.
VOCAB = {
    "deser": "Deserialization", "file_upload": "Unrestricted File Upload",
    "idor": "Insecure Direct Object Reference", "sqli": "SQL injection",
    "xss": "cross-site scripting", "ssrf": "Server-Side Request Forgery",
    "path_traversal": "path traversal", "ssti": "template injection",
    "smb": "SMB", "ad_kerberos": "Kerberos", "tunneling_pivoting": "Proxy",
    "pass_the_hash": "Pass the Hash", "exposed_rmm": "Remote Access Software",
    "cmd": "command injection", "xxe": "XML External Entity",
    "ldap_enum": "LDAP", "service_enumeration": "Network Service Scanning",
    "rdp": "Remote Desktop Protocol", "dns_enum": "DNS", "misconfig": "Misconfiguration",
    "info_disclosure": "information disclosure", "authz": "Authorization Bypass",
    "authn": "Authentication", "jwt": "JWT", "smuggling": "request smuggling",
}


def html_to_text(h):
    h = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", h)
    h = re.sub(r"(?s)<[^>]+>", " ", h)
    h = (h.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<")
          .replace("&gt;", ">").replace("&quot;", '"').replace("&#39;", "'"))
    return re.sub(r"\s+", " ", h)


def fetch(url, tries=2):
    for _ in range(tries):
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(url, headers=UA), timeout=30, context=ctx)
            return r.status, r.read().decode("utf-8", "replace")
        except Exception:
            continue
    return None, None


report = {}
for cls in sorted(by_class):
    phrase = VOCAB.get(cls, cls.replace("_", " "))
    entries = []
    for r in by_class[cls]:
        url = r["url"]
        host = url.split("/")[2]
        if config.is_builder_host(host):
            entries.append({"url": url, "host": host, "ok": False,
                            "why": "builder host never counts"})
            continue
        status, body = fetch(url)
        if body is None:
            entries.append({"url": url, "host": host, "ok": False, "why": "fetch failed"})
            continue
        text = html_to_text(body)
        hit = find_quote(text, phrase)
        entries.append({
            "url": url, "host": host, "status": status, "ok": bool(hit and len(text) > 2000),
            "phrase": phrase, "why": "" if hit else f"phrase not found in {len(text)} chars",
            "publisher_org": config.publisher_org(host), "text_chars": len(text),
        })
    good = [e for e in entries if e["ok"]]
    orgs = {e["publisher_org"] for e in good}
    report[cls] = {"phrase": phrase, "usable": good, "orgs": sorted(orgs),
                   "can_corroborate": len(orgs) >= config.MIN_PUBLISHER_HOSTS,
                   "n_sources": len(by_class[cls])}
    flag = "OK " if good else "BAD"
    print(f"  {flag} {cls:<22} {len(good)}/{len(by_class[cls])} usable  orgs={sorted(orgs)}")
    for e in entries:
        if not e["ok"]:
            print(f"        x {e['url'][:88]}  {e.get('why','')}")

# ---- REGRESSION GUARD -------------------------------------------------
# This report is the GENERATOR's output, but two of its checks were repaired in
# other tools (htb_fill_gaps.py derives phrases; htb_fix_phrases.py unescapes
# entities). Re-running this script would overwrite a good report with a worse
# one, so refuse unless the new result is not a regression.
import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument("--force", action="store_true",
                 help="overwrite even if this would lose usable sources")
_args, _ = _ap.parse_known_args()

if os.path.exists(REPORT) and not _args.force:
    try:
        old = json.load(open(REPORT, encoding="utf-8"))
    except Exception:
        old = {}

    def _usable(rep):
        return sum(1 for v in rep.values() if v.get("usable"))

    def _per_class(rep):
        return {c: len(v.get("usable") or []) for c, v in rep.items()}

    o_tot, n_tot = _usable(old), _usable(report)
    o_pc, n_pc = _per_class(old), _per_class(report)
    lost = {c: (o_pc.get(c, 0), n_pc.get(c, 0)) for c in o_pc
            if n_pc.get(c, 0) < o_pc.get(c, 0)}
    if n_tot < o_tot or lost:
        print("\nREFUSING to write: this run is a REGRESSION.")
        print(f"  usable classes: existing {o_tot} -> this run {n_tot}")
        for c, (was, now) in sorted(lost.items()):
            print(f"    LOST {c}: {was} -> {now}")
        print("\nThe hand-picked VOCAB phrases are the known cause; the repairs live")
        print("in tools/htb_fill_gaps.py and tools/htb_fix_phrases.py. Re-run those")
        print("afterwards, or pass --force to overwrite deliberately.")
        raise SystemExit(2)
    print(f"\nregression guard: ok ({o_tot} -> {n_tot} usable classes, none lost)")
    if n_tot > o_tot:
        print("  note: new classes gained; downstream entity-trim may be needed")
        print("        (python tools/htb_fix_phrases.py)")

with open(REPORT, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)

usable = sum(1 for v in report.values() if v["usable"])
corrob = sum(1 for v in report.values() if v["can_corroborate"])
print(f"\nclasses with >=1 usable normative source: {usable}/{len(report)}")
print(f"classes where normative sources alone span >=2 orgs: {corrob}")
print(f"report -> {REPORT}")