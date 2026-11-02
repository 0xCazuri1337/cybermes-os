"""Prove the NVD API is citable, and that the HTML page is NOT -- before I build on it.

MEASURED: `https://nvd.nist.gov/vuln/detail/CVE-2007-2447` returns HTTP 200 with
2,453 bytes that de-tag to 1,618 characters of which every line is a `<script>`
loader. `pipeline._looks_like_shell()` says True and there is no CVE prose on the
page at all. A 200 here is worthless -- quoting it would put an invented
sentence in the corpus, which is exactly the fabrication this gate exists to
refuse.

The REST API on the same host serves real prose:
    services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2007-2447

This test asserts BOTH directions before anything is built on it:
  * the API returns a quotable description,
  * the HTML page does NOT contain it (so the claim cannot be laundered from a
    page that lacks it),
  * the API host is an INDEPENDENT publisher org from hackthebox.com.
"""
import json
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")
from wks import config, pipeline

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}
API_UA = dict(UA, Accept="application/json")

CVE = "CVE-2007-2447"
API = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={CVE}"
PAGE = f"https://nvd.nist.gov/vuln/detail/{CVE}"

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}"
          f"{('  -- ' + detail) if detail and not cond else ''}")
    if not cond:
        FAILED.append(name)


print("T27.1 the NVD API returns quotable prose")
r = urllib.request.urlopen(urllib.request.Request(API, headers=API_UA),
                           timeout=40, context=ctx)
d = json.loads(r.read().decode())
cve = d["vulnerabilities"][0]["cve"]
desc = [x["value"] for x in cve["descriptions"] if x["lang"] == "en"][0]
check("API 200", r.status == 200, str(r.status))
check("description is substantial", len(desc) > 80, f"{len(desc)} chars")
check("names the product (Samba)", "Samba" in desc or "smbd" in desc)
check("names the mechanism (shell metacharacters)",
      "metacharacter" in desc.lower() or "command" in desc.lower())
print(f"      -> {desc[:150]}...")

print("\nT27.2 the HTML page is a SHELL and cannot carry this quote")
r2 = urllib.request.urlopen(urllib.request.Request(PAGE, headers=UA), timeout=40,
                            context=ctx)
b2 = r2.read()
t2 = pipeline.extract_text(b2, r2.headers.get("Content-Type", ""))
check("HTML page 200", r2.status == 200)
check("HTML page looks like a shell", pipeline._looks_like_shell(t2),
      "if this is now False the shell test changed -- re-read it before trusting")
check("HTML page does NOT contain the description",
      desc[:60] not in t2,
      "page now carries the text -- prefer the page, it is more readable")
print(f"      -> de-tagged text is {len(t2)} chars, "
      f"{t2.lower().count('<script')} script tags")

print("\nT27.3 independence: NVD must not collapse into hackthebox.com")
nvd = config.publisher_org("services.nvd.nist.gov")
htb = config.publisher_org("hackthebox.com")
check(f"nvd org ({nvd}) != htb org ({htb})", nvd != htb)
check("both are real orgs", bool(nvd) and bool(htb))
check("collapsing them would still be 2", len({nvd, htb}) >= config.MIN_PUBLISHER_HOSTS)

print("\n" + ("ALL T27 CHECKS PASSED" if not FAILED else f"{len(FAILED)} FAILED: {FAILED}"))
sys.exit(1 if FAILED else 0)