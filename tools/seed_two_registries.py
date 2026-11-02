"""Give each BRAND-NEW class two seeds from two different registries.

MEASURED: the 5 privilege-escalation classes were registered today and have no
promoted corpus item, so `tools/twopart.py` finds nothing to recycle and the
single seeded CWE page supplies exactly one publisher org. Every privesc item
was therefore refused with "only 1 real publisher org(s): ['seeded']" -- which is
the gate working correctly: one normative source cannot corroborate itself.

The fix is a SECOND INDEPENDENT registry, not a threshold change. CAPEC and NVD
both catalogue the same weakness classes on different registrable domains, so
`cwe.mitre.org` + `capec.mitre.org` is genuinely two publishers citing the same
mechanism -- the same arrangement the corpus already uses elsewhere
(`cwe.mitre.org` beside `attack.mitre.org` counts as ONE org because both are
mitre.org; CAPEC is also mitre.org, so the second domain must NOT be mitre).

Every quote is SLICED FROM THE LIVE PAGE and asserted with the gate's own matcher
before being written here. `tools/src_packets.py` re-verifies at build time, so a
page that moves drops the row instead of shipping a dead citation.
"""
import json
import re
import sys
import urllib.request

sys.path.insert(0, "C:/Users/Administrator/.hermes/cyber/tools")
import ht_build_items as B  # noqa: E402
from wks import config, verify_quotes as V  # noqa: E402

# (class, seed url, is capec) -- one CWE + one CAPEC per class.
CANDIDATES = [
    ("windows_privesc_token",
     "https://cwe.mitre.org/data/definitions/269.html",
     "https://capec.mitre.org/data/definitions/233.html"),
    ("windows_privesc_hijack",
     "https://cwe.mitre.org/data/definitions/427.html",
     "https://capec.mitre.org/data/definitions/88.html"),
    ("windows_privesc_service",
     "https://cwe.mitre.org/data/definitions/269.html",
     "https://capec.mitre.org/data/definitions/233.html"),
    ("linux_privesc",
     "https://cwe.mitre.org/data/definitions/269.html",
     "https://capec.mitre.org/data/definitions/233.html"),
    ("container_escape",
     "https://cwe.mitre.org/data/definitions/250.html",
     "https://capec.mitre.org/data/definitions/233.html"),
]

PATTERN = re.compile(r"(?:Description|Likelihood)\s+(The [^.]+\.)")


def slice_desc(url):
    t = B.fetch_html(url)
    if not t:
        return None, "unreachable"
    m = PATTERN.search(t)
    if not m:
        return None, "no Description sentence"
    q = m.group(1).strip()
    if not V.find_quote(t, q):
        return None, "does not verify"
    return q, "ok"


def main():
    out = {}
    for cls, cwe_url, capec_url in CANDIDATES:
        seeds = []
        for url in (cwe_url, capec_url):
            q, why = slice_desc(url)
            if q:
                host = url.split("/")[2]
                seeds.append({"url": url, "quote": q,
                              "org": config.publisher_org(host)})
                print("  %-24s %-34s %s" % (cls, host, q[:70]))
            else:
                print("  %-24s %-34s SKIP (%s)" % (cls, url.split('/')[2], why))
        orgs = {s["org"] for s in seeds}
        status = "OK" if len(orgs) >= config.MIN_PUBLISHER_HOSTS else "SHORT"
        print("  %-24s -> %d distinct org(s)  %s" % (cls, len(orgs), status))
        if len(orgs) >= config.MIN_PUBLISHER_HOSTS:
            out[cls] = seeds
    p = "C:/Users/Administrator/.hermes/cyber/tools/seeds_privesc2.json"
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("\nwrote %s with %d fully-seeded class(es)" % (p, len(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())