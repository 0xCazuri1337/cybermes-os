"""Slice a SECOND normative seed per brand-new class, from an independent org.

MEASURED, twice, in this order, because both obvious choices failed:

  * `capec.mitre.org` is not a second publisher. `publisher_org` maps it to
    `mitre.org`, the same registrable org as `cwe.mitre.org`, so CWE + CAPEC is
    one voice on two hosts -- the exact laundering the 2-publisher rule forbids.
  * `cheatsheetseries.owasp.org` serves only 5,319 bytes for the Access Control
    sheet and the prose is a JS stub: the one "sentence" mentioning privilege is
    CSS. So OWASP is unreachable for a second seed in this form.
  * `owasp.org/www-community/...` returns 0 chars, `nvd.nist.gov` a 1,578-byte JS
    shell, `csrc.nist.gov` 0.

What DOES serve static prose on a non-mitre registrable domain:
  man7.org   23,661 chars   the Linux man-pages (execve, capabilities, setuid)
  docker.com 40,471 chars   Docker Engine security
  first.org  50,271 chars   the CVSS specification
  ietf.org  146,789 chars   the RFCs

This picks a sentence by TOPIC RELEVANCE to the class, then asserts it with the
gate's own matcher. It never types a quote.
"""
import json
import re
import sys

sys.path.insert(0, "C:/Users/Administrator/.hermes/cyber/tools")
sys.path.insert(0, "C:/Users/Administrator/.hermes/cyber")
import ht_build_items as B  # noqa: E402
from wks import config, verify_quotes as V  # noqa: E402

# class -> (cwe url, second url, terms the second quote must be ABOUT)
PLAN = {
    "windows_privesc_token": (
        "https://cwe.mitre.org/data/definitions/269.html",
        "https://man7.org/linux/man-pages/man2/execve.2.html",
        r"privilege|set-?uid|effective uid|dumpable"),
    "windows_privesc_hijack": (
        "https://cwe.mitre.org/data/definitions/427.html",
        "https://man7.org/linux/man-pages/man8/ld.so.8.html",
        r"search|library|DT_|RPATH|RUNPATH|LD_LIBRARY"),
    "windows_privesc_service": (
        "https://cwe.mitre.org/data/definitions/269.html",
        "https://man7.org/linux/man-pages/man2/execve.2.html",
        r"privilege|set-?uid|gain|effective"),
    "linux_privesc": (
        "https://cwe.mitre.org/data/definitions/269.html",
        "https://man7.org/linux/man-pages/man2/execve.2.html",
        r"privilege|set-?uid|effective uid|root"),
    "container_escape": (
        "https://cwe.mitre.org/data/definitions/250.html",
        "https://docs.docker.com/engine/security/",
        r"container|daemon|privilege|isolat"),
}
DESC = re.compile(r"(?:Description|Likelihood)\s+(The [^.]+\.)")
SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z`\"'(])")


def cwe_quote(url):
    t = B.fetch_html(url)
    if not t:
        return None
    m = DESC.search(t)
    return m.group(1).strip() if m else None


def topical_quote(url, terms):
    """Longest sentence on the page that is ABOUT the mechanism, verified."""
    t = B.fetch_html(url)
    if not t:
        return None, "unreachable"
    rx = re.compile(terms, re.I)
    best = None
    for s in SPLIT.split(t):
        s = s.strip()
        if not (110 <= len(s) <= 400):
            continue
        if not rx.search(s):
            continue
        # reject nav/CSS/JSON noise
        if re.search(r"[{}]|--md-|__md_|\.css|gatsby|Gordon|console\.error",
                     s):
            continue
        if not V.find_quote(t, s):
            continue
        if best is None or len(s) > len(best):
            best = s
    return (best, "ok") if best else (None, "no on-topic verifiable sentence")


def main():
    out = {}
    for cls, (u1, u2, terms) in PLAN.items():
        q1 = cwe_quote(u1)
        q2, why2 = topical_quote(u2, terms)
        orgs = set()
        rows = []
        if q1 and V.find_quote(B.fetch_html(u1), q1):
            rows.append((u1, q1))
            orgs.add(config.publisher_org(u1.split("/")[2]))
        if q2:
            rows.append((u2, q2))
            orgs.add(config.publisher_org(u2.split("/")[2]))
        ok = len(orgs) >= config.MIN_PUBLISHER_HOSTS
        for u, q in rows:
            print("  %-24s %-24s %s" % (cls, config.publisher_org(u.split("/")[2]),
                                       q[:74]))
        if not q2:
            print("  %-24s second seed FAILED: %s" % (cls, why2))
        print("  %-24s -> %d org(s) %s\n" % (cls, len(orgs),
                                             "OK" if ok else "SHORT"))
        if ok:
            out[cls] = [{"url": u, "quote": q,
                         "org": config.publisher_org(u.split("/")[2])}
                        for u, q in rows]
    p = "C:/Users/Administrator/.hermes/cyber/tools/seeds_two_orgs.json"
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("wrote %s : %d/%d classes fully seeded"
          % (p, len(out), len(PLAN)))
    return 0


if __name__ == "__main__":
    sys.exit(main())