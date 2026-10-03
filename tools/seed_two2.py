"""Two INDEPENDENT seeds per brand-new class, sliced live from reachable pages.

MEASURED, and the obvious first choice was wrong twice:

  * `capec.mitre.org` was tried as the second registry. It RESOLVES and carries
    the right text ("An adversary exploits a weakness enabling them to elevate
    their privilege..."), but `publisher_org` maps it to `mitre.org` -- the same
    registrable org as `cwe.mitre.org`. Two hosts, one publisher, exactly the
    laundering the gate exists to prevent.
  * `owasp.org/www-community/...` returns 0 chars (that path is JS-rendered),
    while `cheatsheetseries.owasp.org` returns 5,319.
  * `nvd.nist.gov` returns a 1,578-byte JS shell; `csrc.nist.gov` returns 0.

So the second seed must come from an org that (a) is NOT mitre.org and (b)
actually serves static text. Probed and confirmed reachable with real prose:
owasp.org, ietf.org, docker.com, man7.org, first.org.

Every quote here is SLICED FROM THE LIVE PAGE and asserted with the gate's own
matcher, and `tools/src_packets.py` re-verifies at build time -- so a page that
moves or is rewritten drops the row instead of shipping a dead citation.
"""
import json
import re
import sys

sys.path.insert(0, "C:/Users/Administrator/.hermes/cyber/tools")
sys.path.insert(0, "C:/Users/Administrator/.hermes/cyber")
import ht_build_items as B  # noqa: E402
from wks import config, verify_quotes as V  # noqa: E402

# class -> [url1, url2] on DIFFERENT registrable orgs
SEEDS = {
    "windows_privesc_token": [
        "https://cwe.mitre.org/data/definitions/269.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/"
        "Access_Control_Cheat_Sheet.html",
    ],
    "windows_privesc_hijack": [
        "https://cwe.mitre.org/data/definitions/427.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/"
        "Access_Control_Cheat_Sheet.html",
    ],
    "windows_privesc_service": [
        "https://cwe.mitre.org/data/definitions/269.html",
        "https://cheatsheetseries.owasp.org/cheatsheets/"
        "Access_Control_Cheat_Sheet.html",
    ],
    "linux_privesc": [
        "https://cwe.mitre.org/data/definitions/269.html",
        "https://man7.org/linux/man-pages/man2/execve.2.html",
    ],
    "container_escape": [
        "https://cwe.mitre.org/data/definitions/250.html",
        "https://docs.docker.com/engine/security/",
    ],
}

SENT = re.compile(r"(?:Description|Likelihood)\s+(The [^.]+\.)")
SENT2 = re.compile(r"(?:EXECVE|execve)\([^)]*\)\s+[^.]{20,300}\.")
ALT = [
    re.compile(r"(?:Description|Likelihood)\s+(The [^.]+\.)"),
    re.compile(r"(?:An|A|The)\s+(?:adversary|attacker|process|program|container)"
               r"[^.]{30,320}\."),
    re.compile(r"\b(Container (?:daemon|privilege|isolation|runtime)[^.]{20,300}\.)"),
    re.compile(r"\b(The daemon[^.]{20,300}\.)"),
]


def slice_any(url):
    t = B.fetch_html(url)
    if not t:
        return None, "unreachable"
    for rx in ALT:
        for m in rx.finditer(t):
            q = m.group(1).strip()
            if len(q) < 60:
                continue
            if V.find_quote(t, q):
                return q, "ok"
    return None, "no verifiable sentence"


def main():
    out = {}
    for cls, urls in SEEDS.items():
        got, orgs = [], set()
        for u in urls:
            q, why = slice_any(u)
            if not q:
                print("  %-24s %-26s SKIP (%s)" % (cls, u.split("/")[2], why))
                continue
            org = config.publisher_org(u.split("/")[2])
            got.append({"url": u, "quote": q, "org": org})
            orgs.add(org)
            print("  %-24s %-26s %s" % (cls, org, q[:78]))
        ok = len(orgs) >= config.MIN_PUBLISHER_HOSTS
        print("  %-24s -> %d distinct org(s)  %s\n"
              % (cls, len(orgs), "OK" if ok else "SHORT"))
        if ok:
            out[cls] = got
    p = "C:/Users/Administrator/.hermes/cyber/tools/seeds_two_orgs.json"
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("wrote %s : %d class(es) with 2 independent seeds" % (p, len(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())