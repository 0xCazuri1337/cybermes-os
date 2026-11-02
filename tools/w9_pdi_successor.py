"""The 404 projectdiscovery.io citation: does the trimmed-path successor hold
the quote? And is the item still promotable on its OTHER sources alone?

An unresolvable dead citation must not be silently deleted (that discards real
knowledge) and must not be silently kept as if it verified. The honest outcome
depends on whether the surviving sources still carry the item.
"""
import html
import re
import sys
import urllib.request

sys.path.insert(0, r"C:/Users/Administrator/.hermes/cyber")
from wks.verify_quotes import find_quote  # noqa: E402
from wks import config  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
SUCC = "https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass"
QUOTES = [
    "We insert a DigestValue of the modified assertion inside the samlp:extensions "
    "element. The XPath selector will extract this smuggled DigestValue instead of "
    "the one from the SignedInfo block.",
]
OTHER = [("projectdiscovery.io", "https://projectdiscovery.io/blog/nuclei-templates-november-2025"),
         ("httpwg.org", "https://httpwg.org/specs/rfc9530.html")]


def plain(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=30) as r:
        s = r.read().decode("utf-8", "ignore")
    s = re.sub(r"(?is)<(script|style|nav|footer)[^>]*>.*?</\1>", " ", s)
    s = html.unescape(html.unescape(re.sub(r"<[^>]+>", " ", s)))
    return re.sub(r"\s+", " ", s).replace("\u00a0", " ")


succ = plain(SUCC)
print("successor page:", SUCC, "(%d chars)" % len(succ))
for q in QUOTES:
    print("  quoted span present on successor:", bool(find_quote(succ, q)))
print("  successor mentions DigestValue:", "DigestValue" in succ)
print("  successor mentions SignedInfo:", "SignedInfo" in succ)
print("  successor mentions samlp:extensions:", "samlp:extensions" in succ)

print("\n--- the item's OTHER citations (what would remain) ---")
for host, url in OTHER:
    try:
        p = plain(url)
        print(" ", host, len(p), "chars")
    except Exception as e:
        print(" ", host, "FETCH_FAIL", type(e).__name__)

print("\n--- publisher arithmetic after losing projectdiscovery.io ---")
alive = [h for h, _ in OTHER if h != "projectdiscovery.io"]
orgs = {config.publisher_org(h) for h in alive}
print("  surviving hosts:", alive, "-> distinct orgs:", sorted(orgs))
print("  would still satisfy >=2 publisher orgs:", len(orgs) >= 2)