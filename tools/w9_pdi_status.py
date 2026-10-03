"""Is the projectdiscovery.io citation dead, moved, or just unsupported by the
WSTG-only resolver? Fetch the URL, the blog index, and try a couple of plausible
successor shapes, then decide on evidence.
"""
import html
import re
import sys
import urllib.error
import urllib.request

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
BAD = "https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass-cve-2024-45409"
QUOTE = ("We insert a DigestValue of the modified assertion inside the samlp:extensions "
         "element. The XPath selector will extract this smuggled DigestValue instead of "
         "the one from the SignedInfo block.")

CANDS = [
    BAD,
    "https://projectdiscovery.io/blog",
    "https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass",
    "https://projectdiscovery.io/blog/cve-2024-45409",
]


def get(url):
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


for u in CANDS:
    st, body = get(u)
    print(" ", st, u)
    if st == 200 and "blog" in u and u.rstrip("/").endswith("blog"):
        # look for any saml / gitlab / 45409 link in the index
        hits = sorted({h for h in re.findall(r'href="([^"]+)"', body)
                       if any(k in h.lower() for k in ("saml", "gitlab", "45409"))})
        print("      index hits:", hits[:10])

st, body = get(BAD)
print("\ncited url status:", st)
if st == 200:
    plain = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", body)))
    print("quote present on cited page:", QUOTE[:60] in plain)
    print("contains 'DigestValue':", "DigestValue" in plain)
    print("page length:", len(plain))