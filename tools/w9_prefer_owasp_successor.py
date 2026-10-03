"""Does the LIVE owasp.org 'latest' page hold the 3 quotes? If so it is a better
successor than raw.githubusercontent.com: same publisher (owasp.org), so the
rewrite does not swap a real publisher for a shared CDN host.
"""
import html
import re
import sys
import urllib.request

sys.path.insert(0, r"C:/Users/Administrator/.hermes/cyber")
from wks.verify_quotes import find_quote  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")

QUOTES = [
    ("sqli.signal.async_query_oast_signal",
     "Out-of-band: technique used to retrieve data using a different channel (e.g., "
     "make a HTTP connection to send the results to a web server)"),
    ("sqli.technique.boolean_character_extraction",
     "there is no actual transfer of data, but the tester is able to reconstruct "
     "the information by sending particular requests"),
    ("sqli.validation.single_variable_differential",
     "only one variable must vary while all the other remain constant, in order to "
     "precisely understand which parameters are vulnerable"),
]

CANDS = [
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/05-SQL_Injection",
    "https://raw.githubusercontent.com/OWASP/wstg/v4.2/document/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md",
]


def plain(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=35) as r:
        s = r.read().decode("utf-8", "ignore")
    s = re.sub(r"(?is)<(script|style|nav|footer)[^>]*>.*?</\1>", " ", s)
    s = TAG.sub(" ", s)
    s = html.unescape(html.unescape(s))
    return WS.sub(" ", s).replace("\u00a0", " ")


for url in CANDS:
    try:
        page = plain(url)
    except Exception as e:
        print("FAIL", url, type(e).__name__, e)
        continue
    print("=" * 78)
    print(url, "(%d chars)" % len(page))
    for key, q in QUOTES:
        print("   %-55s find_quote=%s" % (key, bool(find_quote(page, q))))