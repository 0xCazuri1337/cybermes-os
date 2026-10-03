"""Why does the gate say FABRICATED when an identical fetch succeeds?

The verifier reports NOT_FOUND for
  raw.githubusercontent.com/.../27.%20Cross-Site%20Scripting%20%28XSS%29/....md
with quote `| `<script>document.body.style.background = "#141d2b"</script>` | ...`

while urllib with the SAME url and the SAME matcher returns a match. So the
difference is in HOW the page is obtained or how the matcher is invoked. This
compares the two paths byte for byte: raw body, the gate's own normalisation,
and find_quote on the identical string.
"""
import re
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")
from wks.verify_quotes import find_quote

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}

URL = ("https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/"
       "main/Write-ups/Academy/05.%20Web%20Exploitation/27.%20Cross-Site%20Scripting%20"
       "%28XSS%29/Cross-Site%20Scripting%20%28XSS%29.md")
QUOTE = ('| `<script>document.body.style.background = "#141d2b"</script>` | '
         'Change Background Color |\n| `<script>document.body.background = '
         '"https://www.hackthe`')


def fetch(u, headers, label):
    try:
        r = urllib.request.urlopen(urllib.request.Request(u, headers=headers),
                                   timeout=30, context=ctx)
        return r.status, r.read().decode("utf-8", "replace"), None
    except Exception as e:
        return None, "", f"{type(e).__name__}: {str(e)[:70]}"


print("1) with a browser-like User-Agent")
st, body, err = fetch(URL, UA, "browser")
print(f"   status={st} len={len(body)} err={err}")
print(f"   find_quote(body)   = {find_quote(body, QUOTE)}")
print(f"   plain substring    = {QUOTE in body}")

if body:
    i = body.find("<script>document.body.style.background")
    print(f"\n2) context around the quote in the raw body:")
    print("   ", repr(body[max(0, i - 90):i + 150]))

    # the difference may be \r\n vs \n
    print(f"\n3) line-ending check")
    print(f"   body has CRLF: {chr(13)+chr(10) in body}")
    print(f"   quote has CRLF: {chr(13)+chr(10) in QUOTE}")
    print(f"   find_quote on CR-normalised body = "
          f"{find_quote(body.replace(chr(13)+chr(10), chr(10)), QUOTE)}")

print("\n4) with NO User-Agent at all (what a bare fetch might do)")
st2, body2, err2 = fetch(URL, {}, "bare")
print(f"   status={st2} len={len(body2)} err={err2}")
if body2:
    print(f"   find_quote = {find_quote(body2, QUOTE)}")

print("\n5) find_quote normalisation ladder on the SAME body")
if body:
    for name, variant in [
        ("raw", body),
        ("strip\\r", body.replace("\r", "")),
        ("collapse ws", re.sub(r"\s+", " ", body)),
        ("collapse+strip", re.sub(r"\s+", " ", body.replace("\r", ""))),
    ]:
        print(f"   {name:<16} -> {find_quote(variant, QUOTE)}")