"""T26 - extract_text() must not destroy markdown content that looks like tags.

MEASURED BUG: `extract_text()` decided to strip tags from the document's own
characters (`"<" in text[:2000] and ">" in text[:2000]`). In MARKDOWN a tag is
often the CONTENT -- the HTB XSS module is a table of literal
`<script>...</script>` payloads -- so stripping turned a verbatim quote into
`| ` |` and the gate reported FABRICATED for a correctly-quoted item.

A verifier that deletes the evidence it is checking is worse than no verifier,
so this is a gate defect. Two obligations follow, and both are asserted here:

  1. a quoted literal tag in a markdown source must now VERIFY
  2. an HTML page must still be tag-stripped (the fix must not have simply
     switched tag-stripping off, which would pass check 1 while breaking every
     rendered page)

Checked in BOTH directions. Also pins the pre-existing behaviour that the
striper removes tags but keeps script BODIES -- asserted as-is, so a future
change to it is a deliberate decision rather than a silent drift.
"""
import sys

sys.path.insert(0, ".")
from wks import pipeline
from wks.verify_quotes import find_quote

FAILED = []


def check(name, cond, detail=""):
    print(f"  {'PASS' if cond else 'FAIL'}  {name}"
          f"{('  -- ' + detail) if detail and not cond else ''}")
    if not cond:
        FAILED.append(name)


MD_XSS = (
    "| **XSS Payloads** | |\n"
    "| `<script>document.body.style.background = \"#141d2b\"</script>` | "
    "Change Background Color |\n"
    "| `<img src=\"\" onerror=alert(window.origin)>` | HTML-based XSS Payload |\n"
)
Q_XSS = ('| `<script>document.body.style.background = "#141d2b"</script>` | '
         'Change Background Color |')

HTML_PAGE = ("<html><body><nav>Skip to content</nav><p>Intro paragraph.</p>"
             "<script>window.__DATA__=1;</script><p>Second paragraph.</p>"
             "</body></html>")

print("T26.1 the bug: a literal-tag quote from MARKDOWN must verify")
md = pipeline.extract_text(MD_XSS.encode(), "text/markdown; charset=utf-8")
check("markdown text is not tag-stripped", "<script>" in md, f"got {md[:90]!r}")
check("XSS payload quote verifies", find_quote(md, Q_XSS), "quote rejected")
check("onerror payload survives", "onerror=alert" in md)

print("\nT26.2 plain-text content types are also left intact")
for ct in ("text/plain", "text/x-markdown", "application/x-txt"):
    t = pipeline.extract_text(MD_XSS.encode(), ct)
    check(f"ctype={ct} keeps literal tags", "<script>" in t)
    check(f"ctype={ct} quote verifies", find_quote(t, Q_XSS))

print("\nT26.3 REGRESSION: a real HTML page is STILL tag-stripped")
h = pipeline.extract_text(HTML_PAGE.encode(), "text/html; charset=utf-8")
check("html tags removed", "<p>" not in h and "<body>" not in h, f"got {h!r}")
check("nav chrome text retained", "Skip to content" in h)
check("prose retained", "Intro paragraph." in h)

print("\nT26.4 an unknown ctype with real HTML markup is still stripped")
h2 = pipeline.extract_text(HTML_PAGE.encode(), "")
check("unknown ctype still stripped", "<body>" not in h2)

print("\nT26.5 pin the pre-existing striper behaviour (tags gone, bodies kept)")
check("script BODY is retained by the striper (unchanged behaviour)",
      "window.__DATA__" in h,
      "if this now fails, the striper changed -- decide deliberately")

print("\nT26.6 entities still unescaped on both paths")
ent = pipeline.extract_text(b"<p>caf&eacute; &amp; more</p>", "text/html")
check("entities decoded in html", "caf" in ent.lower())

print("\n" + ("ALL T26 CHECKS PASSED" if not FAILED else f"{len(FAILED)} FAILED: {FAILED}"))
sys.exit(1 if FAILED else 0)