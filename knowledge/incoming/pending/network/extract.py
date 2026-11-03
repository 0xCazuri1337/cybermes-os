import json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")


def body_text(html):
    """Return article/main body text only, dropping nav/footer chrome."""
    m = re.search(r"(?is)<main\b.*?</main>", html)
    seg = m.group(0) if m else html
    seg = re.sub(r"(?is)<(script|style|noscript|svg|nav|form)\b.*?</\1>", " ", seg)
    seg = re.sub(r"(?is)<br\s*/?>", "\n", seg)
    seg = re.sub(r"(?is)</(p|div|li|tr|h[1-6]|td|pre|section|article)>", "\n", seg)
    seg = re.sub(r"(?is)<[^>]+>", " ", seg)
    for a, b in [("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'),
                 ("&#39;", "'"), ("&nbsp;", " "), ("&#8217;", "'"), ("&mdash;", "-"),
                 ("&ndash;", "-"), ("&rsquo;", "'"), ("&ldquo;", '"'), ("&rdquo;", '"')]:
        seg = seg.replace(a, b)
    seg = re.sub(r"[ \t\xa0]+", " ", seg)
    seg = re.sub(r"\n\s*\n+", "\n", seg)
    return seg.strip()


def sentences(txt):
    out = []
    for line in txt.split("\n"):
        line = line.strip()
        if len(line) < 40:
            continue
        for s in re.split(r"(?<=[.!?])\s+(?=[A-Z(])", line):
            s = s.strip()
            if 60 <= len(s) <= 400:
                out.append(s)
    return out


def grep(url_or_html, needles, limit=6):
    """Fetch (or accept raw html) and print sentences containing any needle."""
    from fetch import fetch
    if url_or_html.lstrip().startswith("<"):
        html = url_or_html
    else:
        c, html = fetch(url_or_html)
        if c != "200":
            return [f"!! STATUS {c} for {url_or_html}"]
    t = body_text(html)
    hits = []
    for s in sentences(t):
        if any(n.lower() in s.lower() for n in needles):
            hits.append(s)
    return hits[:limit]