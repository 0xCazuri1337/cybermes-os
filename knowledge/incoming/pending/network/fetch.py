import hashlib, os, subprocess, sys, json

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cache")
os.makedirs(CACHE, exist_ok=True)


def fetch(url, force=False):
    """GET url with browser UA, follow redirects. Returns (status, text)."""
    key = hashlib.sha256(url.encode()).hexdigest()[:16]
    body = os.path.join(CACHE, key + ".html")
    meta = os.path.join(CACHE, key + ".meta")
    if not force and os.path.exists(body) and os.path.exists(meta):
        m = json.load(open(meta, encoding="utf-8"))
        return m["status"], open(body, encoding="utf-8", errors="replace").read()
    p = subprocess.run(
        ["curl", "-sS", "-L", "-A", UA,
         "--max-time", "60", "--compressed",
         "-w", "%{http_code}\t%{url_effective}",
         "-o", body, url],
        capture_output=True, text=True, errors="replace")
    out = (p.stdout or "").strip().split("\n")[-1]
    code = out.split("\t")[0] if "\t" in out else "000"
    eff = out.split("\t")[1] if "\t" in out else url
    txt = ""
    if os.path.exists(body):
        txt = open(body, encoding="utf-8", errors="replace").read()
    json.dump({"status": code, "effective": eff, "url": url, "err": p.stderr.strip()},
              open(meta, "w", encoding="utf-8"))
    return code, txt


def text_of(html):
    """Very light HTML -> text, keeps wording, drops markup noise."""
    import re
    h = re.sub(r"(?is)<(script|style|noscript|svg)\b.*?</\1>", " ", html)
    h = re.sub(r"(?is)<br\s*/?>", "\n", h)
    h = re.sub(r"(?is)</(p|div|li|tr|h[1-6]|section|article)>", "\n", h)
    h = re.sub(r"(?is)<[^>]+>", " ", h)
    h = h.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    h = h.replace("&quot;", '"').replace("&#39;", "'").replace("&nbsp;", " ")
    h = re.sub(r"[ \t\xa0]+", " ", h)
    h = re.sub(r"\n\s*\n+", "\n", h)
    return h.strip()


if __name__ == "__main__":
    for u in sys.argv[1:]:
        c, h = fetch(u)
        print(c, len(h), u)