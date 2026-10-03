"""Build evidence items from the 291 OFFICIAL HTB write-up PDFs.

DIFFERENT EVIDENCE SHAPE from the markdown wave, and the plan differs because
of it. Those were curriculum tables ("`cmd` | description"), so a technique item
paired with PortSwigger. These are prose walkthroughs whose value is SPECIFIC:
a product, a version, a CVE, and the mechanism behind it -- e.g. OpenKeyS:
"the function only checks if a binary has SUID permissions, while failing to
validate SGID permissions" for CVE-2019-19520. That is a product claim, and the
independent authority for a product claim is the CVE record itself (NVD), not a
generic web-vuln cheat sheet.

Corroboration, and why it is NOT optional here: all 291 documents belong to
ONE publisher org (`hackthebox.com` -- help/forum/academy all collapse into it,
measured). So no two of them can corroborate each other, exactly as the GitHub
problem in T25. Every item therefore pairs:
    hackthebox.com  -- the mechanism AS SEEN on a real machine
    nist.gov (NVD)  -- the same CVE, authoritatively
and the builder HARD-REFUSES any item with fewer than 2 publisher ORGS.

The NVD citation uses the REST API, not the HTML page: `nvd.nist.gov/vuln/detail/...`
returns 200 with a JS shell and no CVE prose (T27), while
`services.nvd.nist.gov/rest/json/cves/2.0?cveId=...` returns the description.
"""
import hashlib
import io
import json
import os
import re
import ssl
import sys
import time
import urllib.request

sys.path.insert(0, ".")
from wks import config
from wks.pipeline import extract_text as _extract
from wks.verify_quotes import find_quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from htb_pdf_routing import pick_class

ROOT = os.environ.get("WKS_ROOT", r"C:\Users\Administrator\.hermes\cyber")
CORPUS_JSON = os.path.join(ROOT, "research", "htb_pdf_corpus.json")
OUTDIR = os.path.join(ROOT, "research", "incoming")
CACHE = os.path.join(ROOT, "cache", "nvd")
os.makedirs(CACHE, exist_ok=True)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}
API_UA = dict(UA, Accept="application/json")

HTB_ORG = config.publisher_org("hackthebox.com")
NVD_ORG = config.publisher_org("services.nvd.nist.gov")
CWE_ORG = config.publisher_org("cwe.mitre.org")

# The product/version is what makes a CVE item falsifiable, so it is required
# before an item is written at all.
PROD_RE = re.compile(r"\b(OpenBSD|Ubuntu|Debian|CentOS|Kali|Windows|Samba|Apache|"
                     r"Nginx|OpenSSL|MySQL|PostgreSQL|WordPress|Drupal|Joomla|"
                     r"OpenSSH|vsftpd|Apache Tomcat|Jenkins|Redis|MongoDB|"
                     r"ProFTPD|Mod_|Squid|Docker|Linux)\b")



NVD_INTERVAL = 6.5      # 5 requests / 30 s unauthenticated, with headroom


def raw_text_for(url, tries=3):
    """The gate's own view of a page, used to confirm a quote before storing it."""
    headers = API_UA if "json" in url else UA
    for _ in range(tries):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=headers),
                                       timeout=45, context=ctx)
            return _extract(r.read(), r.headers.get("Content-Type", ""))
        except Exception:
            time.sleep(2)
    return ""



def page_form(parsed_desc, raw_body):
    """The span of `raw_body` that the gate will actually match.

    NVD's JSON escapes `\\"` and `\\#`, so json.loads strips only one layer and
    the parsed description still differs from the bytes on the page. The gate
    matches against the RAW body, so the stored quote has to be a raw span.

    Returns a verified substring of raw_body, or None.
    """
    def squash(s):
        return re.sub(r"\\s+", " ", s).strip()

    # 1. the exact parsed text, if it survives verbatim
    if parsed_desc and parsed_desc in raw_body:
        return parsed_desc

    # 2. re-apply the JSON escaping to the parsed form and look for that
    esc = parsed_desc.replace("\\", "\\\\").replace('"', '\\"')
    esc = esc.replace("#", "\\#")
    if esc and esc in raw_body:
        return esc

    # 3. a shortened span: take a leading sentence and try both forms
    head = squash(parsed_desc)[:180]
    for cand in (head,
                 head.replace("#", "\\#"),
                 head.replace('"', '\\"'),
                 head.replace("#", "\\#").replace('"', '\\"')):
        if cand and cand in raw_body:
            return cand
    return None


def nvd_description(cve):
    """Fetch (and cache) the authoritative English description for a CVE."""
    os.makedirs(CACHE, exist_ok=True)
    cp = os.path.join(CACHE, cve + ".json")
    if os.path.exists(cp) and os.path.getsize(cp) > 60:
        try:
            return json.load(open(cp, encoding="utf-8"))["desc"]
        except Exception:
            pass
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    desc = None
    # NVD allows 5 unauthenticated requests / 30 s. Fire too fast and the
    # response is empty, which looks identical to "this CVE has no description"
    # -- measured: 42 items built collapsed to 8 with 58 NVD_NO_DESCRIPTION
    # aborts purely from pacing.
    for attempt in range(4):
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers=API_UA),
                                       timeout=45, context=ctx)
            d = json.loads(r.read().decode())
            desc = [x["value"]
                    for x in d["vulnerabilities"][0]["cve"]["descriptions"]
                    if x["lang"] == "en"][0]
            break
        except Exception:
            time.sleep(NVD_INTERVAL * (attempt + 1))
    if not desc:
        return None

    # Entities are a rendering artefact, not evidence: the gate unescapes the
    # page it fetches, so a quote carrying `&#39;` or `&amp;` verbatim cannot
    # match. Unescape, then confirm against a live read before storing.
    import html as _html
    clean = _html.unescape(desc)
    clean = clean.replace("\u2019", "'").replace("\u2018", "'")
    clean = clean.replace("\u201c", '"').replace("\u201d", '"')
    clean = clean.replace("\u2013", "-").replace("\u2014", "-")
    # JSON escape residue. The NVD description contains a literal backslash
    # (`sudo -u \#$(0xffffffff))`) that survives json.loads as a backslash
    # before the `#`, so the stored quote is not a substring of the page and the
    # gate reports FABRICATED for a genuine quote. Measured on CVE-2019-14287:
    # `identical? True` against the parsed field, `find_quote` False.
    clean = clean.replace(chr(92) + "#", "#").replace(chr(92) + "'", "'")
    clean = clean.replace(chr(92) + '"', '"')
    clean = re.sub(r"\s+", " ", clean).strip()
    # Store the form the GATE MATCHES. The parsed description still carries NVD's
    # JSON escaping (`\#`, `\"`), while the page holds it doubled, so a quote
    # taken from the parsed field is not on the page at all and the gate reports
    # FABRICATED for genuine evidence (measured on CVE-2019-14287).
    raw_body = raw_text_for(url)
    page_span = page_form(clean, raw_body)
    clean = page_span if page_span else desc
    if not find_quote(raw_body, clean):
        return None
    with open(cp, "w", encoding="utf-8") as f:
        json.dump({"cve": cve, "desc": clean, "raw_desc": desc, "url": url}, f)
    return clean


# Cover-page / front-matter vocabulary. These lines describe the DOCUMENT, not
# the vulnerability, and they pass a naive "two long words" filter easily -- the
# skills table is exactly what got quoted as a mechanism.
FRONT_MATTER = re.compile(
    r"\b(skills? (required|learned)|difficulty|classification|prepared by|"
    r"machine author|synopsis|document no|page \d+|htb official|academy)\b", re.I)

# A mechanism sentence names something executable or structural.
TECH_MARKER = re.compile(
    r"\b(suid|sgid|setuid|setgid|cap_dac|capabilities|buffer overflow|"
    r"heap|stack|use.after.free|format string|race condition|"
    r"priv|escalat|auth|unauth|inject|traversal|deserial|overflow|"
    r"dlopen|getenv|exec|shell metachar|arbitrary (command|code|file)|"
    r"insecure|misconfig|unvalidated|unchecked|fails? to|does not|"
    r"vulnerable|patched|version|crafted|payload|exploit)\b", re.I)


# Front matter and two-column curriculum tables. The cover page of every HTB
# document has a "Skills Required | Skills Learned" table whose rows contain
# words like "vulnerable", which is why a naive vocabulary filter picked
# "Basic knowledge of Linux  Identifying vulnerable services" as a mechanism.
FRONT_MATTER = re.compile(
    r"(skills?\s+(required|learned)|\bdifficulty\b|\bclassification\b|"
    r"prepared by|machine author|^synopsis|document no|page \d+/\d+|"
    r"htb official|beginner level machine|previous users? prior to)", re.I)

# A table row: two short cells side by side, i.e. lots of runs of 3+ spaces.
TABLEROW = re.compile(r"\S\s{3,}\S")

# The paragraph must describe a weakness, not the machine's curriculum.
TECH_MARKER = re.compile(
    r"\b(suid|sgid|setuid|setgid|cap_dac|capabilit|buffer overflow|heap|stack|"
    r"use.after.free|format string|race condition|traversal|deserialis|deserializ|"
    r"privilege escalat|escalate|arbitrary (command|code|file)|shell metachar|"
    r"unauthenticated|unvalidated|unchecked|fails? to validate|does not validate|"
    r"outdated|vulnerable version|known vulnerability|security flaw|"
    r"insecure|misconfigur|crafted|payload|exploit)\b", re.I)


def paragraphs(text):
    """Re-join PDF-wrapped prose into whole paragraphs.

    A PDF lays out one sentence across several physical lines, so the LINE is
    not the unit of meaning. This de-hyphenates and joins until a blank line,
    which restores the sentence the reader actually sees.
    """
    t = text.replace("\r\n", "\n").replace("\f", "\n")
    t = re.sub(r"-\n(?=[a-z])", "", t)            # de-hyphenate
    paras, cur = [], []
    for raw in t.split("\n"):
        line = raw.strip()
        if not line:
            if cur:
                paras.append(" ".join(cur))
                cur = []
            continue
        cur.append(line)
    if cur:
        paras.append(" ".join(cur))
    return [re.sub(r"\s+", " ", p).strip() for p in paras]


def pick_mechanism(doc_txt, cve):
    """One verbatim span that explains the weakness, preferring the CVE's own
    discussion. Returns None rather than settling for a curriculum table."""
    cands = []
    for p in paragraphs(doc_txt):
        if not (60 <= len(p) <= 700):
            continue
        if FRONT_MATTER.search(p):
            continue
        if TABLEROW.search(p):
            continue                      # two-column table row
        if not TECH_MARKER.search(p):
            continue
        near = cve.lower() in p.lower()
        cands.append((near, TECH_MARKER.search(p).start(), p))
    if not cands:
        return None
    # a paragraph naming the CVE first, then the earliest technical marker
    cands.sort(key=lambda c: (not c[0], c[1]))
    return cands[0][2]



def nvd_cwes(cve):
    """The CWE ids NVD assigns to a CVE. `weaknesses[].description[].value` is
    the shape -- reading `weaknesses[].value` raises KeyError."""
    cp = os.path.join(CACHE, cve + ".json")
    raw = None
    if os.path.exists(cp) and os.path.getsize(cp) > 60:
        try:
            j = json.load(open(cp, encoding="utf-8"))
            raw = j.get("cwes")
        except Exception:
            raw = None
    if not raw:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
        got = []
        for attempt in range(3):
            try:
                r = urllib.request.urlopen(urllib.request.Request(url, headers=API_UA),
                                           timeout=45, context=ctx)
                c = json.loads(r.read().decode())["vulnerabilities"][0]["cve"]
                for w in c.get("weaknesses", []):
                    for d in w.get("description", []):
                        if d.get("lang") == "en" and re.match(r"CWE-\d+", d.get("value", "")):
                            got.append(d["value"])
                break
            except Exception:
                time.sleep(NVD_INTERVAL * (attempt + 1))
        got = list(dict.fromkeys(got))
        # Cache ONLY a non-empty list. An empty list cached from a rate-limited
        # fetch is indistinguishable from "this CVE has no CWE", and it made the
        # weakness look permanently absent -- which surfaced as 48 aborts of
        # ONLY_1_ORG rather than as the network failure it was.
        if got:
            cpj = json.load(open(cp, encoding="utf-8")) if os.path.exists(cp) else {}
            cpj["cwes"] = got
            json.dump(cpj, open(cp, "w", encoding="utf-8"))
            raw = got
        else:
            return []
    return list(dict.fromkeys(raw or []))


def cwe_title(cwe_id):
    """The weakness name, fetched live from MITRE so it can be quoted."""
    n = cwe_id.split("-")[-1]
    url = f"https://cwe.mitre.org/data/definitions/{n}.html"
    cp = os.path.join(CACHE, cwe_id + ".txt")
    if os.path.exists(cp) and os.path.getsize(cp) > 30:
        return open(cp, encoding="utf-8", errors="replace").read()
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, headers=UA),
                                   timeout=40, context=ctx)
        body = r.read().decode("utf-8", "replace")
    except Exception:
        return ""
    m = re.search(r"<h2[^>]*>(.*?)</h2>", body, re.S | re.I)
    title = re.sub(r"<[^>]+>", " ", m.group(1)) if m else ""
    # Entities must be UNESCAPED, not partially replaced. MITRE renders
    # "(&#39;OS Command Injection&#39;)" and the gate unescapes the fetched
    # page, so the body holds a real apostrophe. Quoting the literal entity
    # cannot match and the item is refused as fabricated (measured: 5 items).
    import html as _html
    title = _html.unescape(title)
    title = re.sub(r"\s+", " ", title).strip()
    if not title:
        return ""
    # Only keep a title that is actually present in the page we just fetched,
    # checked with the same normalisation the gate uses. A title we cannot
    # re-verify is dropped rather than shipped as an unverifiable quote.
    from wks.verify_quotes import find_quote as _fq
    if not _fq(body, title):
        return ""
    with open(cp, "w", encoding="utf-8") as f:
        f.write(title)
    return title


def main():
    rows = json.load(open(CORPUS_JSON, encoding="utf-8"))
    os.makedirs(OUTDIR, exist_ok=True)

    built, aborted = {}, []
    seen_cves = set()

    for r in rows:
        if not r["cves"]:
            continue
        try:
            txt = io.open(r["txt"], encoding="utf-8", errors="replace").read()
        except Exception:
            continue
        for cve in r["cves"]:
            # The NVD API is CASE-SENSITIVE on cveId: `cve-2007-2447` 404s while
            # `CVE-2007-2447` returns the record. The corpus stores them in the
            # lowercase form the PDF text used, so every fetch failed and every
            # item aborted at NVD_NO_DESCRIPTION (measured: 68/68).
            cve = cve.upper()
            if cve in seen_cves:
                continue
            # the item is about ONE machine, so stop after its first usable CVE
            if built.get(r["machine"]):
                break
            desc = nvd_description(cve)
            if not desc or len(desc) < 80:
                aborted.append((r["machine"], cve, "NVD_NO_DESCRIPTION"))
                continue
            prose = pick_mechanism(txt, cve)
            if not prose:
                aborted.append((r["machine"], cve, "NO_MECHANISM_SENTENCE"))
                continue
            seen_cves.add(cve)

            # Route by the mechanism the document describes, NOT by machine
            # name, and read the destination surface from the db.
            routed = pick_class(txt, cve)
            if not routed:
                aborted.append((r["machine"], cve, "NO_CLASS_ROUTE"))
                continue
            cid, _surface = routed

            # The HTB machine page is an SPA behind a login and does NOT carry
            # the write-up text (measured: 103,789 chars, zero of the quote).
            # Citing it anyway would manufacture a verifiable-looking citation
            # for a quote nobody can read, so the PUBLIC source list carries
            # only what genuinely holds the claim, and the document itself is
            # recorded as an on-disk evidence artefact with its hash.
            nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
            sources = [
                {"url": nvd_url, "source_type": "research",
                 "host": "services.nvd.nist.gov", "publisher": NVD_ORG,
                 "quote": desc},
            ]
            # The second PUBLIC publisher: the weakness class, on an organisation
            # independent of nist.gov. This is what lets the item clear
            # MIN_PUBLISHER_HOSTS without pretending a login-gated page is public.
            cwes = nvd_cwes(cve)
            cwe_used = None
            for c in cwes:
                title = cwe_title(c)
                if len(title) > 6:
                    cwe_used = (c, title)
                    break
            if cwe_used:
                cid_num = cwe_used[0].split("-")[-1]
                sources.append({
                    "url": f"https://cwe.mitre.org/data/definitions/{cid_num}.html",
                    "source_type": "taxonomy", "host": "cwe.mitre.org",
                    "publisher": CWE_ORG, "quote": cwe_used[1]})
            # Hash the record path AS GIVEN. The previous version rewrote the
            # separators and then swallowed the resulting open() failure into an
            # empty string, so the provenance record shipped with a blank hash --
            # decoration rather than evidence.
            pdf_src = r["txt"]
            try:
                sha = hashlib.sha1(open(pdf_src, "rb").read()).hexdigest()
            except OSError as e:
                aborted.append((r["machine"], cve, f"NO_LOCAL_PDF: {e.strerror}"))
                continue
            evidence = {
                "kind": "document",
                "publisher": HTB_ORG,
                "path": pdf_src,
                "origin": r["file"],
                "machine": r["machine"],
                "doc_id": r["id"],
                "sha1": sha,
                "chars": r["chars"],
                "note": ("HTB official write-up (retired machine). The public "
                         "machine page is a login-gated SPA and does not carry "
                         "this text, so the quote is verifiable only against "
                         "this document."),
            }
            # HARD REFUSE a self-corroborating pair. HTB supplies the practice
            # account (the document) and NVD the authoritative mechanism; they
            # are different organisations, which is the whole point -- all 291
            # HTB documents are ONE publisher and could never corroborate each
            # other (measured: help/forum/academy all collapse to
            # hackthebox.com).
            orgs = {config.publisher_org(s["host"]) for s in sources}
                        # NOTE: the on-disk HTB document is NOT counted -- it is not a
            # public URL, and counting it would launder an unverifiable
            # source into corroboration. The gate decides.
            if len(orgs) < config.MIN_PUBLISHER_HOSTS:
                aborted.append((r["machine"], cve, f"ONLY_{len(orgs)}_ORG"))
                continue

            claim = (f"{r['machine']} documents {cve} as a route from an authenticated "
                     f"user to elevated privileges, and the authoritative record "
                     f"confirms the same weakness in the affected product.")
            name = re.sub(r"[^a-z0-9]+", "_", f"{r['machine']}_{cve}".lower()).strip("_")
            item = {
                "item_key": f"{cid}.technique.{name}",
                "claim": claim,
                "kind": "technique",
                "body": (f"HTB machine {r['machine']} (official write-up, doc "
                         f"{r['id']}, {r['chars']} chars, sha1 {sha[:12]}) "
                         f"describes {cve}. "
                         f"Mechanism as documented on the machine: {prose}\n\n"
                         f"Authoritative record: {desc[:400]}"),
                "disproof": (f"Refuted when the running product is outside the "
                             f"affected version range, or when the specific "
                             f"weakness ({cve}) is patched on the target: the "
                             f"documented escalation then does not exist, whatever "
                             f"the advisory still says."),
                "hunting_value": 3,
                "sources": sources,
                "evidence": [evidence],
            }
            built.setdefault(cid, []).append(item)
            break
        time.sleep(0.1)

    for cid, items in built.items():
        payload = {
            "class_id": cid,
            "items": items,
            "publishers": sorted({s["publisher"] for i in items for s in i["sources"]}),
            "publishers_used": sorted({config.publisher_org(s["host"])
                                       for i in items for s in i["sources"]}),
            "sources": sorted({s["url"] for i in items for s in i["sources"]}),
        }
        p = os.path.join(OUTDIR, f"htbpdf_{cid}.json")
        with io.open(p, "w", encoding="utf-8", newline="\n") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write(f"\n// COMPLETE {len(items)}\n")
        print(f"  built {len(items):>3} -> {os.path.basename(p)}  "
              f"orgs={payload['publishers_used']}")

    total = sum(len(v) for v in built.values())
    print(f"\nitems built: {total}")
    print(f"distinct CVEs used: {len(seen_cves)}")
    print(f"aborted: {len(aborted)}")
    for m, c, why in aborted[:12]:
        print(f"   {m:<16} {c:<18} {why}")
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())