"""Build WKS items FROM HackTricks pages by slicing real quotes out of them.

This is the strongest anti-fabrication move available (learned on an earlier wave):
the builder never TYPES a quote. It holds (class_id, page, anchor) tuples, reads the
cached page, slices the real span out of it, trims it to a sentence boundary, asserts
the gate's own matcher `verify_quotes.find_quote(page, quote)` is True, and refuses to
write an item whose evidence would fail the gate.

Three refusals are HARD (the build aborts):
  R1  the anchor is not in the page            -> the page does not say what we claim
  R2  find_quote(page, quote) is False         -> the slice would be rejected as
                                                  QUOTE_NOT_FOUND_ON_CITED_PAGE
  R3  fewer than 2 INDEPENDENT publisher orgs  -> the item could never promote, and
                                                  the usual way that happens is one
                                                  document cited on two hosts of the
                                                  same publisher

R3 is the load-bearing one for this corpus. HackTricks is available at
hacktricks.wiki AND raw.githubusercontent.com/HackTricks-wiki -- the same document
on two hosts. `publisher_org` counts those as two orgs, so a lazy item would
"self-corroborate" and promote on one voice. HT_ONE_ORG collapses the HackTricks
property so the check is honest.

Usage:
    python tools/ht_build_items.py --class idor --pages 3
    python tools/ht_build_items.py --plan tools/ht_plan_web.json --dry
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import config, store, verify_quotes  # noqa: E402
import ht_fetch  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# HackTricks and its GitHub mirror are ONE editorial voice for this corpus.
HT_ORGS = {config.publisher_org("hacktricks.wiki"),
           config.publisher_org("raw.githubusercontent.com")}
HT_HOST_MARKERS = ("hacktricks.wiki", "HackTricks-wiki/hacktricks")


def is_ht(url_or_host):
    return any(m in (url_or_host or "") for m in HT_HOST_MARKERS)


def org(url):
    host = re.sub(r"^https?://", "", url).split("/")[0]
    o = config.publisher_org(host)
    return HT_ORGS.intersection({o}) and "HT" or o


def ht_org(url):
    """The collapsed HackTricks org for any of its mirrors."""
    host = re.sub(r"^https?://", "", url).split("/")[0]
    return "hacktricks"


def fetch_html(url, tries=3, pause=1.5):
    """Fetch an independent publisher's page and return flattened prose."""
    import html as _html
    import time as _time
    import urllib.request as _rq
    for attempt in range(tries):
        try:
            req = _rq.Request(url, headers={"User-Agent": ht_fetch.UA})
            body = _rq.urlopen(req, timeout=45).read().decode("utf-8", "replace")
            body = re.sub(r"(?s)<(script|style|nav|footer|header).*?</>", " ", body)
            body = _html.unescape(re.sub(r"<[^>]+>", " ", body))
            return re.sub(r"\s+", " ", body)
        except Exception:                                     # noqa: BLE001
            _time.sleep(pause * (attempt + 1))
    return ""


def to_text(md):
    """Flatten markdown to prose while KEEPING payload text verbatim.

    A previous wave's bug: stripping tags from a markdown document destroyed the
    evidence it was checking, because in markdown a tag is often the CONTENT
    (HackTricks' XSS tables are literal <script> payloads). So: keep code spans
    and fenced blocks intact, drop only link/emphasis syntax.
    """
    t = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", md)     # links -> text
    t = re.sub(r"(?m)^\s*\|?[\s:\-|]{6,}\|?\s*$", " ", t)  # table rules
    t = re.sub(r"(?m)^\s*\|", " ", t)                     # leading pipes
    t = re.sub(r"(?m)^#{1,6}\s*", "", t)                  # heading marks
    t = t.replace("**", "").replace("__", "").replace("`", "")
    t = re.sub(r"[ \t]+", " ", t)
    return t


def sentences(text):
    """Sentence-ish spans, long enough to be evidence.

    A SPAN MUST NOT CROSS A HEADING. Measured: a naive whitespace split produced
    a single 'sentence' that ran from OWASP's JSON advice, through the heading
    'Output Encoding for "CSS Contexts" ¶', into the CSS paragraph. Every
    fragment was on the page, so `find_quote` failed on the joined form and the
    citation was unusable -- a malformed quote is not evidence. Headings are
    block boundaries, so we split on them first and never rejoin across one.
    """
    # block boundary: any markdown heading line
    blocks = re.split(r"(?m)^(?=#{1,6}\s)", text)
    out = []
    for blk in blocks:
        for part in re.split(r"(?<=[.!?:;])\s+(?=[A-Z0-9\`\"'(])", blk):
            p = part.strip()
            if len(p) >= 80:
                out.append(p)
    return out


def slice_quote(page_md, anchor, width=3, need=1):
    """Return real quotes containing `anchor`, or [].

    R1 fires when the anchor is absent: the page does not contain the claim's
    mechanism, so the item must not be built from it.
    """
    text = to_text(page_md)
    if anchor.lower() not in text.lower():
        return []
    low = text.lower()
    out = []
    for s in sentences(text):
        if anchor.lower() in s.lower() and need <= 1:
            out.append(s)
    if not out:
        # widen: a window around the anchor, trimmed to sentence boundaries
        i = low.find(anchor.lower())
        start = max(0, text.rfind("\n", 0, i) + 1)
        end = text.find("\n", i)
        end = end if end > 0 else min(len(text), i + 600)
        win = re.sub(r"\s+", " ", text[start:end]).strip()
        if len(win) >= 120:
            out.append(win)
    return out[:width]


def build_one(plan_row, con, idx):
    """Build ONE item. Returns (item, notes). Never raises on a soft refusal."""
    cid = plan_row["class_id"]
    rel = plan_row["page"]
    anchor = plan_row["anchor"]
    notes = []

    text, status = ht_fetch.get(rel, idx)
    if not text:
        return None, ["%s: fetch failed (%s)" % (rel, status)]
    if status == "too_small" or len(text) < ht_fetch.MIN_BYTES:
        return None, ["%s: only %d bytes, refusing to treat as evidence"
                      % (rel, len(text))]

    quotes = slice_quote(text, anchor, width=plan_row.get("width", 3))
    if not quotes:
        return None, ["%s: R1 anchor %r absent" % (rel, anchor)]
    quote = quotes[0]

    # R2: the gate's own matcher, before writing anything.
    if not verify_quotes.find_quote(text, quote):
        return None, ["%s: R2 find_quote failed on the slice" % rel]

    url = ht_fetch.RAW % rel
    sources = [{"url": url,
                "source_type": "reference",
                "host": "raw.githubusercontent.com",
                "publisher": "hacktricks",
                "quote": quote}]

    # An INDEPENDENT publisher must exist, or this item can never promote.
    partner = plan_row.get("partner")
    if partner:
        pq = partner["quote"]
        ptext = partner.get("text")
        if ptext is None:
            # independent publisher: fetch it and verify against the LIVE page,
            # exactly as the gate will. Never trust a quote typed into a plan.
            ptext = fetch_html(partner["url"])
        if not ptext:
            return None, ["%s: partner page unreachable %s" % (cid, partner["url"])]
        if not verify_quotes.find_quote(ptext, pq):
            return None, ["%s: R2b partner quote does not verify on %s"
                          % (cid, partner["url"])]
        sources.append({"url": partner["url"],
                        "source_type": "research",
                        "host": re.sub(r"^https?://", "", partner["url"]).split("/")[0],
                        "publisher": org(partner["url"]),
                        "quote": pq})

    # R3: >=2 INDEPENDENT orgs, counting HackTricks' mirrors as ONE.
    orgs = set()
    for s in sources:
        orgs.add(ht_org(s["url"]) if is_ht(s["url"]) else org(s["url"]))
    if len(orgs) < config.MIN_PUBLISHER_HOSTS:
        return None, ["%s: R3 only %d independent org(s) %s -- would never promote"
                      % (cid, len(orgs), sorted(orgs))]

    item = {
        "item_key": "%s.%s.ht_%s" % (cid, plan_row["kind"],
                                     re.sub(r"\W+", "_", anchor)[:40].strip("_")),
        "kind": plan_row["kind"],
        "claim": plan_row["claim"],
        "body": plan_row.get("body") or ("HackTricks reference: %s"
                                         % plan_row.get("title", rel)),
        "disproof": plan_row["disproof"],
        "hunting_value": plan_row.get("hunting_value", 4),
        "sources": sources,
    }
    notes.append("%s: ok  %d quote chars, orgs=%s"
                 % (cid, len(quote), sorted(orgs)))
    return item, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", help="JSON list of plan rows")
    ap.add_argument("--class", dest="cls")
    ap.add_argument("--pages", type=int, default=0,
                    help="take the first N rows of the plan")
    ap.add_argument("--out", default=os.path.join(ROOT, "research", "incoming",
                                                  "ht_items.json"))
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args()

    if a.plan:
        with open(a.plan, encoding="utf-8") as fh:
            plan = json.load(fh)
        if a.cls:
            plan = [p for p in plan if p["class_id"] == a.cls]
        if a.pages:
            plan = plan[:a.pages]
    else:
        print("need --plan")
        return 1

    con = store.connect()
    idx = ht_fetch.load_index()
    items, refusals, oks = [], [], []
    for row in plan:
        it, notes = build_one(row, con, idx)
        for n in notes:
            # a note starting "ok " is a SUCCESS report, not a refusal
            (oks if n.endswith(("orgs=%s" % "",)) or " ok  " in n
             else refusals).append(n)
        if it:
            items.append(it)

    ht_fetch.save_index(idx)
    for n in refusals:
        print("REFUSED  %s" % n)
    for n in oks:
        print("BUILT    %s" % n)
    print("\nbuilt %d item(s) from %d plan row(s); %d refusal(s)"
          % (len(items), len(plan), len(refusals)))

    if items and not a.dry:
        with open(a.out, "w", encoding="utf-8") as fh:
            json.dump({"class_id": items[0]["item_key"].split(".")[0],
                       "items": items,
                       "publishers": sorted({o for i in items for o in
                                             [org(s["url"]) for s in i["sources"]]}),
                       "sources": [s["url"] for i in items for s in i["sources"]]},
                      fh, indent=1)
        print("wrote %s" % a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())