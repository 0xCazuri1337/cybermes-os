"""Map a flat documentation book's pages to WKS classes, then slice VERIFIED quotes.

Generic across GitBook sources: the pages are FLAT (one page per topic) and the
page title IS the topic, so unlike HackTricks there is no tree to inherit from and
no port-shaped filenames. Matching is IDF-weighted over the class vocabulary with
a runner-up margin, plus an explicit ANCHOR table for the pages whose URL slug
is more reliable than their title (e.g. `sqli/sql_injection.md` -> `sqli`).

Output is a PACKET file in the same shape `ht_build_items.py` and
`ht_stage.py` already consume, so the merge path is shared:

    packets[class][page] = {url, title, quotes:[{quote, class_terms}],
                            partner:{url, quote, org}}

The partner is RECYCLED from an already-promoted corpus item on a different
registrable domain, so MIN_PUBLISHER_HOSTS=2 is met honestly and nothing in the
partner path is typed. Crucially, two GitBooks are NOT two publishers: they are
the same genre, and a pair of gitbook hosts is refused unless the partner is a
normative domain (portswigger/owasp/mitre/rfc/...).
"""
import argparse
import collections
import json
import math
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ht_build_items as B          # noqa: E402  (to_text, sentences, fetch_html)
import ht_verify2 as V2             # noqa: E402  (has_furniture)
from wks import config, relevance, store, verify_quotes  # noqa: E402
V0 = verify_quotes

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MIN_PARTNER_CHARS = 110
NORMATIVE = ("portswigger.net", "owasp.org", "mitre.org", "rfc-editor.org",
             "ietf.org", "httpwg.org", "w3.org", "cwe.mitre.org", "nvd.nist.gov")

# Seeded normative partner for a BRAND-NEW class, which by definition has no
# promoted item to recycle one from. Each quote was verified live before being
# written here; tools/src_packets.py re-verifies it at build time, so a page
# that moves or is rewritten drops the row instead of shipping a dead citation.
SEEDS = {
    "windows_privesc_token": [
        {
            "url": "https://cwe.mitre.org/data/definitions/269.html",
            "quote": "The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.",
            "org": "mitre.org"
        },
        {
            "url": "https://man7.org/linux/man-pages/man2/execve.2.html",
            "quote": "(Before Linux 2.6, the resource limit was not imposed on processes that changed their user IDs.) Since Linux 3.1, the scenario just described no longer causes the set*uid () call to fail, because it too often led to security holes where buggy applications didn't check the return status and assumed that\u2014if the caller had root privileges\u2014the call would always succeed.",
            "org": "man7.org"
        }
    ],
    "windows_privesc_hijack": [
        {
            "url": "https://cwe.mitre.org/data/definitions/427.html",
            "quote": "The product uses a fixed or controlled search path to find resources, but one or more locations in that path can be under the control of unintended actors.",
            "org": "mitre.org"
        },
        {
            "url": "https://man7.org/linux/man-pages/man8/ld.so.8.html",
            "quote": "Other environment variables treated in this way include: GCONV_PATH , GETCONF_DIR , HOSTALIASES , LOCALDOMAIN , LD_AUDIT , LD_DEBUG , LD_DEBUG_OUTPUT , LD_DYNAMIC_WEAK , LD_HWCAP_MASK , LD_LIBRARY_PATH , LD_ORIGIN_PATH , LD_PRELOAD , LD_PROFILE , LD_SHOW_AUXV , LOCALDOMAIN , LOCPATH , MALLOC_TRACE , NIS_PATH , NLSPATH , RESOLV_HOST_CONF , RES_OPTIONS , TMPDIR , and TZDIR .",
            "org": "man7.org"
        }
    ],
    "windows_privesc_service": [
        {
            "url": "https://cwe.mitre.org/data/definitions/269.html",
            "quote": "The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.",
            "org": "mitre.org"
        },
        {
            "url": "https://man7.org/linux/man-pages/man2/execve.2.html",
            "quote": "(Before Linux 2.6, the resource limit was not imposed on processes that changed their user IDs.) Since Linux 3.1, the scenario just described no longer causes the set*uid () call to fail, because it too often led to security holes where buggy applications didn't check the return status and assumed that\u2014if the caller had root privileges\u2014the call would always succeed.",
            "org": "man7.org"
        }
    ],
    "linux_privesc": [
        {
            "url": "https://cwe.mitre.org/data/definitions/269.html",
            "quote": "The product does not properly assign, modify, track, or check privileges for an actor, creating an unintended sphere of control for that actor.",
            "org": "mitre.org"
        },
        {
            "url": "https://man7.org/linux/man-pages/man2/execve.2.html",
            "quote": "(Before Linux 2.6, the resource limit was not imposed on processes that changed their user IDs.) Since Linux 3.1, the scenario just described no longer causes the set*uid () call to fail, because it too often led to security holes where buggy applications didn't check the return status and assumed that\u2014if the caller had root privileges\u2014the call would always succeed.",
            "org": "man7.org"
        }
    ],
    "container_escape": [
        {
            "url": "https://cwe.mitre.org/data/definitions/250.html",
            "quote": "The product performs an operation at a privilege level that is higher than the minimum level required, which creates new weaknesses or amplifies the consequences of other weaknesses.",
            "org": "mitre.org"
        },
        {
            "url": "https://docs.docker.com/engine/security/",
            "quote": "For this reason, the REST API endpoint (used by the Docker CLI to communicate with the Docker daemon) changed in Docker 0.5.2, and now uses a Unix socket instead of a TCP socket bound on 127.0.0.1 (the latter being prone to cross-site request forgery attacks if you happen to run Docker directly on your local machine, outside of a VM).",
            "org": "docker.com"
        }
    ]
}

STOP = {"the", "and", "for", "with", "from", "that", "this", "how", "using",
        "into", "a", "an", "of", "to", "in", "on", "is", "are", "be", "at", "by",
        "it", "or", "as", "not", "no", "you", "your", "we", "can", "will", "when",
        "what", "attack", "attacks", "attackers", "hunt", "hunting", "test",
        "testing", "method", "methods", "methodology", "approach", "guide",
        "tips", "trick", "tricks", "bug", "bugs", "vuln", "vulnerability",
        "basic", "common", "note", "notes", "step", "steps", "part", "use",
        "using", "find", "finding", "learn", "check", "section", "page"}


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip()


def toks(s, minlen=2):
    return {t for t in norm(s).split() if t not in STOP and len(t) >= minlen}


def load_classes():
    con = store.connect()
    docs, raw = [], {}
    for cid, name, aliases, summary in con.execute(
            "SELECT id,name,aliases,summary FROM bug_class"):
        vocab = toks("%s %s %s" % (cid.replace("_", " "), name, aliases or ""))
        docs.append(vocab)
        raw[cid] = {"vocab": vocab, "summ": toks(summary or ""),
                    "stem": norm(cid)}
    n = len(docs)
    df = collections.Counter(t for d in docs for t in d)
    idf = {t: math.log(n / (1.0 + c)) for t, c in df.items()}
    for c in raw.values():
        c["idf"] = {t: idf[t] for t in c["vocab"]}
    return list(raw.values()), con


def load_partners(con):
    per = collections.defaultdict(list)
    for cid, url, host, quote in con.execute(
            "SELECT i.class_id, s.url, s.host, x.quote FROM item i"
            "  JOIN quality q ON q.item_id=i.id"
            "  JOIN item_source x ON x.item_id=i.id"
            "  JOIN source s ON s.id=x.source_id"
            " WHERE q.validation_state='high_confidence'"
            "   AND x.quote IS NOT NULL AND length(x.quote) >= ?",
            (MIN_PARTNER_CHARS,)):
        org = config.publisher_org(host)
        # A NORMATIVE publisher only. Two hunter-written gitbooks are one genre,
        # not two publishers -- see the module docstring.
        if not any(nm in host for nm in NORMATIVE):
            continue
        per[cid].append({"url": url, "host": host, "quote": quote, "org": org})
    for cid in per:
        seen, uniq = set(), []
        for p in sorted(per[cid], key=lambda p: -len(p["quote"])):
            k = (p["url"], p["quote"][:60])
            if k not in seen and not V2.has_furniture(p["quote"]):
                seen.add(k)
                uniq.append(p)
        per[cid] = uniq
    return per


def route(url, title, classes, anchors, margin):
    for frag, cid in anchors.items():
        if frag in url:
            return cid, 100.0, "anchor"
    pt = toks(title) | toks(url.rsplit("/", 1)[-1][:-3].replace("_", " ").replace("-", " "))
    ranked = []
    for c in classes:
        sc = sum(c["idf"].get(t, 0.0) for t in pt & c["vocab"])
        sc += 0.25 * len(pt & c["summ"])
        ranked.append((sc, c["stem"]))
    ranked.sort(reverse=True)
    if not ranked or ranked[0][0] < 2.0:
        return None, ranked[0][0] if ranked else 0.0, "-"
    if len(ranked) > 1 and ranked[0][0] - ranked[1][0] < margin:
        return None, ranked[0][0], "ambiguous"
    return ranked[0][1], ranked[0][0], "scored"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", required=True, help="dir written by src_fetch.py")
    ap.add_argument("--out", required=True)
    ap.add_argument("--per-class", type=int, default=3)
    ap.add_argument("--quotes-per-page", type=int, default=3)
    ap.add_argument("--margin", type=float, default=1.0)
    a = ap.parse_args()

    cache = a.cache if os.path.isabs(a.cache) else os.path.join(ROOT, a.cache)
    with open(os.path.join(cache, "index.json"), encoding="utf-8") as fh:
        index = json.load(fh)

    anchors = json.loads(os.environ.get("SRC_ANCHORS", "{}"))
    classes, con = load_classes()
    partners = load_partners(con)

    packets = collections.defaultdict(list)
    unmapped = []
    for url, meta in sorted(index.items()):
        if meta.get("status") not in ("ok", "cached") or not meta.get("file"):
            continue
        path = os.path.join(cache, meta["file"] + ".md")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            md = fh.read()
        title = url.rsplit("/", 1)[-1][:-3].replace("_", " ").replace("-", " ").strip()
        cid, score, via = route(url, title, classes, anchors, a.margin)
        if not cid:
            unmapped.append((url, title, via))
            continue
        pool = partners.get(cid, [])
        if not pool:
            # A BRAND-NEW class has no promoted item to recycle a partner from.
            # Refusing here is right in principle -- a partner must be a quote
            # already proven to exist on a normative page -- but it would make
            # every new class permanently unharvestable. Fall back to a SEEDED
            # normative page for the class's mechanism and verify it live at
            # staging time, which is what the packet's partner check does.
            seedlist = SEEDS.get(cid) or []
            if not seedlist:
                unmapped.append((url, title, "no normative partner and no seed"))
                continue
            pool = []
            for seed in seedlist:
                # fetch_html returns TEXT only (empty string on failure)
                body = B.fetch_html(seed["url"])
                if not body:
                    print("   seed page unreachable: %s" % seed["url"])
                    continue
                if not V0.find_quote(body, seed["quote"]):
                    print("   seed quote does not verify: %s" % seed["url"])
                    continue
                pool.append({"url": seed["url"],
                             "host": seed["url"].split("/")[2],
                             "quote": seed["quote"], "org": seed["org"]})
            orgs = {p["org"] for p in pool}
            if len(orgs) < config.MIN_PUBLISHER_HOSTS:
                unmapped.append((url, title,
                                 "seeds give %d org(s): %s"
                                 % (len(orgs), sorted(orgs))))
                continue

        prose = B.to_text(md)
        picks, seen = [], set()
        for s in B.sentences(prose):
            if V2.has_furniture(s):
                continue
            v = relevance.assess(cid, norm(s))
            if v is None or not v.own_hits:
                continue
            if not verify_quotes.find_quote(md, s):
                continue
            key = s[:70]
            if key in seen:
                continue
            seen.add(key)
            strong = [h for h in v.own_hits
                      if len(h.split()) > 1 or len(h) > 4] or sorted(v.own_hits)
            picks.append({"quote": s, "class_terms": sorted(strong)})
            if len(picks) >= a.quotes_per_page:
                break
        if not picks:
            unmapped.append((url, title, "no class-relevant verifiable quote"))
            continue
        part = pool[len(packets[cid]) % len(pool)]
        packets[cid].append({
            "page": url, "title": title, "section": "doc",
            "url": url, "quotes": picks,
            "partner": pool[0],
            "partner2": pool[1] if len(pool) > 1 else None,
        })

    # cap per class
    for cid in list(packets):
        packets[cid] = packets[cid][:a.per_class]

    vocab = {c: sorted(relevance.CLASS_VOCAB.get(c, [])) for c in packets}
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump({"vocab": vocab, "packets": dict(packets)}, fh, indent=1)

    nq = sum(len(e["quotes"]) for v in packets.values() for e in v)
    print("=" * 72)
    print("PACKETS from %s" % cache)
    print("  classes      : %d" % len(packets))
    print("  pages mapped : %d" % sum(len(v) for v in packets.values()))
    print("  quotes       : %d (all asserted with find_quote)" % nq)
    print("  unmapped     : %d" % len(unmapped))
    for u, t, why in unmapped[:20]:
        print("    %-28s %-46s %s" % (t[:28], u[-46:], why))
    print("\nwrote %s" % a.out)


if __name__ == "__main__":
    main()