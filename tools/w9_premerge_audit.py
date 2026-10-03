"""Independent pre-merge audit of the wave-9 files, before any real ingest.

Checks the things a child's self-report cannot be trusted on:
  1. HOST REUSE - is every cited host genuinely NEW to the corpus, counted by
     REGISTRABLE DOMAIN (so www.ired.team and ired.team are one host, and
     unit42.paloaltonetworks.com is caught as already-cited)?
  2. PUBLISHER DIVERSITY re-derived per item from config.publisher_org.
  3. BUILDER PAGES - any *.gitbook.io / *.notion.site / app.notion.com /
     *.netlify.app / docs.readthedocs.io used as a publisher.
  4. QUOTE LENGTH - the brief capped quotes at 200 chars.
  5. SCHEMA completeness and item_key class_id agreement.

Prints a verdict per file. Does not ingest.
"""
import json
import os
import re
import sys
from collections import Counter

ROOT = r"C:/Users/Administrator/.hermes/cyber"
sys.path.insert(0, ROOT)
from wks import config, store  # noqa: E402

BUILDER_SUFFIX = (".gitbook.io", ".notion.site", ".netlify.app", ".readthedocs.io")
BUILDER_HOSTS = {"app.notion.com", "docs.readthedocs.io", "medium.com"}
MAXQ = 200

con = store.open_db(create=False)
cited = {r[0] for r in con.execute("SELECT DISTINCT host FROM source").fetchall()}
cited_urls = {r[0] for r in con.execute("SELECT url FROM source").fetchall()}
con.close()


def regdomain(host):
    return config.publisher_org(host)


def audit(path):
    raw = open(path, encoding="utf-8").read()
    raw = re.sub(r"\n?//\s*COMPLETE[^\n]*\s*$", "", raw).strip()
    d = json.loads(raw)
    items = d["items"] if isinstance(d, dict) else d
    print("=" * 78)
    print(os.path.basename(path), " items:", len(items))

    hosts = Counter()
    reuse_hosts, builder, longq, shape, lowdiv = Counter(), [], [], [], []
    for it in items:
        srcs = it.get("sources", [])
        for s in srcs:
            h = (s.get("host") or "").lower().removeprefix("www.")
            hosts[h] += 1
            if h in cited or regdomain(h) in {regdomain(c) for c in cited}:
                reuse_hosts[h] += 1
            if h in BUILDER_HOSTS or h.endswith(BUILDER_SUFFIX):
                builder.append((it["item_key"], h))
            q = s.get("quote") or ""
            if len(q) > MAXQ:
                longq.append((it["item_key"], h, len(q)))
        for f in ("item_key", "class_id", "kind", "claim", "surface",
                  "severity_hint", "hunting_value", "disproof", "sources"):
            if f not in it or it[f] in (None, "", []):
                shape.append((it.get("item_key", "?"), f))
        real = [s for s in srcs
                if not ((s.get("host") or "").lower().removeprefix("www.")
                        in BUILDER_HOSTS)]
        orgs = {regdomain((s.get("host") or "").lower().removeprefix("www."))
                for s in real}
        if len(orgs) < 2:
            lowdiv.append((it["item_key"], sorted(orgs)))

    print("  distinct hosts:", len(hosts))
    for h, n in hosts.most_common():
        flag = "  <-- REUSE (already in corpus)" if reuse_hosts.get(h) else ""
        print("     %-38s %-3d%s" % (h, n, flag))
    print("  items with a REUSED host:", sum(1 for it in items
                                             if any(reuse_hosts.get(
                                                 (s.get('host') or '').lower()
                                                 .removeprefix('www.'))
                                                 for s in it.get("sources", []))))
    print("  builder-page sources:", len(builder), builder[:4])
    print("  quotes over %d chars: %d" % (MAXQ, len(longq)))
    for x in longq[:5]:
        print("     ", x)
    print("  items with <2 publisher orgs:", len(lowdiv), lowdiv[:4])
    print("  schema holes:", len(shape), shape[:4])
    return {"items": len(items), "reuse_hosts": dict(reuse_hosts),
            "builder": builder, "long_quotes": longq,
            "low_diversity": lowdiv, "shape": shape}


for f in sys.argv[1:]:
    audit(f)