"""Add a SECOND normative partner to staged items from practice-guide sources.

MEASURED: excluding the guide as a publisher (correct) left every HowToHunt item
with one real publisher, so `MIN_PUBLISHER_HOSTS=2` could never be met and the
gate held all 37. The gate is right; a practice guide cannot corroborate itself
or stand as evidence.

The fix is a second INDEPENDENT normative publisher, not a lower threshold. Each
item from a guide source now cites:
    guide  (practice: how it is hunted)
    + norm A (mechanism)
    + norm B (corroboration, a DIFFERENT registrable domain)
`tools/twopart.py` measures which classes actually have two distinct normative
orgs; 57 of 60 do. The 3 that do not are REFUSED, and named, rather than padded.
"""
import io

P = "tools/ht_stage.py"
src = io.open(P, encoding="utf-8").read()

# 1. load the two-partner pool
old_imports = "from ht_verify2 import has_furniture  # noqa: E402"
new_imports = (old_imports +
               "\nimport twopart  # noqa: E402")
if "import twopart" not in src:
    src = src.replace(old_imports, new_imports, 1)
    print("patched: import twopart")

# 2. build the pool once in main()
old_idx = "    idx = ht_fetch.load_index()\n    per_class = collections.defaultdict(list)\n    refused = []"
new_idx = ("    idx = ht_fetch.load_index()\n"
           "    # Two DISTINCT normative publishers per class, so a guide-sourced item\n"
           "    # can still satisfy MIN_PUBLISHER_HOSTS honestly.\n"
           "    tp = twopart.two_part(con)\n"
           "    per_class = collections.defaultdict(list)\n"
           "    refused = []")
if old_idx in src:
    src = src.replace(old_idx, new_idx, 1)
    print("patched: load the two-partner pool")

# 3. replace the partner acceptance test + sources block
old_block = '''        if has_furniture(part):
            refused.append((r["class_id"], page,
                            "partner quote carries heading furniture"))
            continue

        # Two REAL publishers are required, and the source page is not one of
        # them. Assert it here so the refusal names the cause instead of
        # surfacing later as an unexplained hold.
        pubs = {o for o in (org_of(r["hacktricks_url"]),
                            org_of(r["partner_url"])) if o}
        if len(pubs) < config.MIN_PUBLISHER_HOSTS:
            refused.append((r["class_id"], page,
                            "only %d real publisher org(s): %s"
                            % (len(pubs), sorted(pubs))))
            continue'''
new_block = '''        if has_furniture(part):
            refused.append((r["class_id"], page,
                            "partner quote carries heading furniture"))
            continue

        # A PRACTICE GUIDE IS NOT A PUBLISHER (the gate says so itself:
        # BUILDER_PAGE_NOT_PUBLISHER). It therefore needs TWO independent
        # NORMATIVE publishers to reach MIN_PUBLISHER_HOSTS. A normative source
        # IS a publisher, so one partner suffices there -- which is why the
        # HackTricks wave promoted 72 items on this same code path.
        sources = [{
            "url": r["hacktricks_url"], "source_type": "reference",
            "host": r["hacktricks_url"].split("/")[2],
            "publisher": "source-guide", "quote": quote}]

        sources.append({
            "url": r["partner_url"], "source_type": "research",
            "host": r["partner_url"].split("/")[2],
            "publisher": r.get("partner_org") or org_of(r["partner_url"]),
            "quote": part})

        if is_guide(r["hacktricks_url"]):
            pool = tp.get(r["class_id"], [])
            if len(pool) < config.MIN_PUBLISHER_HOSTS:
                refused.append((r["class_id"], page,
                                "guide source needs %d independent normative "
                                "orgs, class has %d"
                                % (config.MIN_PUBLISHER_HOSTS, len(pool))))
                continue
            have = {org_of(r["partner_url"])}
            for cand in pool:
                if cand["org"] in have:
                    continue
                sources.append({
                    "url": cand["url"], "source_type": "research",
                    "host": cand["host"], "publisher": cand["org"],
                    "quote": cand["quote"]})
                have.add(cand["org"])
                if len(have) >= config.MIN_PUBLISHER_HOSTS:
                    break

        pubs = {s["publisher"] for s in sources
                if s["publisher"] not in ("source-guide", "")}
        if len(pubs) < config.MIN_PUBLISHER_HOSTS:
            refused.append((r["class_id"], page,
                            "only %d real publisher org(s): %s"
                            % (len(pubs), sorted(pubs))))
            continue'''
if old_block in src:
    src = src.replace(old_block, new_block, 1)
    print("patched: two-publisher acceptance + sources")
else:
    print("acceptance block NOT found -- needs manual review")

# 4. the item now uses the built `sources` list
old_srcs = '''            "sources": [
                {"url": r["hacktricks_url"], "source_type": "reference",
                 "host": r["hacktricks_url"].split("/")[2],
                 "publisher": "hacktricks", "quote": quote},
                {"url": r["partner_url"], "source_type": "research",
                 "host": r["partner_url"].split("/")[2],
                 "publisher": r.get("partner_org") or org_of(r["partner_url"]),
                 "quote": part},
            ],'''
if old_srcs in src:
    src = src.replace(old_srcs, '            "sources": sources,', 1)
    print("patched: item uses the built sources list")

compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("lint ok")