"""Fix ht_stage: the SOURCE page is not a publisher, and the prefix must follow it.

MEASURED: all 37 HowToHunt items came back HELD with
    BUILDER_PAGE_NOT_PUBLISHER(kathan19.gitbook.io)
    INSUFFICIENT_PUBLISHER_HOSTS(1<2:<the partner>)
The gate was right twice over:

  D1  A PRACTICE GUIDE IS NOT A PUBLISHER. The gate counts distinct publisher ORGS
      and the gate's own allowlist recognises normative sources. I had let the
      GitBook page count as one of the two publishers, so every item had a
      partner (portswigger/owasp/cwe/rfc) plus a genre page that is not evidence
      -- exactly the "a write-up alone can never promote" rule, and here the
      write-up is a whole guide rather than one engagement.

  D2  The item_key prefix was hardcoded `ht_` for EVERY source, so HowToHunt and
      Biscuit items were indistinguishable from HackTricks ones in the db. The
      prefix now derives from the source host, which is what makes "which source
      contributed this" answerable from the row alone.

Neither is a threshold to move. The fix is to stop counting a genre page as a
publisher, and to name the source honestly.
"""
import io
import re

P = "tools/ht_stage.py"
src = io.open(P, encoding="utf-8").read()

# --- 1. per-source item_key prefix -----------------------------------------
old_prefix = 'name = "".join(ch if (ch.isalnum() or ch == "_") else "_"\n                       for ch in quote[:34].lower())\n        name = "_".join(p for p in name.split("_") if p)[:80]\n        slug = "%s.%s.ht_%s" % (r["class_id"], r.get("kind") or "technique", name)'
new_prefix = 'name = "".join(ch if (ch.isalnum() or ch == "_") else "_"\n                       for ch in quote[:34].lower())\n        name = "_".join(p for p in name.split("_") if p)[:80]\n        # The prefix names the SOURCE, not a fixed string: ht_ = HackTricks,\n        # hth_ = HowToHunt, bis_ = Biscuit. A hardcoded prefix made four\n        # sources indistinguishable in the db.\n        slug = "%s.%s.%s_%s" % (r["class_id"], r.get("kind") or "technique",\n                                SRC_PREFIX(r["hacktricks_url"]), name)'
if old_prefix in src:
    src = src.replace(old_prefix, new_prefix, 1)
    print("patched: per-source item_key prefix")
else:
    print("prefix anchor not found")

# --- 2. the source page is NOT a publisher ---------------------------------
helper = '''

# A practice-guide page carries NO evidentiary weight on its own: the same rule
# that stops a single write-up from promoting an item stops a whole guide. The
# gate enforces this itself (BUILDER_PAGE_NOT_PUBLISHER); this keeps the stager
# from pretending otherwise, so `publishers` in the intake file reports what the
# gate will actually count.
GUIDE_HOSTS = ("gitbook.io", "notion.site", "notion.so", "pentester.land")


def SRC_PREFIX(url):
    host = url.split("/")[2] if "://" in url else url
    if "HackTricks-wiki" in host or "hacktricks" in host:
        return "ht"
    if "kathan19" in host:
        return "hth"
    if "oreobiscuit" in host:
        return "bis"
    if "pentester.land" in host:
        return "pl"
    return re.sub(r"\\W+", "_", host.split(".")[0])[:6].strip("_") or "src"


def is_guide(url):
    return any(g in url for g in GUIDE_HOSTS)

'''
anchor = "\ndef read_page(rel, idx):"
if anchor in src:
    src = src.replace(anchor, helper + "\ndef read_page(rel, idx):", 1)
    print("patched: GUIDE_HOSTS + SRC_PREFIX")
else:
    raise SystemExit("read_page anchor not found")

# --- 3. publisher_org must not count the guide ------------------------------
src = src.replace(
    'def org_of(url):\n    host = url.split("/")[2]\n    return config.publisher_org(host)',
    'def org_of(url):\n    """Publisher org of a CITED SOURCE.\n\n    A practice guide returns "" so it cannot satisfy the 2-publisher rule --\n    the gate would refuse it anyway, and counting it here made every item\n    report a publisher it would never be credited with.\n    """\n    if is_guide(url):\n        return ""\n    host = url.split("/")[2]\n    return config.publisher_org(host)')
print("patched: org_of excludes guides")

# --- 4. the partner-only check must be the real acceptance test ------------
src = src.replace(
    '        hosts = {org_of(r["hacktricks_url"]), org_of(r["partner_url"])}\n'
    '        if len(hosts) < config.MIN_PUBLISHER_HOSTS:\n'
    '            refused.append((r["class_id"], page,\n'
    '                            "only %d publisher org(s)" % len(hosts)))\n'
    '            continue',
    '        # Two REAL publishers are required, and the source page is not one\n'
    '        # of them. Assert it here so the refusal names the cause instead of\n'
    '        # surfacing later as an unexplained hold.\n'
    '        pubs = {o for o in (org_of(r["hacktricks_url"]),\n'
    '                            org_of(r["partner_url"])) if o}\n'
    '        if len(pubs) < config.MIN_PUBLISHER_HOSTS:\n'
    '            refused.append((r["class_id"], page,\n'
    '                            "only %d real publisher org(s): %s"\n'
    '                            % (len(pubs), sorted(pubs))))\n'
    '            continue')

src = src.replace('import json\nimport os\nimport sys', 'import json\nimport os\nimport re\nimport sys')
compile(src, P, "exec")
io.open(P, "w", encoding="utf-8").write(src)
print("lint ok")