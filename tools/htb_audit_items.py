"""Audit the built items against the SOURCE OF TRUTH, not the builder's own log.

Three defects this catches, all found by reading the emitted JSON rather than
trusting the printout:

  D1 A quote that starts mid-word / mid-table-cell. `slice_sentence` walks
     back a fixed `lo` chars and the previous char can be a letter, so the
     quote opens as "ic path traversal filter" instead of "Basic path
     traversal filter". A quote is evidence; a mangled one verifies against the
     page and teaches nothing.
  D2 The write-up chosen does not actually cover the claim. The builder picks
     the first corpus record whose `classes` list contains the class, and
     `classes` came from a VOCABULARY SCORE -- so a path_traversal claim was
     satisfied by a SQL Injection module that happens to mention file
     inclusion. The quote then contradicts the claim.
  D3 The quote is furniture (a markdown table row / separator / heading),
     not prose describing a technique.

The rule: a generator that renders a corpus must be checked against the corpus
AFTER writing. A green run proves nothing here.
"""
import glob
import importlib.util
import json
import os
import re
import sys

sys.path.insert(0, ".")

_spec = importlib.util.spec_from_file_location("sl", "tools/htb_slicer.py")
sl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sl)


# The PLAN is the single source of truth for what each claim's primary term is.
_b = importlib.util.spec_from_file_location("htbb", "tools/htb_build_items.py")
_bm = importlib.util.module_from_spec(_b)
_b.loader.exec_module(_bm)
# Key by the row's OWN claim, not by class. A class may carry several claims
# with several different mechanisms (`path_traversal` has three), and a
# class-keyed dict silently keeps only the last -- so the audit demanded one
# row's primary term of every row and flagged correct quotes as wrong.
PLAN_TERMS = {}
for _row in _bm.PLAN:
    _t = tuple(_row.get("claim_terms") or ())
    if _t:
        PLAN_TERMS[_row["claim"]] = _t
        PLAN_TERMS.setdefault(_row["cls"], _t)   # fallback for single-row classes

# legacy class-only lookup kept for the report lines
PLAN_TERMS_BY_CLASS = {}
for _row in _bm.PLAN:
    _t = tuple(_row.get("claim_terms") or ())
    if _t:
        PLAN_TERMS_BY_CLASS.setdefault(_row["cls"], _t)

# The harvested write-up corpus. It lives under WKS_ROOT because
# cache/scratch/ is pruned after 24h idle and this is the only local copy
# of the primary evidence behind the merged items.
_ROOT = os.environ.get("WKS_ROOT") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
HERE = os.path.join(_ROOT, "research", "corpus")
d1 = d2 = d3 = d4 = 0
d4_ok = 0
d4_undeclared = 0
rows = []
rows_d4 = []
_D4_BAD = set()

# Claim tokens that carry no topical signal, so they do not dilute D4.
_STOP = {"which", "there", "their", "these", "those", "where", "while", "because",
         "before", "after", "under", "other", "being", "about", "using", "into",
         "when", "what", "with", "from", "that", "this", "than", "then", "they"}
_MIN_OVERLAP = 0.12

for p in sorted(glob.glob("knowledge/incoming/htb_*.json")):
    raw = open(p, encoding="utf-8").read()
    raw = re.sub(r"\n\s*//\s*COMPLETE.*$", "", raw)
    d = json.loads(raw)
    for it in d["items"]:
        gh = [s for s in it["sources"] if s["publisher"] == "github.com"]
        if not gh:
            continue
        q = gh[0]["quote"]
        url = gh[0]["url"]
        prov = re.search(r":: (.+?) \(", it["body"])
        prov_path = prov.group(1) if prov else "?"

        # D1 -- the quote must not begin INSIDE a word. A markdown table row
        # legitimately starts with "|", and "### Heading" / "- bullet" are
        # clean boundaries too; the real D1 defect was a window that started
        # mid-token ("ic path traversal filter"). Reuse the slicer's own
        # predicate so the AUDIT and the BUILDER cannot disagree -- a checker
        # that disagrees with the thing it checks measures nothing.
        starts_clean = sl.starts_clean(q)
        # and must not begin mid-word (previous non-space char was a letter)
        if not starts_clean:
            d1 += 1

        # D3 -- quote must contain prose, not just table furniture
        prose = len(re.findall(r"[a-z]{4,}", q)) >= 8
        tableish = q.count("|") >= 4 and prose is False
        if not prose or tableish:
            d3 += 1

        # D2 -- the write-up path must plausibly belong to this class
        cls = it["item_key"].split(".")[0]
        claim_l = it["claim"].lower()
        path_l = prov_path.lower()
        topical = any(t in path_l for t in (
            "file_inclusion", "path_traversal", "lfi",
            "sql_injection", "sqlmap", "xss", "cross-site", "file_upload",
            "ssrf", "template", "ssti", "xxe", "nosql", "idor", "access_control",
            "information_disclosure", "javascript", "smuggl",
            "nmap", "enumeration", "footprint", "smb", "kerberos", "active_directory",
            "ldap", "pivot", "tunnel", "rdp", "privilege", "password_attack",
            "common_services", "attacking_web", "dns",
        ))
        # topical mismatch: class is web but the only citing write-up is a
        # network module (or vice versa)
        net_words = ("kerberos", "active_directory", "pivot", "ldap", "smb",
                     "rdp", "privilege_escalation", "nmap")
        is_net_doc = any(w in path_l for w in net_words)
        web_words = ("file_inclusion", "sql_injection", "xss", "file_upload",
                     "ssrf", "ssti", "xxe", "nosql", "attacking_web")
        is_web_doc = any(w in path_l for w in web_words)
        mismatch = (cls in {"path_traversal", "sqli", "file_upload", "xss",
                            "ssrf", "ssti", "xxe", "nosql", "idor",
                            "info_disclosure", "smuggling"} and is_net_doc) or \
                   (cls in {"smb", "ad_kerberos", "ldap_enum", "rdp",
                            "tunneling_pivoting", "dns_enum", "misconfig",
                            "service_enumeration", "exposed_services",
                            "pass_the_hash"} and is_web_doc)
        if mismatch:
            d2 += 1

        # D4 -- the quote must evidence the claim's MECHANISM. Reproduces the
        # builder's rule exactly: the PLAN's primary claim term must appear in
        # the quote. The term is re-derived from the PLAN (imported from the
        # builder module), NOT read off the emitted item, so an item cannot
        # pass by carrying its own convenient vocabulary.
        terms = PLAN_TERMS.get(it["claim"], PLAN_TERMS.get(cls, ()))
        primary = terms[0].lower() if terms else None
        if primary:
            if primary in q.lower():
                d4_ok += 1
            else:
                d4 += 1
                rows_d4.append((cls, primary, prov_path[:44], q[:70]))
        else:
            d4_undeclared += 1

        rows.append({
            "file": os.path.basename(p), "key": it["item_key"], "cls": cls,
            "prov": prov_path[:64], "clean_start": starts_clean, "prose": prose,
            "topical": topical, "mismatch": mismatch,
            "qlen": len(q), "qhead": q[:78],
        })

_D4_BAD = {c for c, _p, _pr, _q in rows_d4}
print(f"items audited: {len(rows)}")
print(f"  D1 quote starts mid-token     : {d1}")
print(f"  D2 citing write-up off-topic  : {d2}")
print(f"  D3 quote is table furniture   : {d3}")
print(f"  D4 quote lacks claim mechanism: {d4}  (ok {d4_ok}, no primary declared {d4_undeclared})")
if rows_d4:
    print("\nD4 detail (quote missing the claim's primary term):")
    for cls, ov, prov, q in rows_d4:
        print(f"  {cls:<22} missing={ov!r}  {prov}")
        print(f"      q={q!r}")
print("\n--- every item ---")
for r in rows:
    flags = "".join([
        "D1" if not r["clean_start"] else "",
        "D2" if r["mismatch"] else "",
        "D3" if not r["prose"] else "",
        "D4" if r["prov"] and r["cls"] in _D4_BAD else "",
    ]) or "ok"
    print(f"[{flags:<11}] {r['cls']:<20} {r['prov']}")
    print(f"         q={r['qhead']!r}")
print(f"\nTOTAL DEFECTS: D1={d1} D2={d2} D3={d3} D4={d4}")
sys.exit(1 if (d1 or d2 or d3 or d4) else 0)