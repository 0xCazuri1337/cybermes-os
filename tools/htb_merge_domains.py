"""htb_merge_domains.py -- RETIRED. Report-only; it no longer writes files.

It used to render domains/web/htb-techniques.md and domains/network/
htb-techniques.md as a flat "cross-class synthesis" page. MEASURED: every claim
those pages quoted (13 in web) was ALREADY present in the owning class page under
domains/, so 0 pieces of knowledge existed only there, and the file's unique
content was one ordering sentence plus a class list.

The user was right that it did not belong: the corpus convention is one canonical
home per class, and a flat dump duplicating 21KB of class knowledge is the R14
violation in its pure form. So the WRITER is gone, not just the output -- deleting
a file a tool still regenerates is the stale-page defect with extra steps.

Kept as a REPORT because the measurement is still useful: it lists the
write-up-provenance items per domain with their class homes. It writes nothing.
"""
import json
import os
import re
import sqlite3
import sys

sys.path.insert(0, ".")
from wks import config
from wks.domains import domain_of

# technique kinds that render into a CLASS.md section, and where
KIND_SECTION = {
    "prerequisite": "Preconditions", "signal": "Detection",
    "technique": "Exploitation", "bypass": "Variations",
    "validation": "Validation", "impact": "Impact",
    "fp_rule": "Common False Positives",
}
PRIORITY = ["bypass", "technique", "signal", "prerequisite", "validation",
            "impact", "fp_rule"]

HEADER = """# {label} techniques from public HTB write-ups

> **Cross-class synthesis — not the canonical home.** Every technique below is
> a POINTER. The authoritative treatment (definition, preconditions, detection,
> validation, false positives, disproof) lives in the class page linked from
> each entry: `{pagemd}`.
>
> Rendered from `db/wks.db` by `tools/htb_merge_domains.py`. Do not hand-edit:
> edit the rows, re-run the generator.

These are the techniques an operator actually meets on Hack The Box machines.
Each entry pairs a public write-up -- which proves the technique works **in a
real engagement** -- with a normative source (PortSwigger / OWASP / MITRE
ATT&CK / RFC / vendor docs) that carries the **mechanism**. A write-up alone
can never promote an item: one person's account of one box is not evidence.

Nothing on this page predates the harvest. The wider corpus this domain draws
on is much larger and is not repeated here; only items carrying an explicit
`Write-up provenance:` record appear below.

## How to read this

Each entry gives the technique, what it looks like in practice (verbatim from
the write-up), and the sources behind the claim. Confidence words are load
bearing: *"proved"* means a differential or a served artefact, *"suggested"*
means an indicator that needs the differential before it is a finding.

"""

FIELDS = {
    "web": {
        "label": "Web",
        "page": "domains/web/README.md",
        "intro": "Browser-and-server HTTP surfaces, ordered the way a write-up "
                 "walked them.",
    },
    "network": {
        "label": "Network + AD",
        "page": "domains/network/README.md",
        "intro": "Service enumeration, credential access and lateral movement, "
                 "ordered the way a write-up walked them.",
    },
}


def norm_url(u):
    return u


def collect(con, domain):
    """The items THIS WAVE contributed, routed to one domain.

    MEASURED: filtering on `source.host LIKE '%githubusercontent%'` looks right
    and is WRONG. 110 items cite a githubusercontent source, but only 22 of them
    came from this harvest -- the other 88 are pre-existing corpus items that
    happen to cite GitHub too. A page built on that filter claimed "101 items
    harvested from HTB write-ups" and was simply false: it attributed a decade
    of existing knowledge to this work.

    The honest discriminator is the `Write-up provenance:` marker the BUILDER
    writes into every item body, naming the repo and path it sliced. That
    marker is provenance, not a heuristic, so it is what the query keys on.
    """
    out = []
    for r in con.execute("""
        SELECT i.item_key, i.kind, i.claim, i.body, i.disproof, i.id
          FROM item i
         WHERE i.status = 'active'
           AND i.body LIKE '%Write-up provenance:%'
    """):
        cid = r["item_key"].split(".")[0]
        try:
            if domain_of(con, cid) != domain:
                continue
        except KeyError:
            continue
        srcs = []
        # `quote` lives on item_source, NOT on evidence (evidence is an
        # engagement-artefact table: request_raw/response_raw/sha256). Joining
        # evidence here was a guessed schema and raised
        # "no such column: e.quote".
        for sr in con.execute("""
            SELECT s.url, s.host FROM item_source isr
              JOIN source s ON s.id = isr.source_id
             WHERE isr.item_id = ?""", (r["id"],)):
            srcs.append({"url": sr["url"], "org": config.publisher_org(sr["host"])})
        # de-dup by org, keep the first url of each
        seen, keep = set(), []
        for s in srcs:
            if s["org"] in seen:
                continue
            seen.add(s["org"])
            keep.append(s)
        out.append({"key": r["item_key"], "cid": cid, "kind": r["kind"],
                    "claim": r["claim"], "body": r["body"] or "",
                    "disproof": r["disproof"] or "", "srcs": keep})
    return out


def practice(body):
    """The verbatim 'in practice' span the builder recorded, if present."""
    m = re.search(r"In practice on HTB this shows up as:\s*(.+?)(?:\n\n|Write-up provenance)",
                  body, re.S)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else ""


def provenance(body):
    m = re.search(r"Write-up provenance:\s*(\S+)\s*::\s*(.+?)\s*\((\d+) words",
                  body)
    return (m.group(1), m.group(2).strip(), m.group(3)) if m else ("", "", "")


def render(domain, items, corpus):
    f = FIELDS[domain]
    o = [HEADER.format(label=f["label"], pagemd=f["page"])]
    o.append(f"_{f['intro']}_\n\n")

    by_class = {}
    for it in items:
        by_class.setdefault(it["cid"], []).append(it)

    # order classes by how much practice evidence each has
    ranked = sorted(by_class.items(), key=lambda kv: -len(kv[1]))
    o.append("## Classes covered\n")
    o.append("| Class | Techniques | Canonical page |")
    o.append("|---|---|---|")
    for cid, its in ranked:
        link = f"`domains/{domain}/{cid}/knowledge/CLASS.md`"
        o.append(f"| `{cid}` | {len(its)} | {link} |")
    o.append("")

    for cid, its in ranked:
        o.append(f"### `{cid}`")
        o.append("")
        o.append(f"Canonical: `domains/{domain}/{cid}/knowledge/CLASS.md` — "
                 f"read that for the full treatment.")
        o.append("")
        its.sort(key=lambda i: PRIORITY.index(i["kind"])
                 if i["kind"] in PRIORITY else 99)
        for it in its:
            o.append(f"**{it['claim']}**")
            o.append("")
            pr = practice(it["body"])
            if pr:
                o.append(f"> {pr}")
                o.append("")
            repo, path, words = provenance(it["body"])
            if repo:
                o.append(f"- *Seen in practice:* `{repo}` :: `{path}` ({words} words)")
            o.append(f"- *Kind:* `{it['kind']}` → "
                     f"{KIND_SECTION.get(it['kind'], 'see class page')}")
            if it["srcs"]:
                o.append("- *Evidence:* " + ", ".join(
                    f"[{s['org']}]({norm_url(s['url'])})" for s in it["srcs"]))
            if it["disproof"]:
                d = re.sub(r"\s+", " ", it["disproof"]).strip()
                o.append(f"- *Refuted when:* {d}")
            o.append("")

    return "\n".join(o)


def main():
    con = sqlite3.connect("db/wks.db")
    con.row_factory = sqlite3.Row
    corpus = json.load(open("research/htb_corpus.json", encoding="utf-8"))

    written = {}
    for domain in ("web", "network"):
        items = collect(con, domain)
        if not items:
            print(f"  {domain}: NO ITEMS -- refusing to write an empty page")
            continue
        path = None  # RETIRED: no file is written
        text = render(domain, items, corpus)
        if path is None:
            print("RETIRED: domains/{web,network}/<class>/knowledge/CLASS.md is not written; the class pages under"
                  "are the canonical home. This tool reports only.")
            return
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text.rstrip() + "\n")
        written[domain] = (path, len(items), text)

    # ---- ASSERT THE RENDER AGAINST THE DB -----------------------------
    bad = []
    for domain, (path, n, text) in written.items():
        for it in collect(con, domain):
            frag = " ".join(it["claim"].lower().split())[:55]
            if frag not in " ".join(text.lower().split()):
                bad.append((domain, it["key"]))
        print(f"  {path:<42} {n:>3} items  {len(text):>7,} chars")

    print(f"\nassertion: {sum(v[1] for v in written.values())} items rendered, "
          f"{len(bad)} missing from the page")
    for d, k in bad:
        print(f"   MISSING in {d}: {k}")
    if bad:
        print("\nA generator that silently drops knowledge is the same defect as "
              "a stale page. Aborting loudly.")
        return 1

    # link it from the domain README so it is discoverable
    for domain, (path, _, _) in written.items():
        rd = os.path.join("domains", domain, "README.md")
        txt = open(rd, encoding="utf-8").read()
        line = f"- [HTB techniques (cross-class synthesis)]({os.path.basename(path)})"
        if "htb-techniques.md" not in txt:
            txt = txt.rstrip("\n") + "\n\n## Cross-class synthesis\n\n" + line + "\n"
            with open(rd, "w", encoding="utf-8", newline="\n") as f:
                f.write(txt)
            print(f"  linked into {rd}")
    return 0


if __name__ == "__main__":
    sys.exit(main())