"""w11: read-only measurement of WEB-domain evidence diversity.

Counts distinct PUBLISHER ORGS per class (via config.publisher_org), not
hosts. Read-only: opens db/wks.db in mode=ro, never writes.
"""
import json
import os
import sqlite3
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(os.environ.get("WKS_ROOT", r"C:/Users/Administrator/.hermes/cyber"))
sys.path.insert(0, str(ROOT))
from wks.config import publisher_org  # noqa: E402

DB = ROOT / "db" / "wks.db"
WEB_DIR = ROOT / "skills" / "web"


def web_classes() -> list:
    return sorted(
        p.name for p in WEB_DIR.iterdir()
        if p.is_dir() and p.name not in {"areas", "chains", "methodology", "topics"}
    )


def main() -> None:
    con = sqlite3.connect(f"file:{DB.as_posix()}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row

    classes = web_classes()

    # items per class (all states) and promoted/active states
    items = defaultdict(list)
    for r in con.execute("SELECT id, class_id, status, claim, body, disproof FROM item"):
        items[r["class_id"]].append(r)

    # item -> sources
    isrc = defaultdict(list)
    for r in con.execute("SELECT item_id, source_id, quote, locator FROM item_source"):
        isrc[r["item_id"]].append(r)

    src = {}
    for r in con.execute("SELECT * FROM source"):
        src[r["id"]] = r

    # quality vectors
    qual = {}
    for r in con.execute("SELECT * FROM quality"):
        qual[r["item_id"]] = r

    # fp rules per class
    fp = defaultdict(int)
    for r in con.execute("SELECT class_id, COUNT(*) c FROM fp_case GROUP BY class_id"):
        fp[r["class_id"]] = r["c"]

    # chains per class
    chn = defaultdict(int)
    for r in con.execute("SELECT class_id, COUNT(DISTINCT chain_id) c FROM chain_step GROUP BY class_id"):
        chn[r["class_id"]] = r["c"]

    ev = defaultdict(int)
    for r in con.execute("SELECT class_id, COUNT(*) c FROM evidence GROUP BY class_id"):
        ev[r["class_id"]] = r["c"]

    rows = []
    for cid in classes:
        its = items.get(cid, [])
        src_ids = set()
        orgs = set()
        hosts = set()
        per_item_orgs = []
        quote_lens = []
        body_lens = []
        for it in its:
            o = set()
            for s in isrc.get(it["id"], []):
                src_ids.add(s["source_id"])
                sr = src.get(s["source_id"])
                if sr:
                    orgs.add(publisher_org(sr["host"]))
                    hosts.add(sr["host"])
                o.add(publisher_org(sr["host"]) if sr else "")
                quote_lens.append(len(s["quote"] or ""))
            per_item_orgs.append(len({x for x in o if x}))
            body_lens.append(len(it["body"] or ""))
            if not it["body"] or len(it["body"] or "") < 200:
                pass

        # min corroboration across items: the floor the gate enforces per item
        min_item_orgs = min(per_item_orgs) if per_item_orgs else 0
        single_org_items = sum(1 for n in per_item_orgs if n < 2)

        # quality vector means
        qv = [qual[i["id"]] for i in its if i["id"] in qual]
        def m(f):
            vals = [q[f] for q in qv if q[f] is not None]
            return round(sum(vals) / len(vals), 3) if vals else None

        # sources referenced but with no access measurement
        no_access = [
            src[i]["id"] for i in src_ids
            if src.get(i) and (not src[i]["access_checked_at"] or not src[i]["content_hash"])
        ]
        blocked = [
            src[i]["id"] for i in src_ids
            if src.get(i) and src[i]["access_state"] not in ("ACTIVE", None)
        ]

        rows.append({
            "class_id": cid,
            "items": len(its),
            "sources": len(src_ids),
            "orgs": len({x for x in orgs if x}),
            "org_list": sorted({x for x in orgs if x}),
            "hosts": len(hosts),
            "host_list": sorted(hosts),
            "min_item_orgs": min_item_orgs,
            "single_org_items": single_org_items,
            "fp": fp.get(cid, 0),
            "chains": chn.get(cid, 0),
            "evidence_rows": ev.get(cid, 0),
            "med_quote": sorted(quote_lens)[len(quote_lens) // 2] if quote_lens else 0,
            "min_quote": min(quote_lens) if quote_lens else 0,
            "q_corroboration": m("corroboration"),
            "q_evidence_strength": m("evidence_strength"),
            "q_reproducibility": m("reproducibility"),
            "q_real_world_demo": m("real_world_demo"),
            "q_limitations": m("limitations_documented"),
            "q_recency": m("recency"),
            "q_source_cred": m("source_credibility"),
            "q_tech_spec": m("technical_specificity"),
            "q_practical": m("practical_usefulness"),
            "q_score": m("score"),
            "sources_unmeasured": len(no_access),
            "sources_blocked": len(blocked),
        })

    out = ROOT / "validation" / "w11_web_quality_measurement.json"
    out.write_text(json.dumps(rows, indent=1), encoding="utf-8")
    print(f"wrote {out} with {len(rows)} web classes")
    for r in sorted(rows, key=lambda x: (x["orgs"], x["items"])):
        print(f"{r['class_id']:26s} items={r['items']:3d} src={r['sources']:2d} "
              f"orgs={r['orgs']} hosts={r['hosts']:2d} minItemOrgs={r['min_item_orgs']} "
              f"singleOrgItems={r['single_org_items']:3d} qcorrob={r['q_corroboration']} "
              f"qevid={r['q_evidence_strength']} qrepro={r['q_reproducibility']} "
              f"qdemo={r['q_real_world_demo']}")


if __name__ == "__main__":
    main()
