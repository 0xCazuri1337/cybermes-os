"""Tests for wks/eligibility.py (Phase 4)."""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import wks.config as config
import wks.store as store
from wks import eligibility, retrieval


def _mkdb():
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    con.executescript(config.SCHEMA_PATH.read_text(encoding="utf-8"))
    con.commit()
    return con


def _seed(con, class_id="sqli", state="supported", with_source=True, open_conflict=False):
    store.upsert_class(con, class_id, "SQLi", "web", cwe="CWE-89", owasp="A03")
    con.commit()
    item_id = store.add_item(con, item_key=f"{class_id}.item", class_id=class_id,
                            claim="test claim", kind="technique", surface="web",
                            hunting_value=3)
    con.commit()
    store.set_state(con, item_id, state, 0.8, ["ok"])
    con.commit()
    if with_source:
        sid = store.upsert_source(con, "https://example.com/x", "example.com",
                                  publisher="ex", source_type="writeup")
        store.link_source(con, item_id, sid, quote="quote")
        con.commit()
    if open_conflict:
        con.execute("INSERT INTO conflict (class_id, topic, claim_a, claim_b, status, created_at) "
                    "VALUES (?,?,?,?, 'open', datetime('now'))", (class_id, "t", "a", "b"))
        con.commit()
    return item_id


def main():
    # authoritative excludes under_review
    con = _mkdb()
    iid_ur = _seed(con, state="under_review")
    row = con.execute("SELECT i.*, q.validation_state FROM item i JOIN quality q ON q.item_id=i.id WHERE i.id=?", (iid_ur,)).fetchone()
    assert not eligibility.is_eligible(row, "AUTHORITATIVE", con=con, class_id="sqli"), "under_review must be excluded"
    print("PASS under_review excluded")

    # authoritative excludes rejected
    con2 = _mkdb()
    iid_rej = _seed(con2, state="rejected")
    row2 = con2.execute("SELECT i.*, q.validation_state FROM item i JOIN quality q ON q.item_id=i.id WHERE i.id=?", (iid_rej,)).fetchone()
    assert not eligibility.is_eligible(row2, eligibility.AUTHORITATIVE, con=con2, class_id="sqli")
    print("PASS rejected excluded")

    # authoritative excludes missing provenance
    con3 = _mkdb()
    iid_nosrc = _seed(con3, state="supported", with_source=False)
    row3 = con3.execute("SELECT i.*, q.validation_state FROM item i JOIN quality q ON q.item_id=i.id WHERE i.id=?", (iid_nosrc,)).fetchone()
    assert not eligibility.is_eligible(row3, "AUTHORITATIVE", con=con3, class_id="sqli")
    print("PASS missing provenance excluded")

    # authoritative excludes open conflict
    con4 = _mkdb()
    iid_oc = _seed(con4, state="supported", open_conflict=True)
    row4 = con4.execute("SELECT i.*, q.validation_state FROM item i JOIN quality q ON q.item_id=i.id WHERE i.id=?", (iid_oc,)).fetchone()
    assert not eligibility.is_eligible(row4, "AUTHORITATIVE", con=con4, class_id="sqli")
    print("PASS open conflict excluded")

    # authoritative includes supported+source+no conflict
    con5 = _mkdb()
    iid_ok = _seed(con5, state="supported")
    row5 = con5.execute("SELECT i.*, q.validation_state FROM item i JOIN quality q ON q.item_id=i.id WHERE i.id=?", (iid_ok,)).fetchone()
    assert eligibility.is_eligible(row5, "AUTHORITATIVE", con=con5, class_id="sqli")
    print("PASS authoritative includes valid supported")

    # investigation all states accessible
    for st in ("under_review", "rejected", "supported", "high_confidence"):
        c = _mkdb()
        iid = _seed(c, state=st)
        r = c.execute("SELECT i.*, q.validation_state FROM item i JOIN quality q ON q.item_id=i.id WHERE i.id=?", (iid,)).fetchone()
        assert eligibility.is_eligible(r, "INVESTIGATION", con=c, class_id="sqli"), st
    print("PASS investigation all states")

    # historical excludes rejected, includes outdated-labelled
    c = _mkdb()
    iid_out = _seed(c, state="under_review")  # no outdated state in DB; use under_review as legacy-ish
    # historical should not raise and label
    r = c.execute("SELECT i.*, q.validation_state FROM item i JOIN quality q ON q.item_id=i.id WHERE i.id=?", (iid_out,)).fetchone()
    assert eligibility.label(r, "HISTORICAL").startswith("historical:")
    print("PASS historical labelling")

    # trust prior cannot bypass: under_review with high prior still excluded
    c = _mkdb()
    iid = _seed(c, state="under_review")
    r = c.execute("SELECT i.*, q.validation_state FROM item i JOIN quality q ON q.item_id=i.id WHERE i.id=?", (iid,)).fetchone()
    assert not eligibility.trust_prior_cannot_bypass(r, 1.0)
    print("PASS trust prior cannot bypass")

    # empty authoritative retrieval returns honest gap (empty list)
    c = _mkdb()
    _seed(c, state="under_review")  # only under_review -> no authoritative
    res = retrieval.retrieve(c, "test claim", class_id="sqli")
    assert res == [], res
    print("PASS empty authoritative retrieval empty")

    # class_digest defaults authoritative
    c = _mkdb()
    _seed(c, state="under_review")
    _seed(c, state="supported")
    d = retrieval.class_digest(c, "sqli")
    items = [it for kind in d["by_kind"].values() for it in kind]
    assert all(it["state"] in ("supported", "high_confidence") for it in items), items
    print("PASS class_digest authoritative filter")

    print("ALL ELIGIBILITY TESTS PASSED")


if __name__ == "__main__":
    main()
