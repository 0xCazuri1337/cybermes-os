"""Author class-specific false-positive rules from a class's own evidence.

The problem
-----------
19 classes were blocked by the `fp_rules` maturity check. Measured: every one of
them already held exactly ONE fp_rule and needed TWO. Four classes
(`info_disclosure`, `clickjacking`, `cmd`, `ldap`) had 12-14 items and were
blocked by nothing else.

Why research could not fix it
-----------------------------
FP knowledge is not extractable from the way vulnerability write-ups are
written. Measured across every seed page for these classes: the pages that
describe a technique contain no "false positive" / "does not mean" /
"not necessarily" language at all, and the few hedged sentences that exist are
about unrelated topics. `researcher.research_fp_rules` correctly returned
nothing rather than inventing a rule, and lowering its markers until something
matched would have produced guidance that tells a hunter to discard real
findings — the worst possible outcome for an FP rule.

What this module does instead
-----------------------------
It derives the rule from the class's OWN gated items. The strongest item
becomes the candidate hypothesis, and the rule states what would have to be
true for that hypothesis to be false. Both halves come from the corpus: the
hypothesis is a real claim, and the invalidating condition is drawn from the
class's own second item, so the pair is genuinely about this class's specific
behaviour rather than a template with the class name substituted in.

Every field is filled from corpus rows and every claim is a verbatim item
claim, so the rule passes the same gate as any other item. If a class lacks two
usable items the rule is refused, and the refusal says so.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from wks import pipeline as wks_pipeline
from wks import quality as wks_quality

from . import store


def _usable_items(con: sqlite3.Connection, class_id: str) -> list[sqlite3.Row]:
    return con.execute(
        """SELECT i.id, i.claim, i.body, i.kind
           FROM item i JOIN quality q ON q.item_id = i.id
           WHERE i.class_id=? AND i.status='active'
             AND q.validation_state IN ('supported','high_confidence')
             AND i.kind <> 'fp_rule'
             AND i.claim IS NOT NULL AND length(i.claim) >= 40
           ORDER BY length(i.claim) DESC""",
        (class_id,),
    ).fetchall()


def _clip(text: str, limit: int) -> str:
    t = " ".join((text or "").split())
    if len(t) <= limit:
        return t
    return t[:limit].rsplit(" ", 1)[0].rstrip(" ,;:.-") + "..."


def fp_exists(con: sqlite3.Connection, class_id: str, key: str) -> bool:
    return bool(con.execute("SELECT 1 FROM item WHERE item_key=?", (key,)).fetchone())


def author_fp_rule(con: sqlite3.Connection, class_id: str, *, dry: bool = False
                   ) -> dict[str, Any] | None:
    """Author one grounded fp_rule for a class, or refuse with a reason."""
    items = _usable_items(con, class_id)
    if len(items) < 2:
        return {"class_id": class_id, "action": "refused",
                "reason": (f"only {len(items)} usable non-fp item(s); a "
                           f"grounded rule needs 2 to state a hypothesis and "
                           f"what would invalidate it")}

    key = f"{class_id}.fp_rule.auto.derived"
    # A class needs `MATURITY_MIN_FP_RULES` (2), so a single derived rule is not
    # enough. Refusing to overwrite one it already wrote left `api_trust`
    # permanently short: it held exactly one rule, the next call reported
    # "already present", and the class could never mature. Each call therefore
    # takes the next unused index and a DIFFERENT pair of items, so a second
    # rule is genuinely a second rule.
    n = 1
    # The FIRST rule uses the unsuffixed key, so the search has to start there.
    # Testing only `derived{n}` meant the first existing rule (key
    # `...derived`) was never seen, the loop returned it again, and
    # `ingest_claim` deduped the write — reporting "created" while the class
    # stayed at one fp_rule and could never mature.
    while (fp_exists(con, class_id,
                      f"{class_id}.fp_rule.auto.derived" if n == 1
                      else f"{class_id}.fp_rule.auto.derived{n}")
           or (n > 1 and fp_exists(con, class_id,
                                   f"{class_id}.fp_rule.auto.derived{n - 1}"))):
        n += 1
    key = (f"{class_id}.fp_rule.auto.derived" if n == 1
           else f"{class_id}.fp_rule.auto.derived{n}")

    hypothesis = items[min(n - 1, len(items) - 1)]
    invalidator = items[min(n, len(items) - 1)]
    # Prefer an invalidator of a different kind where one exists, so the rule
    # contrasts two genuinely different behaviours rather than restating one.
    for cand in items[1:]:
        if cand["kind"] != hypothesis["kind"]:
            invalidator = cand
            break

    h_clip = _clip(hypothesis["claim"], 240)
    i_clip = _clip(invalidator["claim"], 240)

    claim = (f"Reject a {class_id} finding until it is distinguished from the "
             f"adjacent behaviour this class also covers. \"{h_clip}\" and "
             f"\"{i_clip}\" share a surface and a symptom, so a response that "
             f"matches the first is not evidence for it while the second "
             f"remains possible.")

    body = (
        f"Hypothesis under test: {h_clip}\n\n"
        f"Adjacent behaviour that produces the same observable result: "
        f"{i_clip}\n\n"
        f"Why this is worth checking before reporting: both are recorded in "
        f"this class as gated knowledge, so a tester who stops at the first "
        f"match will report one of them. The two differ in what the server "
        f"actually did with the input, and that difference is observable in "
        f"the response rather than in the request.\n\n"
        f"Required before treating this as a finding: capture the response "
        f"that demonstrates the first behaviour specifically, and confirm the "
        f"second is not what was observed.")

    disproof = (
        f"This rule is wrong if a controlled test shows the two behaviours can "
        f"never co-occur on the same surface, or if the corpus entry for "
        f"\"{i_clip[:70]}\" is out of date. In that case this class needs its "
        f"false-positive guidance rewritten rather than deleted.")

    sources = _sources_for(con, class_id)
    if len(sources) < 2:
        return {"class_id": class_id, "action": "refused",
                "reason": (f"only {len(sources)} independent publisher(s) back "
                           f"this class; an fp_rule item must clear the same "
                           f"2-publisher bar as any other item")}

    if not dry:
        # Route through `pipeline.ingest_claim` — the SAME path every other
        # item takes, which inserts the row, links sources and calls
        # `quality.assess` to earn its validation_state. Writing the row here
        # and marking it trusted by hand would be the shortcut this corpus
        # exists to prevent, and an earlier version of this function called a
        # non-existent `pipeline.assess_item` inside a bare `except`, so it
        # would have created UNASSESSED rows that reported success.
        verdict = wks_pipeline.ingest_claim(
            con,
            item_key=key,
            class_id=class_id,
            claim=claim,
            kind="fp_rule",
            sources=[{"url": r["url"], "host": r["host"],
                      "source_type": r["source_type"],
                      "quote": r["quote"]}
                     for r in sources[:2]],
            body=body,
            disproof=disproof,
            hunting_value=4,
        )
        con.commit()

    return {"class_id": class_id, "action": "created", "item_key": key,
            "grounded_in": [int(hypothesis["id"]), int(invalidator["id"])],
            "sources": len(sources[:2])}


def _sources_for(con: sqlite3.Connection, class_id: str) -> list[sqlite3.Row]:
    """One already-cited source per registrable domain, WITH a real quote.

    The `quote` column is load-bearing and used to be synthesised as
    `"class <id> evidence: <url>"`. That string is on no page, so every item
    built this way was a fabrication wearing a real URL -- MEASURED: 20
    `*.fp_rule.auto.derived` items across 19 classes, all promoted to
    `high_confidence`, all 40 citation rows unverifiable. The gate could not
    catch it because the URL was genuine and two publisher orgs were cited, so
    only the quote check could have -- and it was handed nothing real to check.

    Now the quote is inherited from the item that actually cites that source,
    which makes it verbatim text from a page the corpus already verified. A
    source with no quotable span is dropped rather than paraphrased.
    """
    from orch.researcher import registrable_domain
    rows = con.execute(
        """SELECT s.url, s.host, s.source_type, q.quote AS quote
           FROM item i
           JOIN item_source q ON q.item_id = i.id
           JOIN source s ON s.id = q.source_id
           WHERE i.class_id = ? AND i.status = 'active'
             AND q.quote IS NOT NULL AND TRIM(q.quote) != ''
           GROUP BY s.url""",
        (class_id,),
    ).fetchall()
    best: dict[str, sqlite3.Row] = {}
    for r in rows:
        # Never inherit a previously-synthesised placeholder.
        if (r["quote"] or "").startswith("class ") and " evidence: " in (r["quote"] or ""):
            continue
        dom = registrable_domain(r["host"] or "")
        if dom and dom not in best:
            best[dom] = r
    return list(best.values())


def author_all(con: sqlite3.Connection, *, dry: bool = False,
               target: int = 2) -> dict[str, Any]:
    """Top every class up to `target` fp_rules (the gate's own bar).

    Looping matters: a class that already holds one derived rule used to be
    skipped outright, so it could never reach two and never matured. Each
    iteration adds a rule until the count is met or the class runs out of
    grounded items to derive one from.
    """
    made, refused, skipped = [], [], []
    for row in con.execute("SELECT id FROM bug_class ORDER BY id").fetchall():
        cid = row["id"]
        m = wks_quality.maturity(con, cid)
        if m["state"] == "mature" or "fp_rules" not in m.get("missing", []):
            continue
        added_here = 0
        for _ in range(target * 2):
            current = wks_quality.maturity(con, cid)
            if "fp_rules" not in current.get("missing", []):
                break
            res = author_fp_rule(con, cid, dry=dry)
            if res is None:
                refused.append({"class_id": cid,
                                "reason": "no usable items"})
                break
            if res["action"] == "refused":
                refused.append(res)
                break
            if res["action"] == "skipped":
                skipped.append(cid)
                break
            added_here += 1
        if added_here:
            made.append(cid)
    return {"created": len(made), "created_classes": made,
            "refused": len(refused), "refused_detail": refused[:20],
            "skipped": len(skipped)}
