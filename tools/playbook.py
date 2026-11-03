"""Turn a hunting skill from a knowledge dump into an executable procedure.

THE GAP THIS FILLS (measured 2026-10-04)
----------------------------------------
`skills/<domain>/<class>/SKILL.md` renders every promoted item as a
knowledge section. On `path_traversal` that is 35 techniques, of which **26
carry no action verb at all** — they read

    "By using special elements such as ".." and "/" separators, attackers can
     escape outside of the restricted location."

That is a true statement and useless at 2am. It names no request to send, no
comparison to make, and no observable to record. The skill's actual
"Hunt procedure" is three hand-written lines that cover a fraction of the
material. A hunter following the skill has to invent the mechanics for 26 of 35
entries, which is exactly the part where mistakes become false positives and
missed findings.

The fix is not more knowledge. It is a DERIVED PLAYBOOK: for each technique,
classify its shape and emit the concrete steps for that shape. Nothing here is
invented per class — the procedure templates are keyed on measurable properties
of the item (its kind, whether it names an HTTP request, a comparison, or a
filesystem effect), so the same shapes recur across classes and the templates
are auditable in one place.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
sys.path.insert(0, str(ROOT))

from wks import variation  # noqa: E402

# --------------------------------------------------------------------------
# Procedure templates, keyed on the SHAPE of the technique. Each must be a
# sequence a tester can execute with two terminals, not a description.
# --------------------------------------------------------------------------

TEMPLATES: dict[str, dict] = {
    "http_param_probe": {
        # TIGHTENED (2026-10-04, adversarial review target 2). The original
        # matched `parameter|query|request|GET|POST|url|endpoint|payload|inject|
        # fuzz|send|submit` — in a security corpus nearly every sentence contains
        # one of those, so this template won by DEFAULT and 451/600 entries
        # collapsed into it. Now it requires evidence that an HTTP parameter is
        # actually the carrier: a named method with an argument, a concrete
        # transport word, or an explicit request/parameter pairing.
        "match": r"\b(query\s+(?:parameter|param|string)|parameter\s+in\s+the\s+"
                 r"(?:url|query|body|path)|GET\s+\S+\?|POST\s+to\b|"
                 r"http\s+(?:request|parameter)|request\s+(?:body|query|parameter)|"
                 r"endpoint\s+(?:accepts|reads|takes)|url\s+parameter)\b",
        "title": "Single-parameter differential probe",
        "steps": [
            "Record the BASELINE: request the endpoint with a benign, known-good "
            "value for the parameter. Save the full response (status, length, "
            "body hash).",
            "Change exactly ONE variable: set the parameter to the attack value. "
            "Send it again with identical method, headers and cookies.",
            "DIFF the two responses on all three axes: status code, body length, "
            "and body content hash.",
            "Attribute every difference. A difference the control did not "
            "produce is the finding; a difference the control also produces is "
            "the application's normal behaviour.",
            "Then re-run the attack value THREE times to separate a real "
            "condition from per-request noise (timing, nonce, ordering).",
        ],
        "records": ["baseline response hash", "attack response hash",
                    "status delta", "body-length delta", "reproductions"],
    },
    "encoding_ladder": {
        "match": r"\b(encode|encoding|encoded|decode|percent|url-?decode|"
                 r"double-?encod|unicode|normaliz|canonicali|escape)\b",
        "title": "Encoding / normalisation ladder",
        "steps": [
            "Build the ladder BEFORE probing: raw, single-encoded, "
            "double-encoded, and over-long variants of the same logical value.",
            "Send each rung with the baseline procedure (one variable changed).",
            "Record which rung first produces an effect. That rung identifies "
            "the decoding layer the application applies, and where the check "
            "and the decode disagree.",
            "Verify WHERE normalisation happened: reflect the value in a way "
            "only the server could compute. Client-side canonicalisation proves "
            "nothing about the server.",
        ],
        "records": ["rung that first differed", "decoding layer inferred",
                    "server-side reflection evidence"],
    },
    "filesystem_sink": {
        "match": r"\b(file|filesystem|path|directory|read|open|include|"
                 r"traversal|symlink|canonical|realpath)\b",
        "title": "Filesystem sink confirmation",
        "steps": [
            "Prove the sink reads a file at all BEFORE testing traversal: fetch "
            "a file you KNOW exists on the target and confirm real content "
            "comes back.",
            "If you cannot get a known-good read, there is no traversal finding "
            "to report — the sink is not proven.",
            "Then apply the traversal value and confirm the returned content is "
            "from OUTSIDE the intended directory. Content, not status code.",
            "Reject any result where only the status line differs: proxies, "
            "error handlers and WAFs produce status differentials with no file "
            "ever read.",
        ],
        "records": ["known-good read", "outside-directory content sample",
                    "negative control (baseline vs traversal)"],
    },
    "state_change": {
        # TIGHTENED (2026-10-04): the original matched bare `state|session|
        # token|update|remove`, which is English in every security sentence, and
        # it became the top shape (31%) the moment http_param_probe stopped
        # swallowing everything. It claimed kerberoast tickets, container-exec
        # policy filters and CVE monitors — none of which is a write-then-read.
        # Now it requires the actual shape: a mutation PLUS a read-back, an
        # explicit authorisation decision, or a persistence/upload primitive.
        "match": r"\b(upload(?:ed|s)?\s+(?:file|avatar|attachment)|"
                 r"(?:write|create|update|delete|modify|persist)(?:s|d)?\s+"
                 r"(?:the|a|its|their|back\s+and)|read(?:s)?\s+it\s+back|"
                 r"re-?read|privilege\s+escalat|escalat(?:e|ion)\s+to\s+root|"
                 r"cross-?tenant|second\s+identity|access\s+control\s+decision|"
                 r"authoriz(?:ation|ed)\s+(?:is\s+)?(?:keyed|checked|decided))\b",
        "title": "State-changing verification",
        "steps": [
            "Capture the pre-state with a read-only request and record it.",
            "Perform the single state change.",
            "Read the state again THROUGH THE SAME ACCOUNT and, if a second "
            "test identity exists, through that identity too.",
            "A change visible only to the actor proves write access, not a "
            "vulnerability. Cross-account visibility is what makes it one.",
        ],
        "records": ["pre-state", "post-state (same identity)",
                    "post-state (second identity) if available"],
    },
    "race_condition": {
        "match": r"\b(race|TOCTOU|time-of-check|concurren|window|parallel|"
                 r"simultaneous|interleav)\b",
        "title": "Race / TOCTOU attempt",
        "steps": [
            "Identify the check and the use as TWO separate operations, and "
            "measure the gap between them.",
            "Fire many parallel attempts (tens to hundreds) so at least one "
            "lands inside the window.",
            "Vary ONLY the timing; the payload and session stay fixed.",
            "Report a rate, not a single success: N successes in M attempts "
            "both proves the window and tells the reader whether it is "
            "practical to exploit.",
        ],
        "records": ["attempts", "successes", "success rate", "window size if measurable"],
    },
    "blind_confirmation": {
        "match": r"\b(blind|out-of-band|OOB|callback|time-?based|dns|"
                 r"exfiltrat)\b",
        "title": "Blind / out-of-band confirmation",
        "steps": [
            "Establish that your out-of-band channel works AT ALL with a known "
            "true positive before drawing any conclusion from its absence.",
            "Then test the vulnerable condition. Absence of a callback is only "
            "meaningful once the channel is proven.",
            "Record the callback evidence (resolved host, token, timestamp) — a "
            "blind result with no artefact is not reportable.",
        ],
        "records": ["channel self-test", "callback artefact", "timing"],
    },
    "filter_bypass": {
        "match": r"\b(filter|allowlist|blocklist|deny|sanitis|sanitiz|"
                 r"WAF|blacklist|strip)\b",
        "title": "Filter-bypass ladder",
        "steps": [
            "First establish what the filter rejects: send the plain attack "
            "value and record the rejection (status, message, silence).",
            "Then vary ONE encoding dimension at a time: separators, case, "
            "trailing dots, alternate separators, redundant segments, "
            "container-level normalisation.",
            "The first variation that passes identifies the filter's matching "
            "weakness precisely — which is the finding.",
            "Confirm the bypass reaches the sink by observing an EFFECT, not by "
            "observing a different response status.",
        ],
        "records": ["plain value rejection", "bypass variant that passed",
                    "observed effect at the sink"],
    },
}

FALLBACK = {
    "title": "Claim verification (no mechanical template matched)",
    "steps": [
        "Restate the claim as an assertion about observable behaviour.",
        "Identify the ONE request that would be true if the claim holds and "
        "false if it does not.",
        "Run it with a control that differs in exactly one variable.",
        "If you cannot name the control, you cannot prove the claim — park it "
        "as unverified rather than reporting it.",
    ],
    "records": ["the discriminating request", "control", "observed result"],
}


def _existing_procedure(text: str) -> list[str]:
    """Recover steps the item ALREADY carries, instead of replacing them.

    MEASURED: several promoted `test`/`validation` items state their own
    procedure ("Step: send the identical traversal payload twice, once with
    literal ../ and once percent-encoded..."). The first version of this
    playbook ignored that and overwrote it with a generic template — losing
    specific, already-verified instructions. Item-authored steps win; the
    template only supplies what the item omits.

    The first regex used a lookahead requiring a period and matched NOTHING
    (0 hits against a body that plainly reads "Step: send the identical
    traversal payload twice, once with literal ../ sequences..."). Splitting on
    punctuation destroys a procedure that legitimately contains `../`. Split on
    sentence TERMINALS only, and cap the length instead.
    """
    steps: list[str] = []
    # MEASURED: the lazy form `.{25,300}?` combined with a `(?=Step|\Z)`
    # lookahead returned 0 hits on text that plainly reads "Step: send the
    # identical traversal payload twice, once with literal ../ sequences and
    # once with percent-encoded octets...". `\Z` is unreachable for a match
    # starting mid-string and there is no second "Step" to terminate on, so the
    # lazy quantifier had nothing to satisfy. Stop at the first sentence
    # terminal after a minimum length instead.
    for m in re.finditer(r"\bStep\s*\d*\s*:\s*(.{25,400}?)(?:\.\s|;|$)", text,
                             re.I | re.S):
        s = " ".join(m.group(1).split()).strip().rstrip(".")
        if len(s) > 25:
            steps.append(s[0].upper() + s[1:] + ".")
    return steps


def classify(claim: str, body: str) -> list[str]:
    """Which procedure shapes apply to this item, most specific first."""
    text = f"{claim} {body}".lower()
    hits = []
    for key, tpl in TEMPLATES.items():
        if re.search(tpl["match"], text):
            hits.append(key)
    # Rank so the most operational templates win; a blind-confirmation item is
    # more usefully hunted with the blind procedure than the generic one.
    order = ["http_param_probe", "filter_bypass", "encoding_ladder",
             "filesystem_sink", "state_change", "race_condition",
             "blind_confirmation"]
    hits.sort(key=lambda k: order.index(k) if k in order else 99)
    return hits or ["fallback"]


def build_playbook(class_id: str, domain: str) -> dict:
    con = sqlite3.connect(str(ROOT / "db" / "wks.db"))
    con.row_factory = sqlite3.Row
    rows = con.execute("""
        SELECT i.item_key, i.claim, i.body, i.kind, q.validation_state, q.score
        FROM item i JOIN quality q ON q.item_id = i.id
        WHERE i.class_id = ? AND i.status = 'active'
          AND q.validation_state = 'high_confidence'
          AND i.kind IN ('technique','test','variant','bypass','validation','signal')
        ORDER BY q.score DESC
    """, (class_id,)).fetchall()
    con.close()

    entries = []
    for r in rows:
        claim = r["claim"] or ""
        body = r["body"] or ""
        shapes = classify(claim, body)
        # PRIMARY shape drives the steps; the REST are carried as alternates so
        # a multi-mechanism item no longer loses the two procedures that also
        # apply to it. MEASURED: `shapes[1:]` was previously discarded entirely.
        tpl = TEMPLATES.get(shapes[0], FALLBACK)
        alternates = [{"shape": s, "procedure": TEMPLATES[s]["title"],
                       "steps": TEMPLATES[s]["steps"]}
                      for s in shapes[1:] if s in TEMPLATES]
        own = _existing_procedure(f"{claim} {body}")
        # Item-authored steps take precedence; the template fills the gaps.
        # Measured: these items author ONE compound step ("Step: send X twice,
        # once with literal ../ and once percent-encoded, and compare..."), so a
        # `>= 2 steps` bar discarded every real one and always fell back to the
        # template — which is how a specific verified procedure got replaced by
        # a generic one. One item-authored step outranks any template.
        use_own = len(own) >= 1
        steps = own if use_own else tpl["steps"]
        # VARIATION (measured 2026-10-04): 451/600 entries collapsed into one
        # procedural shape because `classify()` returned a ranked list and only
        # `[0]` was consumed. Axes are detected from the item's OWN text, so an
        # item that says nothing about encoding or transport gets no invented
        # variation -- evidence-bound, not a slot machine.
        axes = variation.detect_axes(claim, body, class_id)
        entries.append({
            "item_key": r["item_key"],
            "claim": claim,
            "score": round(r["score"] or 0, 2),
            "shapes": shapes,
            "procedure": ("item-authored procedure" if use_own else tpl["title"]),
            "steps": steps,
            "records": tpl["records"],
            "source": "item" if use_own else "template",
            "axes": axes,
            "variation": variation.variation_block(axes),
            "escalation": variation.escalation(axes),
            "alternate_procedures": alternates,
        })
    # The audit travels WITH the artifact, so a cosmetic playbook is visible to
    # whoever reads it rather than hidden in a log.
    audit = variation.audit_variation(entries)
    return {"class_id": class_id, "domain": domain,
            "generated_from": "promoted items only",
            "entry_count": len(entries), "entries": entries,
            "variation_audit": audit}


def main() -> int:
    # `--all` regenerates every class. MEASURED: write_hunt_docs.py invoked this
    # script with NO arguments expecting a bulk rebuild; the usage branch exited
    # 2, the JSON files were never rewritten, and the downstream writer reported
    # "0 written" while the on-disk playbooks stayed stale. A silent no-op that
    # looks like a successful idempotent run — the exact failure class this
    # whole session has been fixing.
    if len(sys.argv) > 1 and sys.argv[1] in ("--all", "-A"):
        import sqlite3 as _s
        con = _s.connect(str(ROOT / "db" / "wks.db"))
        con.row_factory = _s.Row
        ids = [r[0] for r in con.execute(
            "SELECT DISTINCT class_id FROM item WHERE status='active' "
            "AND kind IN ('technique','test','variant','bypass','validation','signal')")]
        # The domain MUST come from the db's own routing. MEASURED: this loop
        # hardcoded "web", so every network class was written to `web-<cid>.json`
        # and a stale `network-<cid>.json` from an earlier run kept winning in
        # write_hunt_docs (which globs `<domain>-<cid>.json` and takes the first
        # hit). Result: 30 classes silently regenerated a playbook built from the
        # wrong routing while the audit reported them as unchanged.
        dom = {r["class_id"]: r["domain"] for r in con.execute(
            "SELECT class_id, domain FROM class_domain")}
        con.close()
        n = 0
        for cid in ids:
            d = dom.get(cid, "web")
            pb = build_playbook(cid, d)
            # remove a stale duplicate under a different domain prefix
            for other in ROOT.glob("runtime/loop/playbooks/*-%s.json" % cid):
                if other.stem.split("-", 1)[0] != d:
                    other.unlink()
                    md = other.with_suffix(".md")
                    if md.exists():
                        md.unlink()
            out = ROOT / "runtime" / "loop" / "playbooks" / f"{d}-{cid}.json"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(pb, indent=2, ensure_ascii=False),
                           encoding="utf-8")
            n += 1
        print(f"regenerated {n} playbook(s)")
        return 0
    if len(sys.argv) < 2:
        print("usage: playbook.py <class_id> [domain] | --all")
        return 2
    class_id = sys.argv[1]
    domain = sys.argv[2] if len(sys.argv) > 2 else "web"
    pb = build_playbook(class_id, domain)

    out = ROOT / "runtime" / "loop" / "playbooks" / f"{domain}-{class_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(pb, indent=2, ensure_ascii=False), encoding="utf-8")

    # Also render a readable hunting card, because a JSON file is not something
    # anyone reads at 2am.
    md = [f"# Hunt card — {class_id}", "",
          f"{pb['entry_count']} promoted technique/test items, each mapped to an "
          f"executable procedure derived from its shape.", ""]
    for e in pb["entries"]:
        md += [f"## {e['item_key']}", "", f"**Claim.** {e['claim']}", "",
               f"**Procedure — {e['procedure']}** "
               f"(shapes: {', '.join(e['shapes'])})", ""]
        md += [f"{i}. {s}" for i, s in enumerate(e["steps"], 1)]
        md += ["", f"**Record:** {', '.join(e['records'])}", ""]
    mdp = ROOT / "runtime" / "loop" / "playbooks" / f"{domain}-{class_id}.md"
    mdp.write_text("\n".join(md), encoding="utf-8")

    print(f"{class_id}: {pb['entry_count']} entries -> {mdp.name}")
    from collections import Counter
    for shape, n in Counter(e["shapes"][0] for e in pb["entries"]).most_common():
        print(f"    {shape:22} {n}")
    src = Counter(e["source"] for e in pb["entries"])
    print(f"    step source: item-authored={src['item']} template={src['template']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())