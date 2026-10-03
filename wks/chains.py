"""Attack chains (brief §10).

Chains are first-class rows, not prose buried in a class document. Every step
carries a `why`, because an unjustified chain is a story, and a story in a
knowledge base is worse than no chain at all.

Chains here are assembled from items that are actually IN the corpus and already
passed the gate. A step may not reference an item_key that does not exist — that
constraint is what stops a plausible-sounding chain from being invented.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import store  # noqa: E402

# (chain_key, name, goal, summary, impact, [(item_key, action, why, needs)])
CHAINS = [
    (
        "idor-to-account-takeover",
        "IDOR on a password/session object to account takeover",
        "account_takeover",
        "An object-level authorization flaw on an endpoint that returns or mutates "
        "authentication material is a full account takeover rather than an "
        "information leak, because the disclosed object IS the credential.",
        "Complete compromise of arbitrary user accounts; password reset on any "
        "user by writing the reset object belonging to them.",
        [
            ("idor.prereq.client_controlled_object_identifier",
             "Locate an endpoint whose path or body carries a client-supplied "
             "object identifier for an authentication-adjacent resource",
             "Every later step requires an identifier the client chooses; without "
             "one there is no object to enumerate.",
             "an endpoint referencing a password reset, session, refresh token, "
             "email change or MFA record by id"),
            ("idor.technique.swap_identifier_all_carriers",
             "Swap that identifier for one belonging to another account and record "
             "what comes back",
             "If the server does not re-check ownership per object, the response "
             "carries the other account's data.",
             "two accounts you control"),
            ("idor.validation.two_account_cross_tenant_read",
             "Confirm the read crosses the tenant boundary using your own two "
             "accounts, capturing both responses side by side",
             "Reading your own second account proves the authorization boundary "
             "is missing without involving anyone but yourself — this is what "
             "makes the finding reportable rather than theoretical.",
             "two accounts with distinct data"),
            ("idor.chain_link.to_account_takeover_and_privesc",
             "Escalate the read into a write: attempt to change the reset token, "
             "email or MFA state on the object you reached",
             "A read that crosses tenants is often the same missing check on the "
             "mutating verb; if it holds, the leak becomes takeover.",
             None),
        ],
    ),
    (
        "oauth-open-redirect-to-ato",
        "OAuth redirect_uri validation failure to account takeover",
        "account_takeover",
        "When the authorization server's redirect_uri check is a prefix or "
        "substring match rather than an exact origin match, an attacker who "
        "controls any path on an allowed host can receive the authorization code "
        "and complete the flow themselves.",
        "Full account takeover of any user who follows a crafted authorize link.",
        [
            ("oauth.prereq.authorize_endpoint_live",
             "Obtain the live authorize endpoint and its exact accepted parameters",
             "The redirect_uri check can only be probed once the real endpoint and "
             "its registered values are known.",
             None),
            ("oauth.signal.implicit_grant_or_leaked_secret",
             "Determine whether the client is public (no secret) and whether PKCE "
             "is enforced",
             "A public client without PKCE means an intercepted code is "
             "redeemable by anyone, so the redirect_uri weakness is fully "
             "exploitable rather than theoretical.",
             None),
            ("oauth.fp.redirect_host_exact_match",
             "Test redirect_uri variants and reject any that is not accepted: "
             "subdomain, suffix, path traversal and encoded forms",
             "Establishing the check is exact is what separates a real bypass from "
             "a test that merely looked unusual; most false positives here are a "
             "URL that was rejected correctly.",
             "an allowed host with an attacker-writable path or subdomain"),
            ("oauth.validation.account_takeover_proof",
             "Complete the authorization code flow end to end with an attacker "
             "account and show the victim's session binding to the attacker's "
             "identity",
             "Only a completed flow proves takeover; a redirected code alone shows "
             "misconfiguration, not impact.",
             "an attacker-controlled account"),
        ],
    ),
    (
        "race-to-financial-impact",
        "Race condition to duplicate fulfilment or discount abuse",
        "financial",
        "A check-then-act window on a single-use resource lets concurrent requests "
        "all pass the check before any of them writes, multiplying the effect of "
        "one entitlement.",
        "Direct financial loss: one coupon applied N times, stock oversold, or a "
        "payment confirmed on an order that was already fulfilled.",
        [
            ("race.prereq.check_then_act_single_use_limit",
             "Identify the endpoint where the limit is enforced in application "
             "logic rather than a database constraint",
             "A UNIQUE index or a single transaction closes the window; without "
             "that gap there is nothing to race.",
             "a coupon, stock, reservation or single-use token"),
            ("race.tech.parallel_burst_thread_count",
             "Fire a fixed burst of concurrent identical requests at that endpoint",
             "A burst widens the probability of overlapping the window; two "
             "requests are frequently not enough to hit it.",
             None),
            ("race.validation.counter_moved_once",
             "Check whether the guarded counter advanced once or N times",
             "This is the finding. Successes far exceeding the increment is the "
             "invariant break that cannot happen single-threaded.",
             None),
            ("race.chain.coupon_race_to_financial_damage",
             "Apply the raced entitlement to a checkout or fulfilment to convert "
             "the invariant break into measurable loss",
             "Impact must be priced. A counter that moved twice is a bug; two "
             "discounted orders shipped is a payout.",
             None),
        ],
    ),
    (
        "xss-reflected-to-privileged-action",
        "Reflected XSS on an authenticated surface to privileged in-origin actions",
        "account_takeover",
        "Script execution in the victim's own origin inherits every permission the "
        "victim holds, so the finding is graded on what the injected script can do, "
        "not on the payload's originality. An HttpOnly cookie removes session theft "
        "but leaves the higher-value targets -- the anti-CSRF token and the "
        "state-changing endpoints it protects -- fully reachable.",
        "Any action the victim can perform in that origin, performed as the victim: "
        "password and email change, MFA enrolment, and state changes that a CSRF "
        "token would otherwise protect. Session replay is an ADDITIONAL outcome, "
        "available only where the cookie is not HttpOnly.",
        [
            ("xss.signal.unique_alnum_marker_reflected_in_response",
             "Inject a unique alphanumeric marker at each candidate entry point and "
             "diff the immediate response to establish which surfaces reflect, and "
             "in which context (HTML body, attribute, script string, URL)",
             "Reflection is the precondition for everything after it, and the "
             "context determines the payload. A surface that never returns the "
             "marker is not this class and must be dropped before any time is spent "
             "on payloads.",
             None),
            ("xss.technique.html_attribute.break_out_and_add_event_handler",
             "Craft the breakout for the confirmed context and confirm execution in "
             "a browser, not by pattern-matching the response",
             "Encoded reflection in the response is not proof of execution; the "
             "context decides which characters are load-bearing, and only an "
             "observed execution separates a finding from a curiosity.",
             None),
            ("xss.impact.authenticated_reflected_beats_anonymous_page",
             "Establish whether the reflecting surface is reachable while the "
             "victim is authenticated and what same-origin privileged endpoints the "
             "origin exposes",
             "Impact is priced by the victim's session, not by the payload. An "
             "authenticated surface makes the finding materially higher severity "
             "because the injected script inherits privileged in-origin actions.",
             "an authenticated account on the target"),
            ("xss.validation.httponly_blocks_cookie_theft_chain",
             "Read the session cookie's HttpOnly flag, then restate the impact "
             "WITHOUT session theft and prove a same-origin privileged action "
             "instead",
             "Reporting cookie exfiltration on an HttpOnly session is the single "
             "most common XSS over-claim, and it gets the whole report discounted. "
             "The reachable anti-CSRF token and the endpoints behind it survive "
             "HttpOnly entirely.",
             None),
            ("xss.chain_link.csrf_token_read_defeats_csrf_defence",
             "Have the injected script read the page's anti-CSRF token and replay "
             "the protected state-changing request with it",
             "CSRF defends against a hostile ORIGIN, not against script running "
             "inside the trusted one. Reading the token converts a control the "
             "programmer believes is active into a value the attacker's script "
             "already holds.",
             "an authenticated victim with a CSRF-protected action available"),
        ],
    ),
    (
        "graphql-exposure-to-enumeration",
        "GraphQL excessive exposure to account enumeration to mass assignment",
        "data_exposure",
        "One flexible endpoint removes the per-route authorization that REST "
        "provides for free, so fields the UI never requests are still resolved -- "
        "and the same resolver often writes whatever the selection set contains.",
        "Bulk enumeration of user records, escalating to modification of protected "
        "fields such as role or email.",
        [
            ("graphql.prereq.single_universal_endpoint",
             "Confirm a single query endpoint accepting a JSON body",
             "Without one universal resolver path there is no shared "
             "authorization gap to exploit.",
             None),
            ("graphql.signal.universal_query_and_schema_fields",
             "Enumerate the schema, then request a field the frontend never asks "
             "for on an object you already own",
             "A field returning for an object you are entitled to shows the "
             "resolver has no field-level check, which is the mechanism.",
             None),
            ("graphql.bypass.frontend_only_field_authz",
             "Extend the selection set with the protected fields and confirm they "
             "resolve",
             "The frontend omitting a field is not an authorization control; the "
             "server must reject it regardless.",
             None),
            ("graphql.chain.exposure_to_enumeration_to_mass_assignment",
             "Chain the exposed fields into enumeration and then a write, if the "
             "mutation accepts arbitrary properties",
             "Read and write share the missing check, so one gap commonly yields "
             "both.",
             None),
        ],
    ),
]


def build(con: sqlite3.Connection, *, strict: bool = True) -> dict:
    built, skipped = [], []
    for key, name, goal, summary, impact, steps in CHAINS:
        chain_id = store.add_chain(con, key, name, goal, summary, impact)
        ok = True
        for i, (item_key, action, why, needs) in enumerate(steps, start=1):
            row = con.execute(
                "SELECT i.id, i.class_id, q.validation_state FROM item i "
                "JOIN quality q ON q.item_id=i.id WHERE i.item_key=?",
                (item_key,)).fetchone()
            if row is None:
                if strict:
                    skipped.append({"chain": key, "missing_item": item_key})
                    ok = False
                    continue
                item_id, class_id = None, None
            else:
                item_id, class_id = int(row["id"]), row["class_id"]
                if strict and row["validation_state"] not in ("supported", "high_confidence"):
                    skipped.append({"chain": key, "item": item_key,
                                    "reason": f"state={row['validation_state']}"})
                    ok = False
                    continue
            store.add_chain_step(con, chain_id, i, action, why,
                                 item_id=item_id, class_id=class_id, needs=needs)
        for i in range(1, len(steps)):
            store.add_chain_edge(con, chain_id, i, i + 1,
                                 "enables" if i == 1 else "amplifies")
        built.append({"chain": key, "steps": len(steps), "complete": ok})
    con.commit()
    return {"built": built, "skipped": skipped}


def render(con: sqlite3.Connection, chain_key: str) -> str:
    c = con.execute("SELECT * FROM chain WHERE chain_key=?", (chain_key,)).fetchone()
    steps = con.execute(
        """SELECT cs.*, i.item_key, i.disproof FROM chain_step cs
           LEFT JOIN item i ON i.id=cs.item_id
           WHERE cs.chain_id=? ORDER BY cs.ord""", (c["id"],)).fetchall()
    lines = [
        f"# {c['name']}", "",
        f"> goal: `{c['goal']}`",
        f"> generated from `db/wks.db` — edit the rows, not this file", "",
        # Every field is COALESCEd. A chain row with a NULL summary or impact is
        # normal (a chain can be recorded before its prose is written), and
        # `"\n".join` raises TypeError on a None — so one incomplete chain took
        # the whole batch down and the remaining 70 chains were never rendered.
        # A missing section now renders as an explicit "not yet written" marker,
        # which is both survivable and honest.
        c["summary"] or "_Summary not yet written._", "",
        "## Impact", "",
        c["impact"] or "_Impact not yet written._", "",
        "## Sequence", "",
    ]
    for s in steps:
        lines.append(f"### {s['ord']}. {s['action']}")
        lines.append("")
        lines.append(f"**Why it works:** {s['why']}")
        if s["needs"]:
            lines.append(f"")
            lines.append(f"**Requires:** {s['needs']}")
        if s["item_key"]:
            lines.append(f"")
            lines.append(f"**Backed by:** `{s['item_key']}`")
        if s["disproof"]:
            lines.append(f"")
            lines.append(f"**This step fails if:** {s['disproof']}")
        lines.append("")
    return "\n".join(lines)


def generate_all(con: sqlite3.Connection) -> list[Path]:
    """Render every chain digest into its OWNING DOMAIN's chains/ directory.

    A chain is domain-local (brief §8): a chain whose steps are all web classes
    belongs to `domains/web/chains/`, an AD-only chain to the network domain. The
    owner is derived from the chain's own steps rather than hard-coded per
    chain_key, so adding a chain cannot silently file it in the wrong domain.

    A chain spanning BOTH domains is a genuine cross-domain artifact. Those are
    written to the web domain (the entry point for an external engagement) and
    the renderer already names the participating classes, so the reference is
    discoverable from either side. That is a decision, not an accident: the
    alternative is a root-level chain taxonomy, which is what this refactor
    removed.
    """
    from . import domains as _domains
    out = []
    for row in con.execute("SELECT id, chain_key FROM chain ORDER BY chain_key").fetchall():
        owner = _domains.WEB
        for r in con.execute(
                "SELECT DISTINCT class_id FROM chain_step WHERE chain_id=?",
                (row["id"],)):
            try:
                if _domains.domain_of(con, r["class_id"]) == _domains.NETWORK:
                    owner = _domains.NETWORK
                    break
            except KeyError:
                # An unmapped class cannot claim ownership; the chain falls
                # back to its default domain rather than crashing the run.
                continue
        d = _domains.chain_dir(owner)
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{row['chain_key']}.md"
        p.write_text(render(con, row["chain_key"]), encoding="utf-8")
        out.append(p)
    return out


def main() -> int:
    con = store.open_db(create=True)
    r = build(con)
    for b in r["built"]:
        print(f"  {b['chain']:34} steps={b['steps']} complete={b['complete']}")
    for s in r["skipped"]:
        print(f"  SKIP {s['chain']}: {s}")
    for p in generate_all(con):
        print(f"  wrote {p.name}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
