"""Router tests. T18 in the eval convention: the domain router's own contract.

WHY THIS IS A SEPARATE TEST FILE. The existing suite is `eval/test_wks.py`,
which is about the EVIDENCE gate. Routing is a different subsystem with a
different failure mode, and the lesson from this repo is that a checker never
exercised in both directions is indistinguishable from a checker that always
says yes. So this file asserts positive cases, NEGATIVE cases, and the
deliberate refusal cases — and it includes a TAMPERED case proving the router
can be made to FAIL, because a routing table that has only ever passed proves
nothing about its ability to reject.

The tests are pure-function tests: no db, no network, no target. That is a
design property of `domains.py`, not an accident, and it is what makes the
router cheap enough to test exhaustively.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wks import domains  # noqa: E402

FAILS: list[str] = []
PASSES = 0


def check(cond: bool, label: str) -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {label}")
    else:
        FAILS.append(label)
        print(f"  [FAIL] {label}")


def t18_spec_examples():
    """The three examples the brief states verbatim (§7)."""
    print("T18 the brief's own routing examples")
    r = domains.route("Learn XSS")
    check(r.status == "ROUTED", "Learn XSS is ROUTED")
    check(r.domains == [domains.WEB], f"Learn XSS -> WEB (got {r.domains})")
    check(not r.specializations, "Learn XSS activates no specialization")

    r = domains.route("Master Kerberos attack paths")
    check(r.status == "ROUTED", "Kerberos objective is ROUTED")
    check(r.domains == [domains.NETWORK], f"Kerberos -> NETWORK (got {r.domains})")
    check("active_directory" in r.specializations,
          f"Kerberos -> ACTIVE_DIRECTORY (got {r.specializations})")

    r = domains.route("Find an attack path from a web foothold to domain compromise")
    check(r.status == "CROSS_DOMAIN", "web-foothold-to-domain is CROSS_DOMAIN")
    check(set(r.domains) == {domains.WEB, domains.NETWORK},
          f"both domains activated (got {r.domains})")


def t18_mechanism_not_category():
    """Vocabulary must name MECHANISMS (the measured 2-of-9 -> 7-of-9 lesson)."""
    print("T18 mechanism vocabulary, not category names")
    for phrase, want_special in (
        ("can I asrep roast without a ticket", "active_directory"),
        ("kerberoast the service accounts", "active_directory"),
        ("ntlm relay to a smb listener", "active_directory"),
        ("get the golden ticket", "active_directory"),
        ("resource based constrained delegation on that host", "active_directory"),
        ("abuse the gpo in sysvol", "active_directory"),
        ("dump ntds.dit", "active_directory"),
    ):
        r = domains.route(phrase)
        check(want_special in r.specializations,
              f"{phrase!r} -> {want_special} (got {r.specializations})")

    for phrase, want_domain in (
        ("pivot through a socks tunnel into the internal network", domains.NETWORK),
        ("enumerate the internal hosts by subnet", domains.NETWORK),
        ("move laterally over winrm", domains.NETWORK),
        ("smb share named pipe coercion", domains.NETWORK),
    ):
        r = domains.route(phrase)
        check(want_domain in r.domains,
              f"{phrase!r} -> {want_domain} (got {r.domains})")


def t18_web_not_contaminated():
    """A NETWORK word must not drag a WEB objective across the boundary."""
    print("T18 domain isolation")
    for phrase in ("Learn XSS", "sqli in the search box", "test this csrf",
                   "graphql introspection", "jwt algorithm confusion"):
        r = domains.route(phrase)
        check(r.domains == [domains.WEB],
              f"{phrase!r} stays WEB (got {r.domains})")

    for phrase in ("kerberoasting", "dcsync rights", "ldap injection in the filter"):
        r = domains.route(phrase)
        check(domains.WEB not in r.domains,
              f"{phrase!r} does NOT route to WEB (got {r.domains})")


def t18_excludes_cloud_identity():
    """Cloud identity is out of scope (brief §4) and must not route to on-prem AD."""
    print("T18 cloud identity excluded from on-prem AD")
    for phrase in ("entra id", "azure ad conditional access", "entra id app registration"):
        r = domains.route(phrase)
        check("active_directory" not in r.specializations,
              f"{phrase!r} does not hit on-prem AD (got {r.specializations})")


def t18_refuses_to_guess():
    """UNROUTED is a legitimate verdict. A router that always answers is a liar."""
    print("T18 the router refuses rather than guessing")
    for phrase in ("", "   ", "hello", "improve the process", "read the docs"):
        r = domains.route(phrase)
        check(r.status == "UNROUTED", f"{phrase!r} is UNROUTED (got {r.status})")
        check(bool(r.note), f"{phrase!r} carries a reason, not just a verdict")

    # A real-but-unmatched objective must still refuse rather than defaulting.
    r = domains.route("make the pipeline faster")
    check(r.status == "UNROUTED", "an unrelated objective is UNROUTED")


def t18_cross_domain_is_explicit():
    print("T18 cross-domain activation is explicit")
    for phrase, label in (
        ("exposed credentials from the web app gave me internal access", "creds->internal"),
        ("SSRF from the web foothold into the domain controller", "web->dc"),
        ("source code leaked an API key that reached the domain", "leak->domain"),
    ):
        r = domains.route(phrase)
        check(r.status == "CROSS_DOMAIN", f"{label} is CROSS_DOMAIN (got {r.status})")
        check(set(r.domains) == {domains.WEB, domains.NETWORK},
              f"{label} activates both (got {r.domains})")


def t18_word_boundaries():
    """Substring collisions must not fire. This is the 'spn' in 'suspension' trap."""
    print("T18 word-boundary discipline")
    for phrase, should_not_specialize in (
        ("the suspension policy failed", "active_directory"),
        ("a gpon device is offline", "active_directory"),
        ("growing rapidly", "active_directory"),
    ):
        r = domains.route(phrase)
        check(should_not_specialize not in r.specializations,
              f"{phrase!r} does not trip {should_not_specialize} "
              f"(got {r.specializations})")


def t18_tamper_detectable():
    """PROVE THE ROUTER CAN FAIL.

    The reorg-discipline rule is that a checker only ever seen passing is
    indistinguishable from a healthy instrument. So: break the vocabulary and
    assert the routing verdict changes. If this test passes while the table is
    broken, the router is decorative.
    """
    print("T18 tamper detection — a broken router must produce a different verdict")
    baseline = domains.route("Learn XSS")
    check(baseline.domains == [domains.WEB], "pre-tamper baseline is WEB")

    saved = domains._VOCAB[domains.WEB]
    try:
        domains._VOCAB[domains.WEB] = (("zzz-not-a-real-phrase",), ())
        after = domains.route("Learn XSS")
        check(after.status == "UNROUTED",
              f"with the WEB vocabulary emptied, 'Learn XSS' no longer routes "
              f"(got {after.status}/{after.domains})")
        check(after.domains != baseline.domains,
              "the verdict actually changed — the router is reading the table")
    finally:
        domains._VOCAB[domains.WEB] = saved

    restored = domains.route("Learn XSS")
    check(restored.domains == [domains.WEB], "restoring the table restores the route")

    # Second tamper: break the SPECIALIZATION link, not the vocabulary.
    saved_sp = domains.NETWORK_SPECIALIZATIONS["active_directory"]["parent"]
    try:
        domains.NETWORK_SPECIALIZATIONS["active_directory"]["parent"] = None
        after = domains.route("Master Kerberos attack paths")
        check("active_directory" not in after.domains,
              "an orphaned specialization is NOT promoted to a top-level domain "
              f"(got {after.domains})")
        check("active_directory" in after.orphans,
              f"the orphan is reported instead (got {after.orphans})")
        check(domains.NETWORK not in after.domains,
              "and its parent domain is not invented either "
              f"(got {after.domains})")
    finally:
        domains.NETWORK_SPECIALIZATIONS["active_directory"]["parent"] = saved_sp

    check(domains.NETWORK in domains.route("Master Kerberos attack paths").domains,
          "restoring the parent link restores the route")


def t18_ad_is_not_a_third_domain():
    """Brief §2: AD must not become a top-level domain."""
    print("T18 Active Directory is a specialization, never a domain")
    check(set(domains.DOMAINS) == {domains.WEB, domains.NETWORK},
          f"exactly two top-level domains (got {sorted(domains.DOMAINS)})")
    for spec, meta in domains.NETWORK_SPECIALIZATIONS.items():
        check(meta["parent"] == domains.NETWORK,
              f"{spec} hangs off NETWORK")
    r = domains.route("Master Kerberos attack paths")
    check(domains.NETWORK in r.domains,
          "an AD objective still reports NETWORK as its domain")
    check("active_directory" not in r.domains,
          "an AD objective does NOT report active_directory as a DOMAIN")


def t18_every_phrase_is_reachable():
    """Vocabulary coverage: each phrase must route SOMEWHERE it is defined."""
    print("T18 every vocabulary phrase routes to its own node")
    unreachable = []
    for node, (phrases, _exc) in domains._VOCAB.items():
        for p in phrases:
            r = domains.route(p)
            ok = (node in r.nodes) or (node in r.domains)
            if not ok:
                unreachable.append((node, p, r.status, r.nodes))
    check(not unreachable, f"no unreachable phrase (found {len(unreachable)})")
    for u in unreachable[:10]:
        print(f"         unreachable: {u[0]} <- {u[1]!r} ({u[2]}, {u[3]})")


def t18_bridge_phrases_activate_both():
    print("T18 bridge phrases activate both domains")
    bad = []
    for p in domains._BRIDGE_PHRASES:
        r = domains.route(p)
        if not (set(r.domains) == {domains.WEB, domains.NETWORK}):
            bad.append((p, r.domains))
    check(not bad, f"every bridge phrase activates both (bad={bad[:5]})")


def run() -> int:
    for fn in (
        t18_spec_examples,
        t18_mechanism_not_category,
        t18_web_not_contaminated,
        t18_excludes_cloud_identity,
        t18_refuses_to_guess,
        t18_cross_domain_is_explicit,
        t18_word_boundaries,
        t18_ad_is_not_a_third_domain,
        t18_every_phrase_is_reachable,
        t18_bridge_phrases_activate_both,
        t18_tamper_detectable,
    ):
        fn()
    print(f"\n{'ALL DOMAIN ROUTER TESTS PASS' if not FAILS else 'ROUTER TESTS FAILED'}"
          f"  ({PASSES} pass, {len(FAILS)} fail)")
    for f in FAILS:
        print(f"  FAILED: {f}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(run())
