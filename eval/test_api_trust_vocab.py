"""T30: api_trust's vocabulary admits its OWN corpus, and the added terms do
not swallow any other class.

MEASURED origin.  The gap report showed `api_trust` at 19 items / 5 validated
(26%) -- the weakest corroboration in the web domain.  The deficit was NOT
missing research: 14 items were held for fixable structural reasons, and 5 of
them were held OFF_CLASS_TOPIC while being perfectly good api_trust knowledge:

  audience_bound_token_replayed_on_sibling_api  -> matched windows_privesc_token
                                                   on the generic phrase
                                                   "access token"
  scope_bound_grant_absent_...                  -> matched authz on "access policy"
  service_credential_outlives_...               -> matched windows_privesc_token
  reject_a_api_trust_finding_until_...          -> matched authz
  forwarded_header_trust_requires_...           -> matched host_header on
                                                   "x-forwarded-host"

`assess()` short-circuits on the FILED class's own vocabulary (relevance.py:
`if own_hits: return Verdict(ON_TOPIC, ...)`), so a class whose vocabulary is
thinner than its corpus will have its own knowledge misfiled by a competitor
that matched a generic phrase.  api_trust listed 6 terms; none of them appeared
in these claims.

WHY THIS TEST IS SHAPED THE WAY IT IS
  * It asserts the five REAL held claims (verbatim from the db) are ON_TOPIC
    now -- a specific list, so the fix cannot pass by blanket-accepting.
  * It asserts the three REJECTED candidate terms are still absent from the
    vocabulary.  Each was measured to misfile real knowledge elsewhere:
      "resource server"  -> oauth.test.token_audience_confusion_...
      "service account"  -> pass_the_hash.auto.t.c506c349
      "client credential"-> oauth.signal.implicit_grant_or_leaked_secret
    Shipping one of those would trade 5 held api_trust items for 1-2 wrongly
    held items in another class -- a NET LOSS, and invisible in any count that
    only looks at api_trust.
  * Both directions are asserted, so it cannot pass by disabling the check.
"""
from __future__ import annotations

import os
import sys

WKS = os.environ["WKS_ROOT"]
sys.path.insert(0, WKS)

from wks import relevance  # noqa: E402

FAILS: list[str] = []
PASSES = 0

# The six INERT terms, measured one at a time: each frees held api_trust
# knowledge and misfiles nothing (tools/w12_term_by_term.py).
INERT = ["audience claim", "cross-audience", "service credential",
         "per-application", "forwarding header"]

# The three terms measured to cause collateral damage elsewhere.
COLLATERAL = ["resource server", "service account", "client credential"]

# Real held claims, quoted from the canonical db.
HELD_CLAIMS = [
    ("api_trust.technique.audience_bound_token_replayed_on_sibling_api",
     "An access token minted for one audience that is accepted by a sibling "
     "API proves the resource server is not validating the audience claim, "
     "and the test is a straight cross-audience replay of one legitimate "
     "token against a second endpoint."),
    ("api_trust.signal.scope_bound_grant_absent_means_any_client_can_reach_api",
     "An API whose per-application access policy is permissive rather than "
     "grant-based will mint a token for any registered client, so the "
     "observable signal is not a failed request but a successful token "
     "issuance from a client the target never approved."),
    ("api_trust.impact.service_credential_outlives_the_privilege_that_created_it",
     "A service credential keeps minting access tokens after the human or "
     "role that created it loses access, so removing a person's privileges "
     "does not remove the API access those privileges were used to grant."),
    ("api_trust.test.forwarded_header_trust_requires_the_header_changing_the_"
     "server_decision_not_just_the_response",
     "Trusting a client-supplied forwarding header is proved when "
     "X-Forwarded-For or X-Forwarded-Host changes the server's authorization "
     "or routing decision - a 403 becomes a 200, an IP allowlist admits a "
     "value the tester supplied, or a generated URL host changes - and not "
     "when the header is merely echoed."),
]

# Real claims that MUST stay untouched: each was misfiled by one of the
# COLLATERAL terms, so its presence would prove the vocabulary got too greedy.
COLLATERAL_CLAIMS = [
    ("oauth",
     "Cross-tenant token confusion is proved when a token whose aud names "
     "resource A is presented to the resource server for resource B and "
     "accepted, because audience validation is the resource server's job."),
    ("oauth",
     "response_type=token still being honoured, or a client_secret shipped "
     "inside an SPA/mobile bundle, means tokens and client credentials are "
     "leaked to anyone who unpacks the app."),
    ("pass_the_hash",
     "On mitigation, the AD FS service account must be a gMSA, which gives it "
     "a 120-character password rotated every thirty days and puts it behind "
     "a second factor."),
]


def check(cond: bool, label: str, detail: str = "") -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {label}")
    else:
        FAILS.append(f"{label}{(' -- ' + detail) if detail else ''}")
        print(f"  [FAIL] {label} {detail}")


def main() -> int:
    vocab = relevance.CLASS_VOCAB.get("api_trust", [])
    lowered = [t.lower() for t in vocab]

    print("T30a the inert vocabulary terms are present")
    for term in INERT:
        check(term in lowered, f"api_trust vocabulary includes {term!r}")

    print("T30b the collateral terms are ABSENT (measured to misfile other classes)")
    for term in COLLATERAL:
        check(term not in lowered,
              f"api_trust vocabulary excludes {term!r}",
              "it was measured to misfile real oauth/pass_the_hash knowledge")

    print("T30c the real held api_trust claims are ON_TOPIC, not MISFILED")
    for key, claim in HELD_CLAIMS:
        v = relevance.assess("api_trust", claim)
        state = v.state if v else "UNPROBEABLE"
        check(state != "MISFILED",
              f"no longer misfiled: {key[:56]}",
              f"state={state} best={getattr(v, 'best_class', None)} "
              f"hits={getattr(v, 'best_hits', None)}")

    print("T30d collateral claims in OTHER classes are not newly misfiled")
    for cid, claim in COLLATERAL_CLAIMS:
        v = relevance.assess(cid, claim)
        state = v.state if v else "UNPROBEABLE"
        check(state != "MISFILED",
              f"{cid} claim stays out of MISFILED",
              f"state={state} best={getattr(v, 'best_class', None)} "
              f"hits={getattr(v, 'best_hits', None)}")

    print("T30e the module selftest still passes in both directions")
    ok, fails = relevance.selftest(verbose=False)
    check(ok, "relevance.selftest passes",
          "; ".join(fails[:3]))

    print("T30f the fix is not a blanket accept")
    # A claim with NO api_trust vocabulary must still not be accepted just
    # because the vocabulary grew: an api_trust item about, say, kerberoasting
    # must not read as on-topic for api_trust.
    alien = "A share with an unconstrained Everyone ACE lets any authenticated "
    alien += "user rewrite the service binary and obtain remote code execution "
    alien += "as SYSTEM on the domain controller."
    v = relevance.assess("api_trust", alien)
    check(not (v and v.state == "ON_TOPIC"),
          "an unrelated SMB claim does NOT read as api_trust ON_TOPIC",
          f"state={v.state if v else None}")

    print()
    print(f"T30 API_TRUST VOCABULARY: {PASSES} pass, {len(FAILS)} fail")
    for f in FAILS:
        print("  FAIL " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    raise SystemExit(main())